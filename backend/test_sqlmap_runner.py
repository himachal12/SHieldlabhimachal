import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.config import ScanMode, settings
from app.scanners import sqlmap_runner
from app.scanners.sqlmap_runner import SQLMapConfigurationError


def _touch(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("print('ok')")
    return path


@pytest.fixture
def sqlmap_config(tmp_path, monkeypatch):
    sqlmap = _touch(tmp_path / "sqlmap folder" / "sqlmap.py")
    python = _touch(tmp_path / "Python Folder" / "python.exe")
    monkeypatch.setattr(settings, "SQLMAP_PATH", f'"{sqlmap}"')
    monkeypatch.setattr(settings, "SQLMAP_PYTHON", f'"{python}"')
    return sqlmap, python


class _FakeStream:
    def __init__(self, text):
        self._lines = text.splitlines(True)

    def readline(self):
        if self._lines:
            return self._lines.pop(0)
        return ""

    def close(self):
        pass


class _FakeProcess:
    def __init__(self, stdout="", stderr="", returncode=0, never_exits=False):
        self.stdout = _FakeStream(stdout)
        self.stderr = _FakeStream(stderr)
        self.returncode = returncode
        self._never_exits = never_exits
        self.killed = False

    def poll(self):
        if self._never_exits and not self.killed:
            return None
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        if self._never_exits and not self.killed:
            raise subprocess.TimeoutExpired("cmd", timeout)
        return self.returncode


def _popen_factory(stdout="", stderr="", returncode=0, never_exits=False):
    return Mock(return_value=_FakeProcess(stdout, stderr, returncode, never_exits))


def test_successful_launch(sqlmap_config, monkeypatch):
    popen = _popen_factory(stdout="1.7.0\n", returncode=0)
    monkeypatch.setattr(sqlmap_runner.subprocess, "Popen", popen)

    assert sqlmap_runner.is_sqlmap_available() is True
    command = popen.call_args.args[0]
    assert command[0].endswith("python.exe")
    assert command[1].endswith("sqlmap.py")
    assert "--version" in command
    assert "--batch" in command
    assert popen.call_args.kwargs["shell"] is False
    assert popen.call_args.kwargs["stdin"] is subprocess.DEVNULL


def test_invalid_sqlmap_path(sqlmap_config, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "SQLMAP_PATH", str(tmp_path / "missing" / "sqlmap.py"))

    with pytest.raises(SQLMapConfigurationError, match="SQLMAP_PATH"):
        sqlmap_runner.get_sqlmap_config()


def test_invalid_sqlmap_python(sqlmap_config, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "SQLMAP_PYTHON", str(tmp_path / "missing" / "python.exe"))

    with pytest.raises(SQLMapConfigurationError, match="SQLMAP_PYTHON"):
        sqlmap_runner.get_sqlmap_config()


def test_timeout(sqlmap_config, monkeypatch):
    popen = _popen_factory(stdout="partial\n", returncode=None, never_exits=True)
    monkeypatch.setattr(sqlmap_runner.subprocess, "Popen", popen)
    result = sqlmap_runner.execute_sqlmap(sqlmap_runner.build_sqlmap_command("http://a.test/?id=1"), timeout=0)

    assert result.timed_out is True
    assert result.error == "timeout"
    assert result.stdout == "partial\n"


def test_subprocess_failure(sqlmap_config, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("boom")

    monkeypatch.setattr(sqlmap_runner.subprocess, "Popen", fail)
    result = sqlmap_runner.execute_sqlmap(sqlmap_runner.build_sqlmap_command("http://a.test/?id=1"))

    assert result.error == "boom"
    assert "boom" in result.stderr


def test_windows_paths_with_spaces(sqlmap_config):
    command = sqlmap_runner.build_sqlmap_command("http://a.test/search?q=1", params=["q"], max_requests=7)

    assert "Python Folder" in command[0]
    assert "sqlmap folder" in command[1]
    assert command[command.index("-p") + 1] == "q"
    assert "--batch" in command
    assert "--answers" in command
    assert "--max-requests=7" in command


def test_active_scan_uses_sqlmap_launcher(monkeypatch):
    monkeypatch.setitem(sys.modules, "requests", SimpleNamespace(get=lambda *a, **k: None))
    from app.scanners import web_scanner

    monkeypatch.setattr(web_scanner, "scan_ports", lambda target: {"ports": []})
    monkeypatch.setattr(web_scanner, "check_exposed_files", lambda target: [])
    monkeypatch.setattr(web_scanner, "analyze_ssl", lambda target: {"findings": []})
    monkeypatch.setattr(web_scanner, "check_headers", lambda target: {"findings": []})
    monkeypatch.setattr(web_scanner, "is_nuclei_available", lambda: False)
    monkeypatch.setattr(sqlmap_runner, "get_sqlmap_unavailable_reason", lambda: None)
    monkeypatch.setattr(
        sqlmap_runner,
        "run_sqlmap_active",
        lambda target_url, max_requests: [{"source": "sqlmap_active", "url": target_url}],
    )

    findings = web_scanner.scan_web_target(
        "example.com",
        scan_mode=ScanMode.ACTIVE,
        consent_confirmed=True,
        active_urls=["http://example.com/?id=1"],
    )

    assert findings == [{"source": "sqlmap_active", "url": "http://example.com/?id=1", "scan_mode": "active"}]


def test_combined_scan_passes_active_urls(monkeypatch):
    monkeypatch.setitem(sys.modules, "sqlalchemy", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "sqlalchemy.orm", SimpleNamespace(Session=object))
    monkeypatch.setitem(sys.modules, "app.database", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "app.models", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "app.crud", SimpleNamespace(
        update_scan_status=lambda *args, **kwargs: None,
        update_scan_counts=lambda *args, **kwargs: None,
        get_scan=lambda *args, **kwargs: SimpleNamespace(total_findings=0, critical_count=0, high_count=0),
        create_finding=lambda *args, **kwargs: None,
        create_attack_chain=lambda *args, **kwargs: None,
    ))
    from app import pipeline

    captured = {}
    monkeypatch.setattr(pipeline, "_update_progress", lambda *args, **kwargs: None)
    monkeypatch.setattr(pipeline, "_persist_findings", lambda *args, **kwargs: None)
    monkeypatch.setattr(pipeline.crud, "update_scan_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(pipeline.crud, "update_scan_counts", lambda *args, **kwargs: None)
    monkeypatch.setattr(pipeline.crud, "get_scan", lambda *args, **kwargs: SimpleNamespace(total_findings=0, critical_count=0, high_count=0))

    def fake_scan_web_target(**kwargs):
        captured.update(kwargs)
        return []

    monkeypatch.setitem(sys.modules, "app.utils.repo_handler", SimpleNamespace(
        download_github_repo=lambda url: "/tmp/repo",
        cleanup_temp_repo=lambda path: None,
    ))
    monkeypatch.setitem(sys.modules, "app.scanners.code_scanner", SimpleNamespace(scan_codebase=lambda path: []))
    monkeypatch.setitem(sys.modules, "app.scanners.semantic_analyzer", SimpleNamespace(review_all_low_confidence=lambda findings: findings))
    monkeypatch.setitem(sys.modules, "app.agents.fix_generation", SimpleNamespace(generate_all_fixes=lambda findings: findings))
    monkeypatch.setitem(sys.modules, "app.scanners.web_scanner", SimpleNamespace(scan_web_target=fake_scan_web_target))
    monkeypatch.setitem(sys.modules, "app.agents.severity_reasoning", SimpleNamespace(reason_all_severities=lambda findings: findings))
    monkeypatch.setitem(sys.modules, "app.agents.cross_domain_analyzer", SimpleNamespace(analyze_attack_chains=lambda findings: []))

    pipeline.run_combined_pipeline(
        db=object(),
        scan_id="scan-1",
        repo_url="https://github.com/a/b",
        domain="example.com",
        scan_mode=ScanMode.ACTIVE,
        consent_confirmed=True,
        active_urls=["http://example.com/?id=1"],
    )

    assert captured["active_urls"] == ["http://example.com/?id=1"]
    assert captured["scan_mode"] == ScanMode.ACTIVE
