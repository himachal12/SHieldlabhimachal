import subprocess

from app.scanners import sqlmap_runner


def test_sqlmap_availability_falls_back_when_backend_python_times_out(monkeypatch):
    """A hanging backend venv Python should not prevent sqlmap from launching."""
    calls = []

    def fake_run(command_prefix, args, timeout):
        calls.append(command_prefix)
        if command_prefix == ["backend-venv-python"]:
            raise subprocess.TimeoutExpired(command_prefix, timeout)
        return subprocess.CompletedProcess(
            [*command_prefix, "sqlmap.py", *args],
            returncode=0,
            stdout="1.8.12#stable",
            stderr=""
        )

    monkeypatch.setattr(sqlmap_runner, "_SQLMAP_CHECKED", False)
    monkeypatch.setattr(sqlmap_runner, "_SQLMAP_COMMAND", None)
    monkeypatch.setattr(sqlmap_runner, "_SQLMAP_SCRIPT", "C:/sqlmap/sqlmap.py")
    monkeypatch.setattr(sqlmap_runner.os.path, "exists", lambda path: True)
    monkeypatch.setattr(
        sqlmap_runner,
        "_python_candidates",
        lambda: [["backend-venv-python"], ["system-python"]]
    )
    monkeypatch.setattr(sqlmap_runner, "_run_with_python", fake_run)

    assert sqlmap_runner.is_sqlmap_available() is True
    assert sqlmap_runner._SQLMAP_COMMAND == ["system-python"]
    assert calls == [["backend-venv-python"], ["system-python"]]


def test_run_sqlmap_active_uses_cached_working_python(monkeypatch):
    """Active scans should execute sqlmap with the command resolved by availability."""
    executed = []

    def fake_run(command_prefix, args, timeout):
        executed.append((command_prefix, args))
        return subprocess.CompletedProcess(
            [*command_prefix, "sqlmap.py", *args],
            returncode=0,
            stdout="parameter 'id' appears to be injectable",
            stderr=""
        )

    monkeypatch.setattr(sqlmap_runner, "_SQLMAP_COMMAND", ["system-python"])
    monkeypatch.setattr(sqlmap_runner, "_SQLMAP_CHECKED", True)
    monkeypatch.setattr(sqlmap_runner, "_run_with_python", fake_run)
    monkeypatch.setattr(sqlmap_runner.active_scan_limiter, "wait", lambda: None)

    findings = sqlmap_runner.run_sqlmap_active(
        "http://target.local/item?id=1",
        max_requests=5,
        timeout=10
    )

    assert executed[0][0] == ["system-python"]
    assert "-u" in executed[0][1]
    assert findings[0]["source"] == "sqlmap_active"
