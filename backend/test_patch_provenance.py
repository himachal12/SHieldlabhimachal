"""Tests for safe, repository-relative patch provenance."""

from app.patches import repository_relative_path, source_sha256


def test_repository_relative_path_never_leaks_checkout_directory(tmp_path):
    file_path = tmp_path / "src" / "settings.py"
    file_path.parent.mkdir()
    file_path.write_text("SECRET_KEY = 'value'\n", encoding="utf-8")

    assert repository_relative_path(str(file_path), str(tmp_path)) == "src/settings.py"
    assert repository_relative_path("/outside/settings.py", str(tmp_path)) is None


def test_source_hash_is_stable_and_content_sensitive():
    assert source_sha256("one\n") == source_sha256("one\n")
    assert source_sha256("one\n") != source_sha256("two\n")
