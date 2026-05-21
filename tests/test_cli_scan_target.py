"""Resolver for `virgil scan TARGET`.

The CLI accepts either a local path or a remote repo coordinate and figures
out which is which. These tests pin the branches in that decision tree so a
future refactor can't silently turn a typo into a "scan a random GitHub
repo" event.
"""
import pytest
import click

from cli.main import _resolve_scan_target


def test_no_arg_resolves_to_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    kind, value = _resolve_scan_target(None, None)
    assert kind == "local"
    assert value == str(tmp_path.resolve())


def test_explicit_url_flag_wins(tmp_path):
    kind, value = _resolve_scan_target(None, "https://github.com/x/y")
    assert (kind, value) == ("remote", "https://github.com/x/y")


def test_url_flag_with_positional_is_rejected():
    with pytest.raises(click.UsageError):
        _resolve_scan_target("foo/bar", "https://github.com/x/y")


def test_full_https_url():
    assert _resolve_scan_target("https://github.com/OWASP/NodeGoat", None) == (
        "remote", "https://github.com/OWASP/NodeGoat",
    )


def test_ssh_url():
    assert _resolve_scan_target("git@github.com:foo/bar.git", None) == (
        "remote", "git@github.com:foo/bar.git",
    )


@pytest.mark.parametrize("bare,expected", [
    ("github.com/x/y",     "https://github.com/x/y"),
    ("gitlab.com/g/p",     "https://gitlab.com/g/p"),
    ("bitbucket.org/a/b",  "https://bitbucket.org/a/b"),
    ("codeberg.org/a/b",   "https://codeberg.org/a/b"),
])
def test_bare_host_gets_scheme(bare, expected):
    assert _resolve_scan_target(bare, None) == ("remote", expected)


def test_shorthand_resolves_to_github(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # No local `OWASP/NodeGoat` exists, so this is GitHub shorthand.
    assert _resolve_scan_target("OWASP/NodeGoat", None) == (
        "remote", "https://github.com/OWASP/NodeGoat",
    )


def test_shorthand_loses_to_existing_local_path(tmp_path, monkeypatch):
    # If the user really has a local dir with that name, that wins — the
    # shorthand heuristic must not silently switch to remote.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "OWASP" / "NodeGoat").mkdir(parents=True)
    kind, value = _resolve_scan_target("OWASP/NodeGoat", None)
    assert kind == "local"
    assert value.endswith("OWASP/NodeGoat")


def test_local_dot_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "myrepo").mkdir()
    monkeypatch.chdir(tmp_path / "myrepo")
    kind, value = _resolve_scan_target(".", None)
    assert kind == "local"
    assert value == str((tmp_path / "myrepo").resolve())


def test_nonexistent_local_path_errors(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # Not a URL, not a shorthand (has too many segments), not a real path.
    with pytest.raises(click.BadParameter) as ei:
        _resolve_scan_target("nope/this/aint/real", None)
    msg = str(ei.value).lower()
    assert "no such path" in msg
    # Helpful hint about remote syntax.
    assert "owner/repo" in msg or "github.com" in msg


def test_file_target_is_rejected(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    f = tmp_path / "f.txt"
    f.write_text("x")
    with pytest.raises(click.BadParameter):
        _resolve_scan_target("f.txt", None)
