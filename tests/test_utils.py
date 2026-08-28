"""Tests for socials.utils."""

import os
import tempfile

from socials.utils import read_env, run, project_root, bold, Colors


def test_read_env_existing_key():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
        f.write("MONITOR_IP=10.0.0.1\nGF_PORT=3001\n")
        f.flush()
        path = f.name
    try:
        assert read_env(path, "MONITOR_IP") == "10.0.0.1"
        assert read_env(path, "GF_PORT") == "3001"
    finally:
        os.unlink(path)


def test_read_env_missing_key():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
        f.write("FOO=bar\n")
        f.flush()
        path = f.name
    try:
        assert read_env(path, "MISSING", "fallback") == "fallback"
    finally:
        os.unlink(path)


def test_read_env_missing_file():
    assert read_env("/nonexistent/.env", "KEY", "default") == "default"


def test_read_env_value_with_equals():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
        f.write("DSN=postgres://user:pass@host/db?opt=val\n")
        f.flush()
        path = f.name
    try:
        assert read_env(path, "DSN") == "postgres://user:pass@host/db?opt=val"
    finally:
        os.unlink(path)


def test_run_echo():
    out, code = run("echo hello", timeout=5)
    assert code == 0
    assert "hello" in out


def test_run_failing_command():
    _, code = run("exit 42", timeout=5)
    assert code == 42


def test_run_timeout():
    out, code = run("sleep 60", timeout=1)
    assert code == 124
    assert out == ""


def test_project_root_is_directory():
    root = project_root()
    assert os.path.isdir(root)
    assert os.path.exists(os.path.join(root, "socials", "__init__.py"))


def test_bold_wraps_text():
    Colors.disable()
    result = bold("test")
    assert "test" in result


def test_colors_disable():
    Colors.disable()
    assert Colors.RED == ""
    assert Colors.NC == ""
    assert Colors.BOLD == ""
