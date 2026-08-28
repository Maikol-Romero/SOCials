"""Tests for socials.config — centralized config loading, merging, env overrides."""

import os
import textwrap
import pytest

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

pytestmark = pytest.mark.skipif(not HAS_YAML, reason="pyyaml not installed")


@pytest.fixture(autouse=True)
def _clear_config_cache():
    from socials import config
    config._cached = None
    yield
    config._cached = None


@pytest.fixture
def config_file(tmp_path):
    """Create a temporary socials.yml and return its path."""
    def _write(content: str) -> str:
        p = tmp_path / "socials.yml"
        p.write_text(textwrap.dedent(content))
        return str(p)
    return _write


class TestDeepMerge:
    def test_override_scalar(self):
        from socials.config import _deep_merge
        result = _deep_merge({"a": 1}, {"a": 2})
        assert result == {"a": 2}

    def test_nested_merge(self):
        from socials.config import _deep_merge
        defaults = {"monitor": {"ip": "127.0.0.1", "name": "default"}}
        overrides = {"monitor": {"ip": "10.0.0.1"}}
        result = _deep_merge(defaults, overrides)
        assert result["monitor"]["ip"] == "10.0.0.1"
        assert result["monitor"]["name"] == "default"

    def test_extra_keys_preserved(self):
        from socials.config import _deep_merge
        result = _deep_merge({"a": 1}, {"b": 2})
        assert result == {"a": 1, "b": 2}

    def test_empty_overrides(self):
        from socials.config import _deep_merge
        defaults = {"x": {"y": 1}}
        assert _deep_merge(defaults, {}) == defaults

    def test_deep_nested(self):
        from socials.config import _deep_merge
        defaults = {"a": {"b": {"c": 1, "d": 2}}}
        overrides = {"a": {"b": {"c": 99}}}
        result = _deep_merge(defaults, overrides)
        assert result["a"]["b"]["c"] == 99
        assert result["a"]["b"]["d"] == 2


class TestLoad:
    def test_load_from_file(self, config_file):
        from socials.config import load
        path = config_file("""\
            monitor:
              ip: 10.20.0.5
        """)
        cfg = load(path)
        assert cfg["monitor"]["ip"] == "10.20.0.5"
        assert cfg["monitor"]["name"] == "socials-monitor"  # default preserved

    def test_load_defaults_when_missing(self, tmp_path):
        from socials.config import load
        path = str(tmp_path / "nonexistent.yml")
        cfg = load(path)
        assert cfg["monitor"]["ip"] == "127.0.0.1"
        assert cfg["grafana"]["port"] == 3001

    def test_load_invalid_yaml_returns_defaults(self, config_file):
        from socials.config import load
        path = config_file("not_a_dict")
        cfg = load(path)
        assert cfg["monitor"]["ip"] == "127.0.0.1"

    def test_caching(self, config_file):
        from socials import config
        path = config_file("""\
            monitor:
              ip: 10.0.0.1
        """)
        cfg1 = config.load(path)
        cfg1["monitor"]["ip"] = "mutated"
        cfg2 = config.load(path)
        assert cfg2["monitor"]["ip"] == "10.0.0.1"  # path loads bypass cache


class TestGet:
    def test_simple_key(self, config_file):
        from socials import config
        path = config_file("""\
            grafana:
              port: 9999
        """)
        config.load(path)
        config._cached = config.load(path)
        assert config.get("grafana.port") == 9999

    def test_default_for_missing(self):
        from socials import config
        config._cached = config.load(os.devnull)
        assert config.get("nonexistent.key", "fallback") == "fallback"

    def test_nested_key(self, config_file):
        from socials import config
        path = config_file("""\
            betterstack:
              resources:
                api: res-123
        """)
        config._cached = config.load(path)
        assert config.get("betterstack.resources") == {"api": "res-123"}


class TestEnvOverrides:
    def test_string_override(self, config_file, monkeypatch):
        from socials.config import load
        monkeypatch.setenv("SOCIALS_MONITOR_IP", "192.168.1.1")
        path = config_file("""\
            monitor:
              ip: 10.0.0.1
        """)
        cfg = load(path)
        assert cfg["monitor"]["ip"] == "192.168.1.1"

    def test_int_override(self, config_file, monkeypatch):
        from socials.config import load
        monkeypatch.setenv("SOCIALS_GRAFANA_PORT", "8080")
        path = config_file("""\
            grafana:
              port: 3001
        """)
        cfg = load(path)
        assert cfg["grafana"]["port"] == 8080

    def test_unrelated_env_ignored(self, config_file, monkeypatch):
        from socials.config import load
        monkeypatch.setenv("SOCIALS_BOGUS", "value")
        path = config_file("""\
            monitor:
              ip: 10.0.0.1
        """)
        cfg = load(path)
        assert cfg["monitor"]["ip"] == "10.0.0.1"


class TestCheckRequired:
    def test_passes_with_ip(self):
        from socials.config import _check_required
        assert _check_required({"monitor": {"ip": "10.0.0.1"}}) == []

    def test_fails_when_empty(self):
        from socials.config import _check_required
        missing = _check_required({"monitor": {"ip": ""}})
        assert "monitor.ip" in missing

    def test_fails_when_missing_section(self):
        from socials.config import _check_required
        missing = _check_required({})
        assert "monitor.ip" in missing


class TestGenerateEnvFiles:
    def test_dry_run_writes_nothing(self, config_file, tmp_path, monkeypatch):
        from socials import config
        monkeypatch.setattr(config, "project_root", lambda: str(tmp_path))
        path = config_file("""\
            monitor:
              ip: 10.20.0.1
        """)
        cfg = config.load(path)
        result = config.generate_env_files(cfg, dry_run=True)
        assert result == []
        assert not (tmp_path / "observability" / ".env").exists()

    def test_writes_env_files(self, config_file, tmp_path, monkeypatch):
        from socials import config
        monkeypatch.setattr(config, "project_root", lambda: str(tmp_path))
        path = config_file("""\
            monitor:
              ip: 10.20.0.1
            grafana:
              user: testadmin
              password: secret123
              port: 4000
        """)
        cfg = config.load(path)
        written = config.generate_env_files(cfg)
        assert "observability/.env" in written

        env_content = (tmp_path / "observability" / ".env").read_text()
        assert "MONITOR_IP=10.20.0.1" in env_content
        assert "GF_ADMIN_USER=testadmin" in env_content
        assert "GF_ADMIN_PASSWORD=secret123" in env_content
        assert "GF_HTTP_PORT=4000" in env_content

    def test_unchanged_file_skipped(self, config_file, tmp_path, monkeypatch):
        from socials import config
        monkeypatch.setattr(config, "project_root", lambda: str(tmp_path))
        path = config_file("""\
            monitor:
              ip: 10.20.0.1
        """)
        cfg = config.load(path)
        config.generate_env_files(cfg)
        config._cached = None
        cfg = config.load(path)
        written = config.generate_env_files(cfg)
        assert "observability/.env" not in written


class TestInitConfig:
    def test_creates_from_example(self, tmp_path, monkeypatch):
        from socials import config
        monkeypatch.setattr(config, "project_root", lambda: str(tmp_path))
        example = tmp_path / "socials.yml.example"
        example.write_text("monitor:\n  ip: 10.0.0.1\n")
        result = config.init_config()
        assert os.path.exists(result)
        content = open(result).read()
        assert "10.0.0.1" in content

    def test_skip_if_exists(self, tmp_path, monkeypatch):
        from socials import config
        monkeypatch.setattr(config, "project_root", lambda: str(tmp_path))
        existing = tmp_path / "socials.yml"
        existing.write_text("old content")
        result = config.init_config()
        assert open(result).read() == "old content"

    def test_creates_from_defaults_when_no_example(self, tmp_path, monkeypatch):
        from socials import config
        monkeypatch.setattr(config, "project_root", lambda: str(tmp_path))
        result = config.init_config()
        assert os.path.exists(result)
        content = open(result).read()
        assert "monitor" in content
