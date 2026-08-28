"""Tests for socials.otel — OTEL Collector config generator."""

import pytest

from socials.otel import generate_collector_config

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


MACHINE = {"name": "web-prod", "environment": "production"}
MONITOR_IP = "10.0.0.1"


class TestGenerateCollectorConfig:
    def test_returns_string(self):
        result = generate_collector_config(MACHINE, MONITOR_IP)
        assert isinstance(result, str)
        assert len(result) > 100

    def test_contains_machine_name(self):
        result = generate_collector_config(MACHINE, MONITOR_IP)
        assert "web-prod" in result

    def test_contains_monitor_ip(self):
        result = generate_collector_config(MACHINE, MONITOR_IP)
        assert MONITOR_IP in result

    def test_has_otlp_receiver(self):
        result = generate_collector_config(MACHINE, MONITOR_IP)
        assert "otlp:" in result
        assert "4317" in result
        assert "4318" in result

    def test_has_filelog_receiver(self):
        result = generate_collector_config(MACHINE, MONITOR_IP)
        assert "filelog/docker" in result
        assert "/var/lib/docker/containers" in result

    def test_has_tls_insecure(self):
        result = generate_collector_config(MACHINE, MONITOR_IP)
        assert "insecure: true" in result

    def test_exporters_present(self):
        result = generate_collector_config(MACHINE, MONITOR_IP)
        assert "otlp/tempo:" in result
        assert "otlphttp/loki:" in result
        assert "prometheus:" in result

    def test_pipelines_present(self):
        result = generate_collector_config(MACHINE, MONITOR_IP)
        assert "traces:" in result
        assert "logs:" in result
        assert "metrics:" in result

    def test_environment_default(self):
        machine_no_env = {"name": "test"}
        result = generate_collector_config(machine_no_env, "1.2.3.4")
        assert "production" in result

    def test_custom_environment(self):
        machine = {"name": "staging-1", "environment": "staging"}
        result = generate_collector_config(machine, "1.2.3.4")
        assert "staging" in result

    @pytest.mark.skipif(not HAS_YAML, reason="pyyaml not installed")
    def test_valid_yaml(self):
        result = generate_collector_config(MACHINE, MONITOR_IP)
        parsed = yaml.safe_load(result)
        assert "receivers" in parsed
        assert "exporters" in parsed
        assert "service" in parsed

    def test_memory_limiter(self):
        result = generate_collector_config(MACHINE, MONITOR_IP)
        assert "memory_limiter" in result
        assert "limit_mib: 256" in result

    def test_health_check_extension(self):
        result = generate_collector_config(MACHINE, MONITOR_IP)
        assert "health_check" in result
        assert "13133" in result
