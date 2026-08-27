"""OpenTelemetry Collector config generator."""

from __future__ import annotations

from typing import Any


def generate_collector_config(machine: dict[str, Any], monitor_ip: str) -> str:
    """Generate otel-collector-config.yaml content for a remote machine."""
    return f"""receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
  filelog/docker:
    include: ["/var/lib/docker/containers/*/*.log"]
    start_at: end
    operators:
      - type: json_parser
        timestamp:
          parse_from: attributes.time
          layout: "%Y-%m-%dT%H:%M:%S.%LZ"
      - type: move
        from: attributes.log
        to: body
      - type: move
        from: attributes.stream
        to: attributes["log.iostream"]

processors:
  batch:
    timeout: 5s
    send_batch_size: 100
    send_batch_max_size: 500
  memory_limiter:
    check_interval: 1s
    limit_mib: 256
    spike_limit_mib: 64
  resource:
    attributes:
      - key: deployment.environment
        value: "{machine.get('environment', 'production')}"
        action: upsert
      - key: host.name
        value: "{machine['name']}"
        action: upsert

exporters:
  otlp/tempo:
    endpoint: "{monitor_ip}:4317"
    tls:
      insecure: true
  otlphttp/loki:
    endpoint: "http://{monitor_ip}:3100/otlp"
    tls:
      insecure: true
  prometheus:
    endpoint: "0.0.0.0:8889"
    namespace: socials

extensions:
  health_check:
    endpoint: 0.0.0.0:13133

service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, resource, batch]
      exporters: [otlp/tempo]
    logs:
      receivers: [otlp, filelog/docker]
      processors: [memory_limiter, resource, batch]
      exporters: [otlphttp/loki]
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, resource, batch]
      exporters: [prometheus]
  telemetry:
    logs:
      level: warn
"""
