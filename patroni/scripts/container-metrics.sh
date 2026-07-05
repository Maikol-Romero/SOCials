#!/bin/bash
OUTPUT=/tmp/node-exporter-textfile/container_metrics.prom
{
echo "# HELP container_up 1 if running, 0 if not"
echo "# TYPE container_up gauge"
echo "# HELP container_restarts Number of restarts"
echo "# TYPE container_restarts counter"
docker ps -a --format '{{.Names}}|{{.Status}}' 2>/dev/null | while IFS='|' read NAME STATUS; do
    if echo "$STATUS" | grep -qi "Up"; then
        echo "container_up{name=\"$NAME\"} 1"
    else
        echo "container_up{name=\"$NAME\"} 0"
    fi
    RESTARTS=$(docker inspect "$NAME" --format '{{.RestartCount}}' 2>/dev/null || echo 0)
    echo "container_restarts{name=\"$NAME\"} $RESTARTS"
done
} > "${OUTPUT}.tmp" && mv "${OUTPUT}.tmp" "$OUTPUT"
