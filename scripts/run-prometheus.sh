#!/usr/bin/env bash
# Start Prometheus temporarily using the repo-root prometheus.yml to verify scrape.
# Prerequisite: blackbox_exporter must be running at http://127.0.0.1:9115

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DATA_DIR="${PROMETHEUS_DATA_DIR:-$ROOT/prometheus_data_tmp}"
mkdir -p "$DATA_DIR"

# If prometheus binary is not set, try PATH or common locations
PROM="${PROMETHEUS_BIN:-prometheus}"
if ! command -v "$PROM" &>/dev/null; then
  echo "prometheus not found. Install Prometheus or set PROMETHEUS_BIN."
  echo "e.g.: brew install prometheus  or  docker run -v \$PWD/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus"
  exit 1
fi

echo "Config: $ROOT/prometheus.yml"
echo "Data dir: $DATA_DIR"
echo "UI: http://localhost:9090 (Targets: Status -> Targets, query: Graph)"
echo "After Ctrl+C you can remove data: rm -rf $DATA_DIR"
echo ""

exec "$PROM" \
  --config.file="$ROOT/prometheus.yml" \
  --storage.tsdb.path="$DATA_DIR" \
  --storage.tsdb.retention.time=2h \
  --web.enable-lifecycle \
  --web.listen-address=:9090
