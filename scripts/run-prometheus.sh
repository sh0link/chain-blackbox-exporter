#!/usr/bin/env bash
# 临时启动 Prometheus，使用项目根目录的 prometheus.yml 验证抓取数据
# 前置：blackbox_exporter 需已在 http://127.0.0.1:9115 运行

set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DATA_DIR="${PROMETHEUS_DATA_DIR:-$ROOT/prometheus_data_tmp}"
mkdir -p "$DATA_DIR"

# 若未指定 prometheus 二进制，尝试 PATH 或常见路径
PROM="${PROMETHEUS_BIN:-prometheus}"
if ! command -v "$PROM" &>/dev/null; then
  echo "未找到 prometheus 命令。请安装 Prometheus 或设置 PROMETHEUS_BIN。"
  echo "例如: brew install prometheus  或  docker run -v \$PWD/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus"
  exit 1
fi

echo "使用配置: $ROOT/prometheus.yml"
echo "数据目录: $DATA_DIR"
echo "访问: http://localhost:9090 (Targets: Status -> Targets, 查询: Graph)"
echo "按 Ctrl+C 停止后，可删除数据目录: rm -rf $DATA_DIR"
echo ""

exec "$PROM" \
  --config.file="$ROOT/prometheus.yml" \
  --storage.tsdb.path="$DATA_DIR" \
  --storage.tsdb.retention.time=2h \
  --web.enable-lifecycle \
  --web.listen-address=:9090
