#!/bin/bash
# 测试 evm_block_number 两个 0 值（finalized / safe）
# 1) 通过 blackbox exporter 拉取指标（需先启动 exporter）
# 2) 直接请求 RPC，看 safe/finalized 返回

BLACKBOX="${BLACKBOX:-http://127.0.0.1:9115}"
RPC="${RPC:-https://eth.drpc.org}"

echo "=== 1) Blackbox exporter 探针（target=$RPC, module=chain_info）==="
echo "curl \"${BLACKBOX}/probe?target=$(echo -n "$RPC" | sed 's/:/%3A/g; s/\//%2F/g')&module=chain_info\""
echo ""
curl -sS "${BLACKBOX}/probe?target=${RPC}&module=chain_info" | grep -E "evm_block_number|^#"

echo ""
echo "=== 2) 直接 RPC：eth_getBlockByNumber(finalized, false) ==="
curl -sS -X POST "$RPC" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["finalized",false],"id":1}' | jq .

echo ""
echo "=== 3) 直接 RPC：eth_getBlockByNumber(safe, false) ==="
curl -sS -X POST "$RPC" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["safe",false],"id":1}' | jq .

echo ""
echo "=== 4) 对比：eth_blockNumber (latest) ==="
curl -sS -X POST "$RPC" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq .
