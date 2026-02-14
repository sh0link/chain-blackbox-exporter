#!/bin/bash
# Test evm_block_number for two zero values (finalized / safe)
# 1) Fetch metrics via blackbox exporter (exporter must be running)
# 2) Call RPC directly to see safe/finalized responses

BLACKBOX="${BLACKBOX:-http://127.0.0.1:9115}"
RPC="${RPC:-https://eth.drpc.org}"

echo "=== 1) Blackbox exporter probe (target=$RPC, module=chain_info) ==="
echo "curl \"${BLACKBOX}/probe?target=$(echo -n "$RPC" | sed 's/:/%3A/g; s/\//%2F/g')&module=chain_info\""
echo ""
curl -sS "${BLACKBOX}/probe?target=${RPC}&module=chain_info" | grep -E "evm_block_number|^#"

echo ""
echo "=== 2) Direct RPC: eth_getBlockByNumber(finalized, false) ==="
curl -sS -X POST "$RPC" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["finalized",false],"id":1}' | jq .

echo ""
echo "=== 3) Direct RPC: eth_getBlockByNumber(safe, false) ==="
curl -sS -X POST "$RPC" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["safe",false],"id":1}' | jq .

echo ""
echo "=== 4) Compare: eth_blockNumber (latest) ==="
curl -sS -X POST "$RPC" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' | jq .
