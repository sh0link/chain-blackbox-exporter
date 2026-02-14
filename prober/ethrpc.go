// Copyright 2016 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prober

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/sha3"
)

const (
	// ethrpcKeepAlive is the idle connection keepalive time for RPC HTTP client (>= 2 min).
	ethrpcKeepAlive = 130 * time.Second
)

var (
	ethrpcClient     *http.Client
	ethrpcClientOnce sync.Once
)

// envEthrpcInsecureSkipVerify: when set to "1", "true", or "yes", the ethrpc HTTP client
// skips TLS certificate verification (e.g. when behind a proxy that does TLS inspection).
const envEthrpcInsecureSkipVerify = "BLACKBOX_ETHRPC_INSECURE_SKIP_VERIFY"

func getEthrpcClient() *http.Client {
	ethrpcClientOnce.Do(func() {
		transport := &http.Transport{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       ethrpcKeepAlive,
			DisableKeepAlives:     false,
			ResponseHeaderTimeout: 30 * time.Second,
		}
		if v := strings.ToLower(strings.TrimSpace(os.Getenv(envEthrpcInsecureSkipVerify))); v == "1" || v == "true" || v == "yes" {
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		ethrpcClient = &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		}
	})
	return ethrpcClient
}

// jsonrpcReq is a single JSON-RPC 2.0 request.
type jsonrpcReq struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

// jsonrpcResp is a single JSON-RPC 2.0 response.
type jsonrpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// jsonrpcBatchResp is an array of JSON-RPC responses (for batch).
type jsonrpcBatchResp []jsonrpcResp

func (r *jsonrpcResp) resultHex() (string, error) {
	if r.Error != nil {
		return "", fmt.Errorf("rpc error %d: %s", r.Error.Code, r.Error.Message)
	}
	var s string
	if err := json.Unmarshal(r.Result, &s); err != nil {
		return "", err
	}
	if strings.HasPrefix(s, "0x") {
		return s[2:], nil
	}
	return s, nil
}

func (r *jsonrpcResp) resultBigInt() (*big.Int, error) {
	hexStr, err := r.resultHex()
	if err != nil {
		return nil, err
	}
	if hexStr == "" || hexStr == "0x" {
		return big.NewInt(0), nil
	}
	b, err := hex.DecodeString(padHexToEven(hexStr))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func (r *jsonrpcResp) resultUint64() (uint64, error) {
	hexStr, err := r.resultHex()
	if err != nil {
		return 0, err
	}
	if hexStr == "" || hexStr == "0x" {
		return 0, nil
	}
	b, err := hex.DecodeString(padHexToEven(hexStr))
	if err != nil {
		return 0, err
	}
	if len(b) > 8 {
		b = b[len(b)-8:]
	}
	var u uint64
	for _, x := range b {
		u = u<<8 | uint64(x)
	}
	return u, nil
}

// ethCall performs a single JSON-RPC call.
func ethCall(ctx context.Context, rpcURL string, method string, params []interface{}) (*jsonrpcResp, error) {
	body, err := json.Marshal(&jsonrpcReq{JSONRPC: "2.0", Method: method, Params: params, ID: 1})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := getEthrpcClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rpc status %d", resp.StatusCode)
	}

	var out jsonrpcResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ethCallBatch performs a JSON-RPC batch call and returns responses in order.
func ethCallBatch(ctx context.Context, rpcURL string, calls []jsonrpcReq) ([]jsonrpcResp, error) {
	// set IDs
	for i := range calls {
		calls[i].ID = i + 1
		calls[i].JSONRPC = "2.0"
	}
	body, err := json.Marshal(calls)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := getEthrpcClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rpc status %d", resp.StatusCode)
	}

	var out jsonrpcBatchResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	// reorder by ID (some RPCs return out of order)
	byID := make(map[int]jsonrpcResp)
	for _, r := range out {
		byID[r.ID] = r
	}
	result := make([]jsonrpcResp, len(calls))
	for i := range calls {
		result[i] = byID[i+1]
	}
	return result, nil
}

// normalizeRPCURL ensures URL has scheme.
func normalizeRPCURL(target string) string {
	if target == "" {
		return target
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "http://" + target
	}
	return target
}

// ProbeChainInfo gets latest/safe/finalized block numbers and chainId for one RPC URL (target).
func ProbeChainInfo(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger, params url.Values) bool {
	_ = module
	rpcURL := normalizeRPCURL(target)

	chainIDResp, err := ethCall(ctx, rpcURL, "eth_chainId", nil)
	if err != nil {
		logger.Error("eth_chainId failed", "err", err, "url", rpcURL)
		return false
	}
	chainIDBig, err := chainIDResp.resultBigInt()
	if err != nil {
		logger.Error("eth_chainId decode failed", "err", err)
		return false
	}
	chainIDStr := chainIDBig.String()

	blockGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "evm_block_number",
		Help: "EVM block number (latest, safe, finalized) for the RPC endpoint",
	}, []string{"url", "chain_id", "state"})
	registry.MustRegister(blockGauge)

	// Latest: eth_blockNumber
	latestResp, err := ethCall(ctx, rpcURL, "eth_blockNumber", nil)
	if err != nil {
		logger.Error("eth_blockNumber failed", "err", err)
		return false
	}
	latestNum, err := latestResp.resultBigInt()
	if err != nil {
		logger.Error("eth_blockNumber decode failed", "err", err)
		return false
	}
	blockGauge.WithLabelValues(rpcURL, chainIDStr, "latest").Set(float64(latestNum.Uint64()))

	// Safe and finalized: eth_getBlockByNumber("safe"/"finalized", false) - optional
	for _, state := range []string{"safe", "finalized"} {
		resp, err := ethCall(ctx, rpcURL, "eth_getBlockByNumber", []interface{}{state, false})
		if err != nil {
			logger.Debug("eth_getBlockByNumber failed (optional)", "state", state, "err", err)
			blockGauge.WithLabelValues(rpcURL, chainIDStr, state).Set(0)
			continue
		}
		var block struct {
			Number string `json:"number"`
		}
		if err := json.Unmarshal(resp.Result, &block); err != nil || block.Number == "" {
			blockGauge.WithLabelValues(rpcURL, chainIDStr, state).Set(0)
			continue
		}
		bnStr := strings.TrimPrefix(block.Number, "0x")
		b, err := hex.DecodeString(padHexToEven(bnStr))
		if err != nil {
			blockGauge.WithLabelValues(rpcURL, chainIDStr, state).Set(0)
			continue
		}
		blockNum := new(big.Int).SetBytes(b)
		blockGauge.WithLabelValues(rpcURL, chainIDStr, state).Set(float64(blockNum.Uint64()))
	}

	return true
}

// parseAccounts parses params["account"] into list of (name, address).
func parseAccounts(params url.Values) [][2]string {
	var out [][2]string
	for _, s := range params["account"] {
		s = strings.TrimSpace(s)
		idx := strings.Index(s, ":")
		if idx <= 0 {
			continue
		}
		name, addr := strings.TrimSpace(s[:idx]), strings.TrimSpace(s[idx+1:])
		if name != "" && addr != "" {
			out = append(out, [2]string{name, addr})
		}
	}
	return out
}

func parseBoolParam(params url.Values, key string) bool {
	v := params.Get(key)
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "1" || v == "true" || v == "yes"
}

// weiToEther converts wei (big.Int) to ether (float64) to avoid overflow in metric value.
func weiToEther(wei *big.Int) float64 {
	if wei == nil || wei.Sign() == 0 {
		return 0
	}
	f := new(big.Float).SetInt(wei)
	f.Quo(f, big.NewFloat(1e18))
	ether, _ := f.Float64()
	return ether
}

// rawToHuman converts raw token units to human units using decimals (e.g. 18 -> divide by 10^18).
func rawToHuman(raw *big.Int, decimals uint8) float64 {
	if raw == nil || raw.Sign() == 0 {
		return 0
	}
	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals)), nil)
	f := new(big.Float).SetInt(raw)
	f.Quo(f, new(big.Float).SetInt(divisor))
	out, _ := f.Float64()
	return out
}

// ProbeBalance gets native balance (in ether) and nonce for accounts.
func ProbeBalance(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger, params url.Values) bool {
	_ = module
	rpcURL := normalizeRPCURL(target)
	accounts := parseAccounts(params)
	if len(accounts) == 0 {
		logger.Error("no account param (format: accountName:address)")
		return false
	}
	useBatch := parseBoolParam(params, "use_batch")

	chainIDResp, err := ethCall(ctx, rpcURL, "eth_chainId", nil)
	if err != nil {
		logger.Error("eth_chainId failed", "err", err)
		return false
	}
	chainIDBig, err := chainIDResp.resultBigInt()
	if err != nil {
		logger.Error("eth_chainId decode failed", "err", err)
		return false
	}
	chainIDStr := chainIDBig.String()

	balanceGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "evm_account_balance_ether",
		Help: "EVM account native token balance in ether",
	}, []string{"url", "chain_id", "account_name", "account_address"})
	nonceGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "evm_account_nonce",
		Help: "EVM account nonce",
	}, []string{"url", "chain_id", "account_name", "account_address"})
	registry.MustRegister(balanceGauge)
	registry.MustRegister(nonceGauge)

	if useBatch {
		var calls []jsonrpcReq
		for _, a := range accounts {
			calls = append(calls, jsonrpcReq{Method: "eth_getBalance", Params: []interface{}{a[1], "latest"}})
			calls = append(calls, jsonrpcReq{Method: "eth_getTransactionCount", Params: []interface{}{a[1], "latest"}})
		}
		reqs := make([]jsonrpcReq, len(calls))
		copy(reqs, calls)
		responses, err := ethCallBatch(ctx, rpcURL, reqs)
		if err != nil {
			logger.Error("eth batch call failed", "err", err)
			return false
		}
		for i, a := range accounts {
			balanceResp := responses[i*2]
			nonceResp := responses[i*2+1]
			bal, err := balanceResp.resultBigInt()
			if err != nil {
				logger.Error("balance decode failed", "account", a[0], "err", err)
				continue
			}
			balanceGauge.WithLabelValues(rpcURL, chainIDStr, a[0], a[1]).Set(weiToEther(bal))
			nonce, err := nonceResp.resultUint64()
			if err != nil {
				logger.Error("nonce decode failed", "account", a[0], "err", err)
				continue
			}
			nonceGauge.WithLabelValues(rpcURL, chainIDStr, a[0], a[1]).Set(float64(nonce))
		}
	} else {
		for _, a := range accounts {
			balResp, err := ethCall(ctx, rpcURL, "eth_getBalance", []interface{}{a[1], "latest"})
			if err != nil {
				logger.Error("eth_getBalance failed", "account", a[0], "err", err)
				continue
			}
			bal, err := balResp.resultBigInt()
			if err != nil {
				logger.Error("balance decode failed", "account", a[0], "err", err)
				continue
			}
			balanceGauge.WithLabelValues(rpcURL, chainIDStr, a[0], a[1]).Set(weiToEther(bal))

			nonceResp, err := ethCall(ctx, rpcURL, "eth_getTransactionCount", []interface{}{a[1], "latest"})
			if err != nil {
				logger.Error("eth_getTransactionCount failed", "account", a[0], "err", err)
				continue
			}
			nonce, err := nonceResp.resultUint64()
			if err != nil {
				logger.Error("nonce decode failed", "account", a[0], "err", err)
				continue
			}
			nonceGauge.WithLabelValues(rpcURL, chainIDStr, a[0], a[1]).Set(float64(nonce))
		}
	}
	return true
}

// erc20BalanceOfData returns calldata for balanceOf(address).
func erc20BalanceOfData(account string) (string, error) {
	selector, err := methodSelector("balanceOf(address)")
	if err != nil {
		return "", err
	}
	addrBytes, err := addrToHex(account)
	if err != nil {
		return "", err
	}
	return "0x" + selector + addrBytes, nil
}

// erc20SymbolData returns calldata for symbol().
func erc20SymbolData() (string, error) {
	selector, err := methodSelector("symbol()")
	if err != nil {
		return "", err
	}
	return "0x" + selector, nil
}

// erc20DecimalsData returns calldata for decimals().
func erc20DecimalsData() (string, error) {
	selector, err := methodSelector("decimals()")
	if err != nil {
		return "", err
	}
	return "0x" + selector, nil
}

// methodSelector returns first 4 bytes of keccak256(signature) as hex (no 0x).
// Signature must not include return type, e.g. "balanceOf(address)".
func methodSelector(signature string) (string, error) {
	// strip return type if present: "balanceOf(address)(uint256)" -> "balanceOf(address)"
	if idx := strings.Index(signature, ")("); idx != -1 {
		signature = signature[:idx+1]
	}
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(signature))
	return hex.EncodeToString(h.Sum(nil)[:4]), nil
}

func addrToHex(addr string) (string, error) {
	addr = strings.TrimPrefix(strings.TrimSpace(addr), "0x")
	if len(addr) != 40 {
		return "", fmt.Errorf("invalid address length")
	}
	// left-pad to 32 bytes (64 hex chars)
	return strings.Repeat("0", 24) + addr, nil
}

// ProbeErc20Balance gets ERC20 balance and symbol for (account, token) pairs.
func ProbeErc20Balance(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger, params url.Values) bool {
	_ = module
	rpcURL := normalizeRPCURL(target)
	accounts := parseAccounts(params)
	tokens := params["token"]
	if len(accounts) == 0 || len(tokens) == 0 {
		logger.Error("account and token params required")
		return false
	}
	useBatch := parseBoolParam(params, "use_batch")

	chainIDResp, err := ethCall(ctx, rpcURL, "eth_chainId", nil)
	if err != nil {
		logger.Error("eth_chainId failed", "err", err)
		return false
	}
	chainIDBig, _ := chainIDResp.resultBigInt()
	chainIDStr := chainIDBig.String()

	balanceGauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "evm_erc20_balance",
		Help: "EVM ERC20 token balance (in token units, scaled by decimals)",
	}, []string{"url", "chain_id", "account_name", "account_address", "token", "symbol"})
	registry.MustRegister(balanceGauge)

	type toCall struct {
		accountName    string
		accountAddress string
		token          string
	}
	var toCallList []toCall
	seenToken := make(map[string]struct{})
	var uniqueTokens []string
	for _, a := range accounts {
		for _, t := range tokens {
			t = strings.TrimSpace(strings.TrimPrefix(t, "0x"))
			if t == "" {
				continue
			}
			if len(t) != 40 {
				t = strings.Repeat("0", 40-len(t)) + t
			}
			tokenAddr := "0x" + t
			toCallList = append(toCallList, toCall{a[0], a[1], tokenAddr})
			if _, ok := seenToken[tokenAddr]; !ok {
				seenToken[tokenAddr] = struct{}{}
				uniqueTokens = append(uniqueTokens, tokenAddr)
			}
		}
	}

	symbolData, _ := erc20SymbolData()
	decimalsData, _ := erc20DecimalsData()

	// Get decimals for each unique token (decimals() returns uint8).
	tokenDecimals := make(map[string]uint8)
	if useBatch {
		var decCalls []jsonrpcReq
		for _, tokenAddr := range uniqueTokens {
			decCalls = append(decCalls, jsonrpcReq{Method: "eth_call", Params: []interface{}{
				map[string]string{"to": tokenAddr, "data": decimalsData},
				"latest",
			}})
		}
		decReqs := make([]jsonrpcReq, len(decCalls))
		copy(decReqs, decCalls)
		decResponses, err := ethCallBatch(ctx, rpcURL, decReqs)
		if err == nil {
			for i, tokenAddr := range uniqueTokens {
				hexStr, _ := decResponses[i].resultHex()
				tokenDecimals[tokenAddr] = decodeDecimalsFromHex(hexStr)
			}
		}
	} else {
		for _, tokenAddr := range uniqueTokens {
			resp, err := ethCall(ctx, rpcURL, "eth_call", []interface{}{
				map[string]string{"to": tokenAddr, "data": decimalsData},
				"latest",
			})
			if err == nil {
				hexStr, _ := resp.resultHex()
				tokenDecimals[tokenAddr] = decodeDecimalsFromHex(hexStr)
			}
		}
	}

	if useBatch {
		var calls []jsonrpcReq
		for _, c := range toCallList {
			balData, _ := erc20BalanceOfData(c.accountAddress)
			calls = append(calls, jsonrpcReq{Method: "eth_call", Params: []interface{}{
				map[string]string{"to": c.token, "data": balData},
				"latest",
			}})
			calls = append(calls, jsonrpcReq{Method: "eth_call", Params: []interface{}{
				map[string]string{"to": c.token, "data": symbolData},
				"latest",
			}})
		}
		reqs := make([]jsonrpcReq, len(calls))
		copy(reqs, calls)
		responses, err := ethCallBatch(ctx, rpcURL, reqs)
		if err != nil {
			logger.Error("eth_call batch failed", "err", err)
			return false
		}
		for i, c := range toCallList {
			balHex, _ := responses[i*2].resultHex()
			symHex, _ := responses[i*2+1].resultHex()
			bal := decodeUint256Hex(balHex)
			symbol := decodeStringBytesHex(symHex)
			dec := tokenDecimals[c.token]
			balanceGauge.WithLabelValues(rpcURL, chainIDStr, c.accountName, c.accountAddress, c.token, symbol).Set(rawToHuman(bal, dec))
		}
	} else {
		for _, c := range toCallList {
			balData, _ := erc20BalanceOfData(c.accountAddress)
			balResp, err := ethCall(ctx, rpcURL, "eth_call", []interface{}{
				map[string]string{"to": c.token, "data": balData},
				"latest",
			})
			if err != nil {
				logger.Error("eth_call balanceOf failed", "token", c.token, "err", err)
				continue
			}
			balHex, err := balResp.resultHex()
			if err != nil {
				continue
			}
			symResp, err := ethCall(ctx, rpcURL, "eth_call", []interface{}{
				map[string]string{"to": c.token, "data": symbolData},
				"latest",
			})
			symbol := ""
			if err == nil {
				symHex, _ := symResp.resultHex()
				symbol = decodeStringBytesHex(symHex)
			}
			bal := decodeUint256Hex(balHex)
			dec := tokenDecimals[c.token]
			balanceGauge.WithLabelValues(rpcURL, chainIDStr, c.accountName, c.accountAddress, c.token, symbol).Set(rawToHuman(bal, dec))
		}
	}
	return true
}

// padHexToEven 确保 hex 字符串为偶数长度，供 hex.DecodeString 使用（每字节 2 个十六进制位）。
func padHexToEven(s string) string {
	if len(s)%2 == 1 {
		return "0" + s
	}
	return s
}

func decodeUint256Hex(hexStr string) *big.Int {
	if hexStr == "" {
		return big.NewInt(0)
	}
	b, err := hex.DecodeString(padHexToEven(hexStr))
	if err != nil || len(b) == 0 {
		return big.NewInt(0)
	}
	return new(big.Int).SetBytes(b)
}

// decodeDecimalsFromHex decodes ERC20 decimals() return (uint8, 32 bytes right-padded).
func decodeDecimalsFromHex(hexStr string) uint8 {
	if hexStr == "" || len(hexStr) < 64 {
		return 18
	}
	b, err := hex.DecodeString(padHexToEven(hexStr))
	if err != nil || len(b) < 32 {
		return 18
	}
	return b[31]
}

// decodeStringBytesHex decodes ABI-encoded string from eth_call (offset + length + data).
func decodeStringBytesHex(hexStr string) string {
	if hexStr == "" || len(hexStr) < 128 {
		return ""
	}
	b, err := hex.DecodeString(padHexToEven(hexStr))
	if err != nil || len(b) < 64 {
		return ""
	}
	// first 32 bytes = offset, next 32 = length
	length := new(big.Int).SetBytes(b[32:64]).Uint64()
	if length == 0 || int(length) > len(b)-64 {
		return ""
	}
	return string(b[64 : 64+length])
}

// contract call spec: "contractName:contractAddress|methodSig|params|returnName:returnIndex|decimal"
// contractName and returnName are optional (for metric labels); omit the colon to use address/index only.
func parseCallSpec(s string) (contractAddr, contractName, methodSig, paramsStr, returnName string, returnIndex int, decimal int, err error) {
	parts := strings.Split(s, "|")
	if len(parts) < 5 {
		err = fmt.Errorf("call spec must have 5 parts: contractName:address|methodSig|params|returnName:returnIndex|decimal")
		return
	}
	// Part 0: contractName:address or address
	part0 := strings.TrimSpace(parts[0])
	if idx := strings.Index(part0, ":"); idx >= 0 {
		contractName = strings.TrimSpace(part0[:idx])
		contractAddr = strings.TrimSpace(part0[idx+1:])
	} else {
		contractAddr = part0
	}
	methodSig = strings.TrimSpace(parts[1])
	paramsStr = strings.TrimSpace(parts[2])
	// Part 3: returnName:returnIndex or returnIndex
	part3 := strings.TrimSpace(parts[3])
	if idx := strings.Index(part3, ":"); idx >= 0 {
		returnName = strings.TrimSpace(part3[:idx])
		part3 = strings.TrimSpace(part3[idx+1:])
	}
	returnIndex, err = strconv.Atoi(part3)
	if err != nil {
		return
	}
	decimal, err = strconv.Atoi(strings.TrimSpace(parts[4]))
	if err != nil {
		return
	}
	return
}

// encodeCallData builds calldata from method signature and comma-separated params (address or uint256).
func encodeCallData(methodSig, paramsStr string) (string, error) {
	selector, err := methodSelector(methodSig)
	if err != nil {
		return "", err
	}
	if paramsStr == "" {
		return "0x" + selector, nil
	}
	var encoded []string
	params := strings.Split(paramsStr, ",")
	// infer types from common patterns: 0x... = address, else uint256
	for _, p := range params {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "0x") {
			addrHex, err := addrToHex(p)
			if err != nil {
				return "", err
			}
			encoded = append(encoded, addrHex)
		} else {
			// uint256
			n, ok := new(big.Int).SetString(p, 10)
			if !ok {
				return "", fmt.Errorf("invalid uint256 param: %s", p)
			}
			encoded = append(encoded, fmt.Sprintf("%064x", n))
		}
	}
	return "0x" + selector + strings.Join(encoded, ""), nil
}

// returnTypeFromSignature extracts return type from "method(args)(returnType)".
// For multiple return values the type is a tuple e.g. "uint112,uint112,uint32".
func returnTypeFromSignature(sig string) string {
	idx := strings.Index(sig, ")(")
	if idx == -1 {
		return "uint256"
	}
	end := strings.LastIndex(sig, ")")
	if end <= idx+2 {
		return "uint256"
	}
	return strings.TrimSpace(sig[idx+2 : end])
}

// getReturnTypeAt returns the type at index from a tuple return type (e.g. "uint112,uint112,uint32" -> index 1 -> "uint112").
func getReturnTypeAt(returnTypeTuple string, index int) string {
	parts := strings.Split(returnTypeTuple, ",")
	if index < 0 || index >= len(parts) {
		return "uint256"
	}
	return strings.TrimSpace(parts[index])
}

// decodeCallResult converts eth_call result to a float for the metric.
// returnIndex is the 32-byte word index. decimal divides value for uint*/int*; for address/bytes32 we keccak and take first 4 bytes as uint.
func decodeCallResult(resultHex, returnType string, returnIndex, decimal int) (float64, error) {
	b, err := hex.DecodeString(padHexToEven(resultHex))
	if err != nil {
		return 0, err
	}
	offset := returnIndex * 32
	if offset+32 > len(b) {
		return 0, fmt.Errorf("result too short for index %d", returnIndex)
	}
	word := b[offset : offset+32]

	returnType = strings.ToLower(strings.TrimSpace(returnType))
	// uint*/int* (uint256, uint112, uint32, int256, etc.) as numeric
	if strings.HasPrefix(returnType, "uint") || strings.HasPrefix(returnType, "int") {
		val := new(big.Int).SetBytes(word)
		if decimal > 0 {
			divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimal)), nil)
			val = val.Div(val, divisor)
		}
		return float64(val.Uint64()), nil
	}
	// address, bytes32, etc.: keccak then first 4 bytes as big-endian uint32
	h := sha3.NewLegacyKeccak256()
	h.Write(word)
	hash := h.Sum(nil)
	var u uint32
	for i := 0; i < 4 && i < len(hash); i++ {
		u = u<<8 | uint32(hash[i])
	}
	return float64(u), nil
}

// ProbeContractCall runs eth_call for each call spec and exports the result as a gauge.
func ProbeContractCall(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger, params url.Values) bool {
	_ = module
	rpcURL := normalizeRPCURL(target)
	callSpecs := params["call"]
	if len(callSpecs) == 0 {
		logger.Error("call param required (contract|methodSig|params|returnIndex|decimal)")
		return false
	}

	chainIDResp, err := ethCall(ctx, rpcURL, "eth_chainId", nil)
	if err != nil {
		logger.Error("eth_chainId failed", "err", err)
		return false
	}
	chainIDBig, _ := chainIDResp.resultBigInt()
	chainIDStr := chainIDBig.String()

	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "evm_contract_call_value",
		Help: "EVM contract call return value (scaled by decimal for uint256; hash prefix for other types)",
	}, []string{"url", "chain_id", "contract_name", "contract", "method", "params", "return_name"})
	registry.MustRegister(gauge)

	for _, spec := range callSpecs {
		contractAddr, contractName, methodSig, paramsStr, returnName, returnIndex, decimal, err := parseCallSpec(spec)
		if err != nil {
			logger.Error("invalid call spec", "spec", spec, "err", err)
			continue
		}
		data, err := encodeCallData(methodSig, paramsStr)
		if err != nil {
			logger.Error("encode call data failed", "method", methodSig, "err", err)
			continue
		}
		resp, err := ethCall(ctx, rpcURL, "eth_call", []interface{}{
			map[string]string{"to": contractAddr, "data": data},
			"latest",
		})
		if err != nil {
			logger.Error("eth_call failed", "contract", contractAddr, "err", err)
			continue
		}
		hexStr, err := resp.resultHex()
		if err != nil {
			logger.Error("eth_call result decode failed", "err", err)
			continue
		}
		returnTypeTuple := returnTypeFromSignature(methodSig)
		returnTypeAt := getReturnTypeAt(returnTypeTuple, returnIndex)
		val, err := decodeCallResult(hexStr, returnTypeAt, returnIndex, decimal)
		if err != nil {
			logger.Error("decode call result failed", "err", err)
			continue
		}
		methodName := methodSig
		if idx := strings.Index(methodName, "("); idx != -1 {
			methodName = methodName[:idx]
		}
		gauge.WithLabelValues(rpcURL, chainIDStr, contractName, contractAddr, methodName, paramsStr, returnName).Set(val)
	}
	return true
}
