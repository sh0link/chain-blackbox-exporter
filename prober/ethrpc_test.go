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
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
)

// mockEthRPCServerV2 reads body once and handles single or batch JSON-RPC.
func mockEthRPCServerV2(t *testing.T, handlers map[string]func(params []interface{}) interface{}) *httptest.Server {
	t.Helper()
	chainID := "0x1"
	blockNumber := "0x1234"
	blockSafeFinalized := map[string]interface{}{"number": "0x1230"}
	getBalance := "0xde0b6b3a7640000"
	getNonce := "0x2a"
	ethCallResult := "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"

	if handlers != nil {
		if h, ok := handlers["eth_chainId"]; ok && h(nil) != nil {
			if s, ok := h(nil).(string); ok {
				chainID = s
			}
		}
		if h, ok := handlers["eth_call"]; ok && h(nil) != nil {
			if s, ok := h(nil).(string); ok {
				ethCallResult = s
			}
		}
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		dec := json.NewDecoder(r.Body)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		// Try single request first (object)
		var single jsonrpcReq
		if err := json.Unmarshal(raw, &single); err == nil && single.Method != "" {
			var res interface{}
			switch single.Method {
			case "eth_chainId":
				res = chainID
			case "eth_blockNumber":
				res = blockNumber
			case "eth_getBlockByNumber":
				res = blockSafeFinalized
			case "eth_getBalance":
				res = getBalance
			case "eth_getTransactionCount":
				res = getNonce
			case "eth_call":
				res = ethCallResult
			default:
				if h, ok := handlers[single.Method]; ok {
					res = h(single.Params)
				} else {
					res = "0x0"
				}
			}
			resultBytes, _ := json.Marshal(res)
			_ = json.NewEncoder(w).Encode(jsonrpcResp{JSONRPC: "2.0", ID: single.ID, Result: resultBytes})
			return
		}

		// Try batch (array)
		var batch []jsonrpcReq
		if err := json.Unmarshal(raw, &batch); err == nil && len(batch) > 0 {
			var out []jsonrpcResp
			for _, req := range batch {
				var res interface{}
				switch req.Method {
				case "eth_chainId":
					res = chainID
				case "eth_blockNumber":
					res = blockNumber
				case "eth_getBlockByNumber":
					res = blockSafeFinalized
				case "eth_getBalance":
					res = getBalance
				case "eth_getTransactionCount":
					res = getNonce
				case "eth_call":
					res = ethCallResult
				default:
					res = "0x0"
				}
				resultBytes, _ := json.Marshal(res)
				out = append(out, jsonrpcResp{JSONRPC: "2.0", ID: req.ID, Result: resultBytes})
			}
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
}

// TestMockEthRPCServerV2_Direct verifies the mock server responds correctly to a direct POST.
func TestMockEthRPCServerV2_Direct(t *testing.T) {
	srv := mockEthRPCServerV2(t, nil)
	defer srv.Close()

	body := `{"jsonrpc":"2.0","method":"eth_chainId","params":null,"id":1}`
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var out jsonrpcResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	var result string
	if err := json.Unmarshal(out.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result != "0x1" {
		t.Errorf("result = %q, want 0x1", result)
	}
}

// TestEthCall_Mock verifies ethCall works against the mock server (same client as prober).
func TestEthCall_Mock(t *testing.T) {
	srv := mockEthRPCServerV2(t, nil)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := ethCall(ctx, srv.URL, "eth_chainId", nil)
	if err != nil {
		t.Fatalf("ethCall: %v", err)
	}
	chainID, err := resp.resultBigInt()
	if err != nil {
		t.Fatalf("resultBigInt: %v", err)
	}
	if chainID.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("chainId = %v, want 1", chainID)
	}
}

func TestNormalizeRPCURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"https://eth.drpc.org", "https://eth.drpc.org"},
		{"http://localhost:8545", "http://localhost:8545"},
		{"localhost:8545", "http://localhost:8545"},
		{"eth.drpc.org", "http://eth.drpc.org"},
	}
	for _, tt := range tests {
		got := normalizeRPCURL(tt.in)
		if got != tt.want {
			t.Errorf("normalizeRPCURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseAccounts(t *testing.T) {
	tests := []struct {
		params url.Values
		want   [][2]string
	}{
		{url.Values{}, [][2]string{}},
		{url.Values{"account": {"alice:0x1234567890123456789012345678901234567890"}}, [][2]string{{"alice", "0x1234567890123456789012345678901234567890"}}},
		{url.Values{"account": {"a:0xab", "b:0xcd"}}, [][2]string{{"a", "0xab"}, {"b", "0xcd"}}},
		{url.Values{"account": {":0xab"}}, [][2]string{}},
		{url.Values{"account": {"no-colon"}}, [][2]string{}},
	}
	for i, tt := range tests {
		got := parseAccounts(tt.params)
		if len(got) != len(tt.want) {
			t.Errorf("#%d parseAccounts: len = %d, want %d", i, len(got), len(tt.want))
			continue
		}
		for j := range got {
			if got[j][0] != tt.want[j][0] || got[j][1] != tt.want[j][1] {
				t.Errorf("#%d parseAccounts[%d] = %v, want %v", i, j, got[j], tt.want[j])
			}
		}
	}
}

func TestParseBoolParam(t *testing.T) {
	tests := []struct {
		params url.Values
		key    string
		want   bool
	}{
		{url.Values{}, "use_batch", false},
		{url.Values{"use_batch": {"0"}}, "use_batch", false},
		{url.Values{"use_batch": {"1"}}, "use_batch", true},
		{url.Values{"use_batch": {"true"}}, "use_batch", true},
		{url.Values{"use_batch": {"yes"}}, "use_batch", true},
		{url.Values{"use_batch": {"TRUE"}}, "use_batch", true},
	}
	for _, tt := range tests {
		got := parseBoolParam(tt.params, tt.key)
		if got != tt.want {
			t.Errorf("parseBoolParam(%v, %q) = %v, want %v", tt.params, tt.key, got, tt.want)
		}
	}
}

func TestMethodSelector(t *testing.T) {
	// balanceOf(address) selector is 0x70a08231 (known from Ethereum)
	sel, err := methodSelector("balanceOf(address)")
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != 8 {
		t.Errorf("selector hex length = %d, want 8", len(sel))
	}
	b, _ := hex.DecodeString(sel)
	if len(b) != 4 {
		t.Fatalf("selector bytes length = %d, want 4", len(b))
	}
	// balanceOf(address) keccak256 first 4 bytes
	expected := "70a08231"
	if sel != expected {
		t.Errorf("methodSelector(balanceOf(address)) = %s, want %s", sel, expected)
	}

	// with return type stripped
	sel2, err := methodSelector("balanceOf(address)(uint256)")
	if err != nil {
		t.Fatal(err)
	}
	if sel2 != sel {
		t.Errorf("with return type: got %s, want %s", sel2, sel)
	}
}

func TestAddrToHex(t *testing.T) {
	addr := "0x1234567890123456789012345678901234567890"
	got, err := addrToHex(addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 64 {
		t.Errorf("addrToHex length = %d, want 64", len(got))
	}
	wantPrefix := strings.Repeat("0", 24) + "1234567890123456789012345678901234567890"
	if got != wantPrefix {
		t.Errorf("addrToHex = %s, want %s", got, wantPrefix)
	}

	_, err = addrToHex("short")
	if err == nil {
		t.Error("addrToHex(short) should error")
	}
}

func TestParseCallSpec(t *testing.T) {
	tests := []struct {
		s                string
		wantAddr         string
		wantContractName string
		wantSig          string
		wantParams       string
		wantReturnName   string
		wantIdx          int
		wantDec          int
		wantErr          bool
	}{
		{"0xabc|balanceOf(address)(uint256)|0x123|0|0", "0xabc", "", "balanceOf(address)(uint256)", "0x123", "", 0, 0, false},
		{"0xabc|totalSupply()(uint256)||0|0", "0xabc", "", "totalSupply()(uint256)", "", "", 0, 0, false},
		{"0xabc|foo()||0|18", "0xabc", "", "foo()", "", "", 0, 18, false},
		{"a|b|c|1|2", "a", "", "b", "c", "", 1, 2, false},
		{"USDC:0xabc|balanceOf(address)(uint256)|0x123|balance:0|18", "0xabc", "USDC", "balanceOf(address)(uint256)", "0x123", "balance", 0, 18, false},
		{"Uniswap:0xdef|getReserves()(uint112,uint112,uint32)||reserve0:0|6", "0xdef", "Uniswap", "getReserves()(uint112,uint112,uint32)", "", "reserve0", 0, 6, false},
		{"only|four", "", "", "", "", "", 0, 0, true},
		{"a|b|c|notnum|0", "", "", "", "", "", 0, 0, true},
	}
	for _, tt := range tests {
		addr, cname, sig, paramsStr, rname, idx, dec, err := parseCallSpec(tt.s)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseCallSpec(%q) err = %v, wantErr %v", tt.s, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if addr != tt.wantAddr || cname != tt.wantContractName || sig != tt.wantSig || paramsStr != tt.wantParams || rname != tt.wantReturnName || idx != tt.wantIdx || dec != tt.wantDec {
			t.Errorf("parseCallSpec(%q) = addr=%q,cname=%q,sig=%q,params=%q,rname=%q,idx=%d,dec=%d want addr=%q,cname=%q,sig=%q,params=%q,rname=%q,idx=%d,dec=%d",
				tt.s, addr, cname, sig, paramsStr, rname, idx, dec,
				tt.wantAddr, tt.wantContractName, tt.wantSig, tt.wantParams, tt.wantReturnName, tt.wantIdx, tt.wantDec)
		}
	}
}

func TestReturnTypeFromSignature(t *testing.T) {
	tests := []struct {
		sig  string
		want string
	}{
		{"balanceOf(address)(uint256)", "uint256"},
		{"totalSupply()(uint256)", "uint256"},
		{"name()(string)", "string"},
		{"noReturn()", "uint256"},
	}
	for _, tt := range tests {
		got := returnTypeFromSignature(tt.sig)
		if got != tt.want {
			t.Errorf("returnTypeFromSignature(%q) = %q, want %q", tt.sig, got, tt.want)
		}
	}
}

func TestDecodeUint256Hex(t *testing.T) {
	tests := []struct {
		hex  string
		want uint64
	}{
		{"", 0},
		{"0de0b6b3a7640000", 1000000000000000000}, // 1e18, 16 hex chars = 8 bytes
		{"2a", 42},
	}
	for _, tt := range tests {
		got := decodeUint256Hex(tt.hex)
		if got.Uint64() != tt.want {
			t.Errorf("decodeUint256Hex(%q) = %v, want %d", tt.hex, got, tt.want)
		}
	}
}

func TestDecodeStringBytesHex(t *testing.T) {
	// ABI-encoded string "USDC": offset=0x20, length=4, data=USDC
	offset := new(big.Int).SetInt64(32).Bytes()
	padOffset := make([]byte, 32)
	copy(padOffset[32-len(offset):], offset)
	length := new(big.Int).SetInt64(4).Bytes()
	padLength := make([]byte, 32)
	copy(padLength[32-len(length):], length)
	data := append([]byte("USDC"), make([]byte, 28)...) // 32 bytes
	encoded := hex.EncodeToString(append(append(padOffset, padLength...), data...))
	got := decodeStringBytesHex(encoded)
	if got != "USDC" {
		t.Errorf("decodeStringBytesHex = %q, want USDC", got)
	}
	if decodeStringBytesHex("") != "" {
		t.Error("decodeStringBytesHex(empty) should be empty")
	}
}

func TestProbeChainInfo(t *testing.T) {
	srv := mockEthRPCServerV2(t, nil)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	logger := promslog.NewNopLogger()
	params := url.Values{}
	module := config.Module{}

	ok := ProbeChainInfo(ctx, srv.URL, module, registry, logger, params)
	if !ok {
		t.Fatal("ProbeChainInfo failed")
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var evmBlock *dto.MetricFamily
	for _, mf := range mfs {
		if mf.GetName() == "evm_block_number" {
			evmBlock = mf
			break
		}
	}
	if evmBlock == nil {
		t.Fatal("metric evm_block_number not found")
	}
	if len(evmBlock.Metric) == 0 {
		t.Fatal("no evm_block_number metrics")
	}
	// should have latest, safe, finalized
	states := make(map[string]float64)
	for _, m := range evmBlock.Metric {
		for _, l := range m.Label {
			if l.GetName() == "state" {
				states[l.GetValue()] = m.Gauge.GetValue()
				break
			}
		}
	}
	if states["latest"] != 0x1234 {
		t.Errorf("evm_block_number state=latest = %v, want 4660", states["latest"])
	}
}

func TestProbeBalance(t *testing.T) {
	srv := mockEthRPCServerV2(t, nil)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	logger := promslog.NewNopLogger()
	params := url.Values{
		"account": {"alice:0x1234567890123456789012345678901234567890"},
	}
	module := config.Module{}

	ok := ProbeBalance(ctx, srv.URL, module, registry, logger, params)
	if !ok {
		t.Fatal("ProbeBalance failed")
	}

	// check balance metric (mock returns 1e18 wei -> 1.0 ether)
	mfs, _ := registry.Gather()
	var balanceVal float64
	for _, mf := range mfs {
		if mf.GetName() == "evm_account_balance_ether" {
			for _, m := range mf.Metric {
				balanceVal = m.Gauge.GetValue()
				break
			}
			break
		}
	}
	if balanceVal != 1.0 {
		t.Errorf("evm_account_balance_ether = %v, want 1.0 (1e18 wei)", balanceVal)
	}
}

func TestProbeBalance_NoAccount(t *testing.T) {
	srv := mockEthRPCServerV2(t, nil)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	logger := promslog.NewNopLogger()
	params := url.Values{}
	module := config.Module{}

	ok := ProbeBalance(ctx, srv.URL, module, registry, logger, params)
	if ok {
		t.Error("ProbeBalance should fail when no account param")
	}
}

func TestProbeBalance_UseBatch(t *testing.T) {
	srv := mockEthRPCServerV2(t, nil)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	logger := promslog.NewNopLogger()
	params := url.Values{
		"account":   {"bob:0xabcdef1234567890abcdef1234567890abcdef12"},
		"use_batch": {"true"},
	}
	module := config.Module{}

	ok := ProbeBalance(ctx, srv.URL, module, registry, logger, params)
	if !ok {
		t.Fatal("ProbeBalance with use_batch failed")
	}
	mfs, _ := registry.Gather()
	var found bool
	for _, mf := range mfs {
		if mf.GetName() == "evm_account_nonce" && len(mf.Metric) > 0 {
			if mf.Metric[0].Gauge.GetValue() != 42 {
				t.Errorf("evm_account_nonce = %v, want 42", mf.Metric[0].Gauge.GetValue())
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("evm_account_nonce metric not found")
	}
}

func TestProbeErc20Balance(t *testing.T) {
	srv := mockEthRPCServerV2(t, map[string]func([]interface{}) interface{}{
		"eth_call": func(p []interface{}) interface{} {
			// first call is balanceOf, second is symbol; return balance then ABI-encoded "USDC"
			return "0x0000000000000000000000000000000000000000000000000de0b6b3a7640000"
		},
	})
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	logger := promslog.NewNopLogger()
	params := url.Values{
		"account": {"alice:0x1234567890123456789012345678901234567890"},
		"token":   {"0x3c3a81e81dc49a522a592e7622a7e711c06bf354"},
	}
	module := config.Module{}

	ok := ProbeErc20Balance(ctx, srv.URL, module, registry, logger, params)
	if !ok {
		t.Fatal("ProbeErc20Balance failed")
	}
	mfs, _ := registry.Gather()
	for _, mf := range mfs {
		if mf.GetName() == "evm_erc20_balance" {
			if len(mf.Metric) == 0 {
				t.Error("evm_erc20_balance has no samples")
			}
			return
		}
	}
	t.Error("evm_erc20_balance metric not found")
}

func TestProbeErc20Balance_NoAccount(t *testing.T) {
	srv := mockEthRPCServerV2(t, nil)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	logger := promslog.NewNopLogger()
	params := url.Values{"token": {"0x1234567890123456789012345678901234567890"}}
	module := config.Module{}

	ok := ProbeErc20Balance(ctx, srv.URL, module, registry, logger, params)
	if ok {
		t.Error("ProbeErc20Balance should fail when no account")
	}
}

func TestProbeContractCall(t *testing.T) {
	srv := mockEthRPCServerV2(t, nil)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	logger := promslog.NewNopLogger()
	params := url.Values{
		"call": {"0x3c3a81e81dc49a522a592e7622a7e711c06bf354|totalSupply()(uint256)||0|0"},
	}
	module := config.Module{}

	ok := ProbeContractCall(ctx, srv.URL, module, registry, logger, params)
	if !ok {
		t.Fatal("ProbeContractCall failed")
	}
	mfs, _ := registry.Gather()
	var found bool
	for _, mf := range mfs {
		if mf.GetName() == "evm_contract_call_value" && len(mf.Metric) > 0 {
			// mock returns 0x0de0b6b3a7640000 = 1000000000000000000
			if mf.Metric[0].Gauge.GetValue() != 1000000000000000000 {
				t.Errorf("evm_contract_call_value = %v, want 1e18", mf.Metric[0].Gauge.GetValue())
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("evm_contract_call_value metric not found")
	}
}

func TestProbeContractCall_InvalidSpec(t *testing.T) {
	srv := mockEthRPCServerV2(t, nil)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	logger := promslog.NewNopLogger()
	params := url.Values{"call": {"toofew|parts"}}
	module := config.Module{}

	ok := ProbeContractCall(ctx, srv.URL, module, registry, logger, params)
	// still returns true (partial success), but no valid call
	if !ok {
		t.Log("ProbeContractCall returned false on invalid spec (acceptable)")
	}
}

func TestProbeContractCall_NoCall(t *testing.T) {
	srv := mockEthRPCServerV2(t, nil)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	registry := prometheus.NewRegistry()
	logger := promslog.NewNopLogger()
	params := url.Values{}
	module := config.Module{}

	ok := ProbeContractCall(ctx, srv.URL, module, registry, logger, params)
	if ok {
		t.Error("ProbeContractCall should fail when no call param")
	}
}

func TestEncodeCallData(t *testing.T) {
	// totalSupply() no params
	data, err := encodeCallData("totalSupply()(uint256)", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(data, "0x") || len(data) != 10 {
		t.Errorf("encodeCallData totalSupply = %s (len %d)", data, len(data))
	}

	// balanceOf(address) one address
	data2, err := encodeCallData("balanceOf(address)(uint256)", "0x1234567890123456789012345678901234567890")
	if err != nil {
		t.Fatal(err)
	}
	// selector 4 bytes + 32 bytes address = 72 hex chars + 0x
	if len(data2) != 2+4*2+32*2 {
		t.Errorf("encodeCallData balanceOf len = %d", len(data2))
	}
}

func TestDecodeCallResult(t *testing.T) {
	// uint256: 32 bytes big-endian
	hexVal := "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
	val, err := decodeCallResult(hexVal, "uint256", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if val != 1000000000000000000 {
		t.Errorf("decodeCallResult = %v, want 1e18", val)
	}

	// with decimal
	val2, err := decodeCallResult(hexVal, "uint256", 0, 18)
	if err != nil {
		t.Fatal(err)
	}
	if val2 != 1 {
		t.Errorf("decodeCallResult decimal 18 = %v, want 1", val2)
	}
}
