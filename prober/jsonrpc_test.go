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
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promslog"
)

func TestToFloat64(t *testing.T) {
	tests := []struct {
		name    string
		v       interface{}
		want    float64
		wantErr bool
	}{
		{"float64", float64(42.5), 42.5, false},
		{"int", 100, 100, false},
		{"int64", int64(200), 200, false},
		{"uint64", uint64(300), 300, false},
		{"string number", " 123.45 ", 123.45, false},
		{"string int", "999", 999, false},
		{"string hex 0x", "0x1a", 26, false},
		{"string hex 0X", "0XFF", 255, false},
		{"string hex trimmed", "  0x10  ", 16, false},
		{"json.Number", json.Number("42.0"), 42, false},
		{"nil", nil, 0, true},
		{"string invalid", "abc", 0, true},
		{"unsupported type", []int{1}, 0, true},
		{"bool", true, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toFloat64(tt.v)
			if (err != nil) != tt.wantErr {
				t.Errorf("toFloat64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("toFloat64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestJmesPathValue(t *testing.T) {
	tests := []struct {
		name            string
		result          interface{}
		resultJMESPath  string
		want            float64
		wantErr         bool
	}{
		{"whole result number", float64(100), "", 100, false},
		{"whole result with @", float64(200), "@", 200, false},
		{"jmespath field", map[string]interface{}{"height": float64(12345)}, "height", 12345, false},
		{"jmespath nested", map[string]interface{}{"data": map[string]interface{}{"block": float64(99)}}, "data.block", 99, false},
		{"jmespath array index", []interface{}{float64(10), float64(20)}, "[1]", 20, false},
		{"result nil", nil, "@", 0, true},
		{"jmespath invalid expr", map[string]interface{}{"x": 1}, "[invalid", 0, true},
		{"jmespath no match", map[string]interface{}{"a": 1}, "missing", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jmesPathValue(tt.result, tt.resultJMESPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("jmesPathValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("jmesPathValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNormalizeRPCURLForJsonrpc(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"http://localhost:8545", "http://localhost:8545"},
		{"https://rpc.example.com", "https://rpc.example.com"},
		{"localhost:8545", "http://localhost:8545"},
		{"rpc.example.com", "http://rpc.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := normalizeRPCURLForJsonrpc(tt.in)
			if got != tt.want {
				t.Errorf("normalizeRPCURLForJsonrpc(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// mockJsonrpcServer returns a server that responds to JSON-RPC 2.0 POST with configurable result.
// errCode/errMsg: if errCode != 0, response contains JSON-RPC error.
func mockJsonrpcServer(t *testing.T, result interface{}, errCode int, errMsg string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req jsonrpcGenericReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		res := jsonrpcGenericResp{JSONRPC: "2.0", ID: req.ID}
		if errCode != 0 {
			res.Error = &struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			}{errCode, errMsg}
		} else {
			raw, _ := json.Marshal(result)
			res.Result = raw
		}
		_ = json.NewEncoder(w).Encode(res)
	}))
}

func TestJsonrpcPost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("success", func(t *testing.T) {
		srv := mockJsonrpcServer(t, float64(12345), 0, "")
		defer srv.Close()

		raw, err := jsonrpcPost(ctx, srv.URL, "getblockcount", nil)
		if err != nil {
			t.Fatalf("jsonrpcPost: %v", err)
		}
		var v float64
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		if v != 12345 {
			t.Errorf("result = %v, want 12345", v)
		}
	})

	t.Run("rpc_error", func(t *testing.T) {
		srv := mockJsonrpcServer(t, nil, -32600, "invalid request")
		defer srv.Close()

		_, err := jsonrpcPost(ctx, srv.URL, "any", nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("http_status_not_ok", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		_, err := jsonrpcPost(ctx, srv.URL, "any", nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestProbeJsonrpc(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registry := prometheus.NewPedanticRegistry()
	logger := promslog.New(&promslog.Config{})

	t.Run("missing_method", func(t *testing.T) {
		// Expected to fail; use no-op logger to avoid ERROR spam in test output
		ok := ProbeJsonrpc(ctx, "http://localhost:9999", config.Module{}, registry, slog.New(slog.DiscardHandler), url.Values{})
		if ok {
			t.Error("expected false when method is missing")
		}
	})

	t.Run("single_call_value", func(t *testing.T) {
		srv := mockJsonrpcServer(t, map[string]interface{}{"height": float64(250000)}, 0, "")
		defer srv.Close()

		params := url.Values{
			"method":         {"getblockcount"},
			"rpcParams":      {"[]"},
			"resultJMESPath": {"height"},
		}
		ok := ProbeJsonrpc(ctx, srv.URL, config.Module{}, registry, logger, params)
		if !ok {
			t.Fatal("ProbeJsonrpc failed")
		}
		mfs, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		var val float64
		for _, mf := range mfs {
			if mf.GetName() == "jsonrpc_value" && len(mf.Metric) > 0 {
				val = mf.Metric[0].GetGauge().GetValue()
				break
			}
		}
		if val != 250000 {
			t.Errorf("jsonrpc_value = %v, want 250000", val)
		}
	})

	t.Run("decimal_scale", func(t *testing.T) {
		srv := mockJsonrpcServer(t, "1234567890", 0, "") // string to test decimal scaling
		defer srv.Close()

		reg := prometheus.NewPedanticRegistry()
		params := url.Values{
			"method":         {"getbalance"},
			"rpcParams":      {"[]"},
			"resultJMESPath": {"@"},
			"decimal":        {"6"},
		}
		ok := ProbeJsonrpc(ctx, srv.URL, config.Module{}, reg, logger, params)
		if !ok {
			t.Fatal("ProbeJsonrpc failed")
		}
		mfs, _ := reg.Gather()
		for _, mf := range mfs {
			if mf.GetName() == "jsonrpc_value" && len(mf.Metric) > 0 {
				val := mf.Metric[0].GetGauge().GetValue()
				// 1234567890 / 10^6 = 1234.56789
				if val < 1234.5 || val > 1234.6 {
					t.Errorf("jsonrpc_value (scaled) = %v, want ~1234.56789", val)
				}
				return
			}
		}
		t.Fatal("jsonrpc_value metric not found")
	})

	t.Run("target_without_scheme", func(t *testing.T) {
		srv := mockJsonrpcServer(t, float64(42), 0, "")
		defer srv.Close()
		// Use host:port style target; probe should prepend http://
		u, _ := url.Parse(srv.URL)
		target := u.Host

		reg := prometheus.NewPedanticRegistry()
		params := url.Values{
			"method":         {"getblockcount"},
			"rpcParams":      {"[]"},
			"resultJMESPath": {"@"},
		}
		ok := ProbeJsonrpc(ctx, target, config.Module{}, reg, logger, params)
		if !ok {
			t.Fatal("ProbeJsonrpc failed")
		}
		mfs, _ := reg.Gather()
		for _, mf := range mfs {
			if mf.GetName() == "jsonrpc_value" && len(mf.Metric) > 0 {
				for _, l := range mf.Metric[0].Label {
					if l.GetName() == "url" && l.GetValue() != "http://"+target && l.GetValue() != srv.URL {
						t.Errorf("url label = %q, expected http://%s or %s", l.GetValue(), target, srv.URL)
					}
				}
				return
			}
		}
	})

	t.Run("labels_present", func(t *testing.T) {
		srv := mockJsonrpcServer(t, float64(1), 0, "")
		defer srv.Close()

		reg := prometheus.NewPedanticRegistry()
		params := url.Values{
			"method":         {"getblockcount"},
			"rpcParams":      {"[]"},
			"resultJMESPath": {"@"},
		}
		ok := ProbeJsonrpc(ctx, srv.URL, config.Module{}, reg, logger, params)
		if !ok {
			t.Fatal("ProbeJsonrpc failed")
		}
		mfs, _ := reg.Gather()
		for _, mf := range mfs {
			if mf.GetName() != "jsonrpc_value" || len(mf.Metric) == 0 {
				continue
			}
			labels := make(map[string]string)
			for _, l := range mf.Metric[0].Label {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["method"] != "getblockcount" {
				t.Errorf("label method = %q, want getblockcount", labels["method"])
			}
			if labels["result_jmespath"] != "@" {
				t.Errorf("label result_jmespath = %q, want @", labels["result_jmespath"])
			}
			return
		}
		t.Fatal("jsonrpc_value not found")
	})
}

func TestProbeJsonrpc_MultipleCalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	logger := promslog.New(&promslog.Config{})

	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req jsonrpcGenericReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		callCount++
		var res interface{} = float64(100)
		if callCount == 2 {
			res = float64(200)
		}
		raw, _ := json.Marshal(res)
		_ = json.NewEncoder(w).Encode(jsonrpcGenericResp{JSONRPC: "2.0", ID: req.ID, Result: raw})
	}))
	defer srv.Close()

	registry := prometheus.NewPedanticRegistry()
	// Use different methods to produce different labels, yielding 2 jsonrpc_value time series
	params := url.Values{
		"method":         {"getblockcount", "getblockheight"},
		"rpcParams":      {"[]", "[]"},
		"resultJMESPath": {"@", "@"},
	}
	ok := ProbeJsonrpc(ctx, srv.URL, config.Module{}, registry, logger, params)
	if !ok {
		t.Fatal("ProbeJsonrpc failed")
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var values []float64
	for _, mf := range mfs {
		if mf.GetName() == "jsonrpc_value" {
			for _, m := range mf.Metric {
				values = append(values, m.GetGauge().GetValue())
			}
		}
	}
	if len(values) != 2 {
		t.Fatalf("expected 2 jsonrpc_value metrics, got %d", len(values))
	}
	// Order not guaranteed; just ensure both 100 and 200 are present
	has100, has200 := false, false
	for _, v := range values {
		if v == 100 {
			has100 = true
		}
		if v == 200 {
			has200 = true
		}
	}
	if !has100 || !has200 {
		t.Errorf("values = %v, want 100 and 200", values)
	}
}

