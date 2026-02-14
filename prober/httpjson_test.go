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
	"io"
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

func TestNormalizeURLForHttpJson(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"http://localhost:8080", "http://localhost:8080"},
		{"https://api.example.com/data", "https://api.example.com/data"},
		{"api.example.com/path", "https://api.example.com/path"},
		{"localhost:8080", "https://localhost:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := normalizeURLForHttpJson(tt.in)
			if got != tt.want {
				t.Errorf("normalizeURLForHttpJson(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// mockHttpJsonServer returns a server that responds to GET with JSON body.
func mockHttpJsonServer(t *testing.T, body interface{}) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
}

func TestProbeHttpJson(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registry := prometheus.NewPedanticRegistry()
	logger := promslog.New(&promslog.Config{})

	t.Run("success_whole_result", func(t *testing.T) {
		srv := mockHttpJsonServer(t, map[string]interface{}{"value": float64(42)})
		defer srv.Close()

		params := url.Values{
			"resultJMESPath": {"value"},
		}
		ok := ProbeHttpJson(ctx, srv.URL, config.Module{}, registry, logger, params)
		if !ok {
			t.Fatal("ProbeHttpJson failed")
		}
		mfs, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		var val float64
		for _, mf := range mfs {
			if mf.GetName() == "http_json_value" && len(mf.Metric) > 0 {
				val = mf.Metric[0].GetGauge().GetValue()
				break
			}
		}
		if val != 42 {
			t.Errorf("http_json_value = %v, want 42", val)
		}
	})

	t.Run("success_jmespath_nested", func(t *testing.T) {
		srv := mockHttpJsonServer(t, map[string]interface{}{
			"data": map[string]interface{}{"head_slot": "12345"},
		})
		defer srv.Close()

		reg := prometheus.NewPedanticRegistry()
		params := url.Values{
			"resultJMESPath": {"data.head_slot"},
		}
		ok := ProbeHttpJson(ctx, srv.URL, config.Module{}, reg, logger, params)
		if !ok {
			t.Fatal("ProbeHttpJson failed")
		}
		mfs, _ := reg.Gather()
		for _, mf := range mfs {
			if mf.GetName() == "http_json_value" && len(mf.Metric) > 0 {
				if v := mf.Metric[0].GetGauge().GetValue(); v != 12345 {
					t.Errorf("http_json_value = %v, want 12345", v)
				}
				return
			}
		}
		t.Fatal("http_json_value metric not found")
	})

	t.Run("success_hex_value", func(t *testing.T) {
		srv := mockHttpJsonServer(t, map[string]interface{}{"block": "0x1a2b"})
		defer srv.Close()

		reg := prometheus.NewPedanticRegistry()
		params := url.Values{
			"resultJMESPath": {"block"},
		}
		ok := ProbeHttpJson(ctx, srv.URL, config.Module{}, reg, logger, params)
		if !ok {
			t.Fatal("ProbeHttpJson failed")
		}
		mfs, _ := reg.Gather()
		for _, mf := range mfs {
			if mf.GetName() == "http_json_value" && len(mf.Metric) > 0 {
				// 0x1a2b = 6699
				if v := mf.Metric[0].GetGauge().GetValue(); v != 6699 {
					t.Errorf("http_json_value = %v, want 6699 (0x1a2b)", v)
				}
				return
			}
		}
		t.Fatal("http_json_value metric not found")
	})

	t.Run("default_resultJMESPath", func(t *testing.T) {
		srv := mockHttpJsonServer(t, float64(100))
		defer srv.Close()

		reg := prometheus.NewPedanticRegistry()
		params := url.Values{} // no resultJMESPath -> default "@"
		ok := ProbeHttpJson(ctx, srv.URL, config.Module{}, reg, logger, params)
		if !ok {
			t.Fatal("ProbeHttpJson failed")
		}
		mfs, _ := reg.Gather()
		for _, mf := range mfs {
			if mf.GetName() == "http_json_value" && len(mf.Metric) > 0 {
				if v := mf.Metric[0].GetGauge().GetValue(); v != 100 {
					t.Errorf("http_json_value = %v, want 100", v)
				}
				return
			}
		}
		t.Fatal("http_json_value metric not found")
	})

	t.Run("decimal_scale", func(t *testing.T) {
		srv := mockHttpJsonServer(t, "1234567890")
		defer srv.Close()

		reg := prometheus.NewPedanticRegistry()
		params := url.Values{
			"resultJMESPath": {"@"},
			"decimal":        {"6"},
		}
		ok := ProbeHttpJson(ctx, srv.URL, config.Module{}, reg, logger, params)
		if !ok {
			t.Fatal("ProbeHttpJson failed")
		}
		mfs, _ := reg.Gather()
		for _, mf := range mfs {
			if mf.GetName() == "http_json_value" && len(mf.Metric) > 0 {
				v := mf.Metric[0].GetGauge().GetValue()
				if v < 1234.5 || v > 1234.6 {
					t.Errorf("http_json_value (scaled) = %v, want ~1234.56789", v)
				}
				return
			}
		}
		t.Fatal("http_json_value metric not found")
	})

	t.Run("url_label", func(t *testing.T) {
		srv := mockHttpJsonServer(t, float64(1))
		defer srv.Close()

		reg := prometheus.NewPedanticRegistry()
		params := url.Values{"resultJMESPath": {"@"}}
		ok := ProbeHttpJson(ctx, srv.URL, config.Module{}, reg, logger, params)
		if !ok {
			t.Fatal("ProbeHttpJson failed")
		}
		mfs, _ := reg.Gather()
		for _, mf := range mfs {
			if mf.GetName() == "http_json_value" && len(mf.Metric) > 0 {
				for _, l := range mf.Metric[0].Label {
					if l.GetName() == "url" && l.GetValue() != srv.URL {
						t.Errorf("url label = %q, want %q", l.GetValue(), srv.URL)
					}
				}
				return
			}
		}
		t.Fatal("http_json_value not found")
	})

	t.Run("labels_present", func(t *testing.T) {
		srv := mockHttpJsonServer(t, map[string]interface{}{"x": float64(1)})
		defer srv.Close()

		reg := prometheus.NewPedanticRegistry()
		params := url.Values{"resultJMESPath": {"x"}}
		ok := ProbeHttpJson(ctx, srv.URL, config.Module{}, reg, logger, params)
		if !ok {
			t.Fatal("ProbeHttpJson failed")
		}
		mfs, _ := reg.Gather()
		for _, mf := range mfs {
			if mf.GetName() != "http_json_value" || len(mf.Metric) == 0 {
				continue
			}
			labels := make(map[string]string)
			for _, l := range mf.Metric[0].Label {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["result_jmespath"] != "x" {
				t.Errorf("result_jmespath label = %q, want x", labels["result_jmespath"])
			}
			return
		}
		t.Fatal("http_json_value not found")
	})

	// 预期失败的用例使用 no-op logger，避免测试输出中刷 ERROR
	nopLogger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("non_200_status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		reg := prometheus.NewPedanticRegistry()
		params := url.Values{"resultJMESPath": {"@"}}
		ok := ProbeHttpJson(ctx, srv.URL, config.Module{}, reg, nopLogger, params)
		if ok {
			t.Error("expected ProbeHttpJson to fail on 500")
		}
	})

	t.Run("invalid_json", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not json"))
		}))
		defer srv.Close()

		reg := prometheus.NewPedanticRegistry()
		params := url.Values{"resultJMESPath": {"@"}}
		ok := ProbeHttpJson(ctx, srv.URL, config.Module{}, reg, nopLogger, params)
		if ok {
			t.Error("expected ProbeHttpJson to fail on invalid JSON")
		}
	})

	t.Run("jmespath_no_match", func(t *testing.T) {
		srv := mockHttpJsonServer(t, map[string]interface{}{"a": 1})
		defer srv.Close()

		reg := prometheus.NewPedanticRegistry()
		params := url.Values{"resultJMESPath": {"missing"}}
		ok := ProbeHttpJson(ctx, srv.URL, config.Module{}, reg, nopLogger, params)
		if ok {
			t.Error("expected ProbeHttpJson to fail when JMESPath has no match")
		}
	})
}
