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
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

func normalizeURLForHttpJson(target string) string {
	if target == "" {
		return target
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "https://" + target
	}
	return target
}

// ProbeHttpJson GETs the target URL (Accept: application/json), parses the response as JSON,
// extracts a numeric value via resultJMESPath, and exports it as http_json_value.
// Params: resultJMESPath (required), decimal (optional, default 0).
// Example: monitor Eth beacon API slot — target=https://beacon-api/eth/v1/node/syncing, resultJMESPath=data.head_slot
func ProbeHttpJson(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger, params url.Values) bool {
	_ = module
	u := normalizeURLForHttpJson(target)

	resultJMESPath := strings.TrimSpace(params.Get("resultJMESPath"))
	if resultJMESPath == "" {
		resultJMESPath = "@"
	}
	decimal := 0
	if d := strings.TrimSpace(params.Get("decimal")); d != "" {
		decimal, _ = strconv.Atoi(d)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		logger.Error("http_json: new request failed", "url", u, "err", err)
		return false
	}
	req.Header.Set("Accept", "application/json")

	client := getRPCClient()
	resp, err := client.Do(req)
	if err != nil {
		logger.Error("http_json: GET failed", "url", u, "err", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Error("http_json: non-200 status", "url", u, "status", resp.StatusCode)
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("http_json: read body failed", "url", u, "err", err)
		return false
	}

	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		logger.Error("http_json: JSON unmarshal failed", "url", u, "err", err)
		return false
	}

	// jmesPathValue -> toFloat64：0x 开头按十六进制转十进制，否则按十进制
	val, err := jmesPathValue(result, resultJMESPath)
	if err != nil {
		logger.Error("http_json: JMESPath or convert failed", "url", u, "resultJMESPath", resultJMESPath, "err", err)
		return false
	}
	if decimal > 0 {
		val = val / math.Pow(10, float64(decimal))
	}
	if math.IsInf(val, 0) || math.IsNaN(val) {
		logger.Error("http_json: value overflow or NaN", "url", u, "val", val)
		return false
	}

	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "http_json_value",
		Help: "Value extracted from JSON HTTP GET response via JMESPath",
	}, []string{"url", "result_jmespath"})
	registry.MustRegister(gauge)
	gauge.WithLabelValues(u, resultJMESPath).Set(val)
	return true
}
