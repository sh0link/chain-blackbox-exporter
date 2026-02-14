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
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jmespath/go-jmespath"
	"github.com/prometheus/blackbox_exporter/config"
	"github.com/prometheus/client_golang/prometheus"
)

// jsonrpcGenericReq is a generic JSON-RPC 2.0 request (params can be array or object).
type jsonrpcGenericReq struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	ID      int         `json:"id"`
}

// jsonrpcGenericResp is a generic JSON-RPC 2.0 response.
type jsonrpcGenericResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// jsonrpcPost performs a single JSON-RPC POST and returns the raw result.
func jsonrpcPost(ctx context.Context, rpcURL string, method string, params interface{}) (json.RawMessage, error) {
	body, err := json.Marshal(&jsonrpcGenericReq{JSONRPC: "2.0", Method: method, Params: params, ID: 1})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", rpcURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := getRPCClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rpc status %d", resp.StatusCode)
	}

	var out jsonrpcGenericResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", out.Error.Code, out.Error.Message)
	}
	return out.Result, nil
}

// jmesPathValue applies resultJMESPath to result (unmarshaled from response.result) and returns a float64 for the metric.
// resultJMESPath: "" or "@" means use the whole result (must be number or numeric string).
func jmesPathValue(result interface{}, resultJMESPath string) (float64, error) {
	if resultJMESPath != "" && resultJMESPath != "@" {
		search, err := jmespath.Compile(resultJMESPath)
		if err != nil {
			return 0, fmt.Errorf("jmespath compile: %w", err)
		}
		result, err = search.Search(result)
		if err != nil {
			return 0, fmt.Errorf("jmespath search: %w", err)
		}
	}
	return toFloat64(result)
}

func toFloat64(v interface{}) (float64, error) {
	if v == nil {
		return 0, fmt.Errorf("result is nil")
	}
	switch x := v.(type) {
	case float64:
		return x, nil
	case int:
		return float64(x), nil
	case int64:
		return float64(x), nil
	case uint64:
		return float64(x), nil
	case string:
		s := strings.TrimSpace(x)
		// 0x-prefixed: parse as hex to decimal; otherwise parse as decimal
		if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
			u, err := strconv.ParseUint(s[2:], 16, 64)
			if err != nil {
				return 0, fmt.Errorf("cannot parse hex string as number: %w", err)
			}
			return float64(u), nil
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot parse string as number: %w", err)
		}
		return f, nil
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return 0, err
		}
		return f, nil
	default:
		return 0, fmt.Errorf("unsupported result type %T for metric value", v)
	}
}

func normalizeRPCURLForJsonrpc(target string) string {
	if target == "" {
		return target
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return "http://" + target
	}
	return target
}

// ProbeJsonrpc runs generic JSON-RPC calls and exports the JMESPath-extracted value as a gauge.
// Params: method (required), rpcParams (required, JSON string), resultJMESPath (required, applied to response.result), decimal (optional, default 0).
// For multiple calls, pass arrays: method[], rpcParams[], resultJMESPath[], decimal[] (same length).
func ProbeJsonrpc(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, logger *slog.Logger, params url.Values) bool {
	_ = module
	rpcURL := normalizeRPCURLForJsonrpc(target)

	methods := params["method"]
	if len(methods) == 0 {
		logger.Error("jsonrpc: param method required")
		return false
	}
	rpcParamsList := params["rpcParams"]
	resultJMESPaths := params["resultJMESPath"]
	decimals := params["decimal"]

	if len(rpcParamsList) < len(methods) {
		// pad with empty params
		for len(rpcParamsList) < len(methods) {
			rpcParamsList = append(rpcParamsList, "[]")
		}
	}
	if len(resultJMESPaths) < len(methods) {
		for len(resultJMESPaths) < len(methods) {
			resultJMESPaths = append(resultJMESPaths, "@")
		}
	}
	if len(decimals) < len(methods) {
		for len(decimals) < len(methods) {
			decimals = append(decimals, "0")
		}
	}

	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "jsonrpc_value",
		Help: "Generic JSON-RPC call result value (JMESPath on response.result, scaled by decimal)",
	}, []string{"url", "method", "result_jmespath"})
	registry.MustRegister(gauge)

	for i := 0; i < len(methods); i++ {
		method := strings.TrimSpace(methods[i])
		if method == "" {
			continue
		}
		paramsStr := strings.TrimSpace(rpcParamsList[i])
		if paramsStr == "" {
			paramsStr = "[]"
		}
		var rpcParams interface{}
		if err := json.Unmarshal([]byte(paramsStr), &rpcParams); err != nil {
			logger.Error("jsonrpc: invalid rpcParams", "method", method, "err", err)
			continue
		}
		resultJMESPath := strings.TrimSpace(resultJMESPaths[i])
		if resultJMESPath == "" {
			resultJMESPath = "@"
		}
		decimal := 0
		if i < len(decimals) {
			decimal, _ = strconv.Atoi(strings.TrimSpace(decimals[i]))
		}

		rawResult, err := jsonrpcPost(ctx, rpcURL, method, rpcParams)
		if err != nil {
			logger.Error("jsonrpc: call failed", "method", method, "url", rpcURL, "err", err)
			continue
		}
		var result interface{}
		if err := json.Unmarshal(rawResult, &result); err != nil {
			logger.Error("jsonrpc: result unmarshal failed", "method", method, "err", err)
			continue
		}
		val, err := jmesPathValue(result, resultJMESPath)
		if err != nil {
			logger.Error("jsonrpc: jmespath or convert failed", "method", method, "resultJMESPath", resultJMESPath, "err", err)
			continue
		}
		if decimal > 0 {
			val = val / math.Pow(10, float64(decimal))
		}
		// avoid overflow: Prometheus float64
		if math.IsInf(val, 0) || math.IsNaN(val) {
			logger.Error("jsonrpc: value overflow or NaN", "method", method, "val", val)
			continue
		}
		gauge.WithLabelValues(rpcURL, method, resultJMESPath).Set(val)
	}
	return true
}
