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
	"net/http"
	"sync"
	"time"
)

const rpcClientTimeout = 60 * time.Second

var (
	rpcClient     *http.Client
	rpcClientOnce sync.Once
)

// getRPCClient returns a shared HTTP client for JSON-RPC probes (jsonrpc, chain_info, balance, etc.).
// It respects http_proxy, https_proxy, and no_proxy environment variables.
func getRPCClient() *http.Client {
	rpcClientOnce.Do(func() {
		transport := &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			DisableKeepAlives:     false,
			ResponseHeaderTimeout: rpcClientTimeout,
		}
		rpcClient = &http.Client{
			Transport: transport,
			Timeout:   rpcClientTimeout,
		}
	})
	return rpcClient
}

// getEthrpcClient returns the same client as getRPCClient (for chain_info, balance, contract_call, etc.).
func getEthrpcClient() *http.Client {
	return getRPCClient()
}
