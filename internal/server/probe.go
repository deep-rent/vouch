// Copyright (c) 2025-present deep.rent GmbH (https://www.deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// probe encapsulates upstream health checking and the /ready handler.
type probe struct {
	url string       // upstream health endpoint (target + "/_up")
	cli *http.Client // small client for readiness checks
}

// newProbe constructs a probe for the given CouchDB API URL (upstream target).
func newProbe(target *url.URL) *probe {
	return &probe{
		url: target.JoinPath("_up").String(),
		cli: &http.Client{Timeout: 2 * time.Second},
	}
}

// ping probes the upstream health endpoint and expects 200 OK.
func (p *probe) ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return err
	}
	res, err := p.cli.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("health check returned %d", res.StatusCode)
}

// ready is a readiness probe that checks upstream availability.
func (p *probe) ready(res http.ResponseWriter, req *http.Request) {
	// The ping call will be canceled by the client's timeout or if the
	// incoming request's context is canceled.
	if err := p.ping(req.Context()); err != nil {
		http.Error(res, "not ready", http.StatusServiceUnavailable)
		return
	}
	res.WriteHeader(http.StatusOK)
	_, _ = res.Write([]byte("ready"))
}

// healthy is a simple liveness probe handler.
func (p *probe) healthy(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
	_, _ = res.Write([]byte("healthy"))
}
