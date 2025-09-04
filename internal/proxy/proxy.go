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

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

// bufferPool implements httputil.BufferPool backed by sync.Pool.
// It reduces allocations for large response bodies by reusing byte slices.
type bufferPool struct{ bufs sync.Pool }

// newBufferPool creates a buffer pool that returns buffers of at least size
// bytes. Buffers larger than 256 KiB are not kept to avoid memory bloat.
func newBufferPool(size int) *bufferPool {
	return &bufferPool{
		bufs: sync.Pool{
			New: func() any {
				buf := make([]byte, size)
				return &buf
			},
		},
	}
}

// Get returns a reusable buffer slice.
func (p *bufferPool) Get() []byte {
	buf := p.bufs.Get().(*[]byte)
	return *buf
}

// Put returns the buffer to the pool unless it grew beyond 256 KiB.
func (p *bufferPool) Put(buf []byte) {
	if cap(buf) <= 256<<10 { // Avoid holding on to very large buffers
		p.bufs.Put(&buf)
	}
}

// Ensure bufferPool satisfies the interface expected by ReverseProxy.
var _ httputil.BufferPool = (*bufferPool)(nil)

// transport returns an HTTP transport tuned for CouchDB upstreams.
// - Enables HTTP/2 where possible
// - Disables transparent decompression to preserve upstream encoding
// - Sets conservative timeouts and generous connection pooling
func transport() *http.Transport {
	dial := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dial.DialContext,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true, // Keep upstream encoding; don't decompress in-proxy
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 01 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

// New constructs a reverse proxy handler that forwards requests to the target
// address. It applies sane defaults for CouchDB, strips sensitive headers, and
// enriches forwarding headers (X-Forwarded-*). Upstream errors are mapped to
// 502/504 as appropriate; client cancellations are silently ignored.
func New(target string) (http.Handler, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	// Tune transport for upstream CouchDB.
	proxy.Transport = transport()
	// Helpful for long-lived responses such as the _changes feed.
	proxy.FlushInterval = 200 * time.Millisecond
	// Reduce allocations on large responses.
	proxy.BufferPool = newBufferPool(32 << 10)

	// Preserve and augment request details for the upstream.
	base := proxy.Director
	proxy.Director = func(req *http.Request) {
		base(req)
		// Strip access tokens from the outgoing request.
		req.Header.Del("Authorization")
		// Preserve original host
		req.Header.Set("X-Forwarded-Host", req.Host)
		// Augment headers with the immediate peer.
		if ip, _, err := net.SplitHostPort(req.RemoteAddr); err == nil && ip != "" {
			req.Header.Add("X-Forwarded-For", ip)
		}
		// Preserve original scheme  if not already set by upstream infrastructure.
		if req.Header.Get("X-Forwarded-Proto") == "" {
			var scheme string
			if req.TLS != nil {
				scheme = "https"
			} else {
				scheme = "http"
			}
			req.Header.Set("X-Forwarded-Proto", scheme)
		}
	}

	// Map upstream errors to reasonable statuses.
	proxy.ErrorHandler = func(
		res http.ResponseWriter,
		req *http.Request,
		err error,
	) {
		var code = http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) {
			code = http.StatusGatewayTimeout
		}
		// If the client canceled, there's nothing useful to send; just close.
		if errors.Is(err, context.Canceled) {
			return
		}
		http.Error(res, http.StatusText(code), code)
	}

	return proxy, nil
}
