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

type bufferPool struct{ bufs sync.Pool }

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

func (p *bufferPool) Get() []byte {
	buf := p.bufs.Get().(*[]byte)
	return *buf
}

func (p *bufferPool) Put(buf []byte) {
	if cap(buf) > 256<<10 { // Avoid holding on to very large buffers
		return
	}
	p.bufs.Put(&buf)
}

func transport() *http.Transport {
	dial := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dial.DialContext,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true, // Keep upstream encoding; don't decompress in-proxy
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 01 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

func New(target string) (http.Handler, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	// Tune transport for upstream CouchDB
	proxy.Transport = transport()
	// Helpful for long-lived responses such as the _changes feed
	proxy.FlushInterval = 200 * time.Millisecond
	// Reduce allocations on large responses
	proxy.BufferPool = newBufferPool(32 << 10)

	base := proxy.Director
	proxy.Director = func(req *http.Request) {
		base(req)
		// Strip access tokens from the outgoing request
		req.Header.Del("Authorization")
		// Preserve original host
		req.Header.Set("X-Forwarded-Host", req.Host)
		// Augment headers with the immediate peer
		if ip, _, err := net.SplitHostPort(req.RemoteAddr); err == nil && ip != "" {
			req.Header.Add("X-Forwarded-For", ip)
		}
		// Preserve original scheme
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

	// Map upstream errors to reasonable statuses
	proxy.ErrorHandler = func(
		res http.ResponseWriter,
		req *http.Request,
		err error,
	) {
		var code = http.StatusBadGateway
		if errors.Is(err, context.DeadlineExceeded) {
			code = http.StatusGatewayTimeout
		}
		// If the client canceled, there's nothing useful to send; just close
		if errors.Is(err, context.Canceled) {
			return
		}
		http.Error(res, http.StatusText(code), code)
	}

	return proxy, nil
}
