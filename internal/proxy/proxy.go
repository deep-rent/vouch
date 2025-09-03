package proxy

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

type byteBufferPool struct {
	pool sync.Pool
}

func newByteBufferPool(size int) *byteBufferPool {
	return &byteBufferPool{
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, size)
				return &b
			},
		},
	}
}

func (p *byteBufferPool) Get() []byte {
	b := p.pool.Get().(*[]byte)
	return *b
}

func (p *byteBufferPool) Put(b []byte) {
	if cap(b) > 256<<10 { // Avoid holding on to very large buffers
		return
	}
	p.pool.Put(&b)
}

func transport() *http.Transport {
	dial := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dial.DialContext,
		ForceAttemptHTTP2:     true,
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
	// Reduce allocations on large responses
	proxy.BufferPool = newByteBufferPool(32 << 10)

	chain := proxy.Director
	proxy.Director = func(req *http.Request) {
		chain(req)
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

	proxy.ErrorHandler = func(
		res http.ResponseWriter,
		req *http.Request,
		err error,
	) {
		msg := "Error forwarding request to upstream service"

		slog.Error(msg, "error", err)
		http.Error(res, msg, http.StatusBadGateway)
	}

	proxy.Transport = &http.Transport{
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 128,
		IdleConnTimeout:     120 * time.Second,
		ForceAttemptHTTP2:   true,
	}

	return proxy, nil
}
