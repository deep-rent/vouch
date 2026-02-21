package gateway

import (
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/deep-rent/nexus/middleware"
	"github.com/deep-rent/nexus/proxy"
	"github.com/deep-rent/vouch/internal/bouncer"
	"github.com/deep-rent/vouch/internal/stamper"
)

type Config struct {
	Bouncer         *bouncer.Config
	Stamper         *stamper.Config
	URL             *url.URL
	FlushInterval   time.Duration
	MinBufferSize   int
	MaxBufferSize   int
	MaxIdleConns    int
	IdleConnTimeout time.Duration
	Logger          *slog.Logger
}

type Gateway struct {
	bouncer *bouncer.Bouncer
	stamper *stamper.Stamper
	backend http.Handler
}

func New(cfg *Config) http.Handler {
	handler := proxy.NewHandler(
		cfg.URL,
		// For long polling, such as CouchDB's _changes feed, we want to flush as
		// soon as possible (set to -1 to disable buffering entirely). Otherwise,
		// buffering will delay heartbeats (newlines) or event chunks, causing
		// client timeouts.
		proxy.WithFlushInterval(cfg.FlushInterval),
		// Optimize the request buffer to avoid garbage collection pressure under
		// heavy load.
		proxy.WithMinBufferSize(cfg.MinBufferSize),
		proxy.WithMaxBufferSize(cfg.MaxBufferSize),
		proxy.WithTransport(&http.Transport{
			// For a sidecar, this should match or exceed the expected peak of
			// concurrent requests.
			MaxIdleConns: cfg.MaxIdleConns,
			// Since we are only proxying to one host, this is equal to MaxIdleConns.
			MaxIdleConnsPerHost: cfg.MaxIdleConns,
			// We wish to reuse connections as much as possible, but we also need to
			// eventually prune that CouchDB might have silently dropped.
			IdleConnTimeout:    cfg.IdleConnTimeout,
			DisableCompression: true,
			// CouchDB doesn't support HTTP/2.
			ForceAttemptHTTP2: false,
		}),
		proxy.WithLogger(cfg.Logger),
	)
	handler = middleware.Chain(
		handler,
		middleware.Recover(cfg.Logger),
	)
	return &Gateway{
		bouncer: bouncer.New(cfg.Bouncer),
		stamper: stamper.New(cfg.Stamper),
		backend: handler,
	}
}

func (h *Gateway) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	pass, err := h.bouncer.Bounce(req)
	if err != nil {
		res.WriteHeader(http.StatusUnauthorized)
		return
	}
	h.stamper.Stamp(req, pass)
	h.backend.ServeHTTP(res, req)
}
