package guard

import (
	"net/http"
	"time"

	"github.com/deep-rent/nexus/middleware"
	"github.com/deep-rent/nexus/proxy"
	"github.com/deep-rent/vouch/internal/bouncer"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/stamper"
)

type Guard struct {
	bouncer *bouncer.Bouncer
	stamper *stamper.Stamper
	handler http.Handler
}

func New(cfg *config.Config) *Guard {
	handler := proxy.NewHandler(
		cfg.URL,
		proxy.WithFlushInterval(200*time.Millisecond),
		// proxy.WithMinBufferSize(1),
		// proxy.WithMaxBufferSize(256),
		proxy.WithLogger(cfg.Logger),
	)
	handler = middleware.Chain(
		handler,
		middleware.Recover(cfg.Logger),
	)
	return &Guard{
		bouncer: bouncer.New(cfg),
		stamper: stamper.New(cfg),
		handler: handler,
	}
}

func (g *Guard) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	pass, err := g.bouncer.Bounce(req)
	if err != nil {
		res.WriteHeader(http.StatusUnauthorized)
		return
	}
	g.stamper.Stamp(req, pass)
	g.handler.ServeHTTP(res, req)
}
