package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/deep-rent/vouch/internal/middleware"
)

type Server struct {
	mux *http.ServeMux
	srv *http.Server
}

func New(h http.Handler, mws ...middleware.Middleware) *Server {
	s := &Server{
		mux: http.NewServeMux(),
	}
	s.routes(h)
	return s
}

func (s *Server) routes(h http.Handler, mws ...middleware.Middleware) {
	// Unprotected health endpoint (readiness/liveness)
	s.mux.HandleFunc("/healthz", health)

	// Pass CORS preflight straight through to CouchDB (no auth)
	s.mux.Handle("OPTIONS /{path...}", h)

	// Everything else goes through the middleware chain and to CouchDB
	s.mux.Handle("/", middleware.Chain(h, mws...))
}

func (s *Server) Start(addr string) error {
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64 KB
	}

	err := s.srv.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

func health(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
	_, _ = res.Write([]byte("ok"))
}
