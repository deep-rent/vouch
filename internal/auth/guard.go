package auth

import (
	"net/http"
)

type Guard interface {
	Handle(w http.ResponseWriter, r *http.Request) error
}

func NewGuard(bouncer Bouncer, stamper Stamper) Guard {
	return &guard{
		bouncer: bouncer,
		stamper: stamper,
	}
}

type guard struct {
	bouncer Bouncer
	stamper Stamper
}

func (g *guard) Handle(w http.ResponseWriter, r *http.Request) error {
	// Check the incoming request.
	access, err := g.bouncer.Check(r)
	if err != nil {
		w.WriteHeader(err.StatusCode)
		return err
	}
	// Forward the proxy authentication headers to CouchDB.
	g.stamper.Stamp(r, access)
	return nil
}
