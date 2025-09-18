package middleware

import (
	"net/http"

	"github.com/deep-rent/vouch/internal/util"
)

func Health(last http.Handler) Pipe {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if util.DB(r.URL.Path) == "_up" {
				last.ServeHTTP(w, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}
