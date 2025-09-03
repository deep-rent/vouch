package middleware

import (
	"log/slog"
	"net/http"
)

func Recover(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			defer func() {
				if v := recover(); v != nil {
					method, path := req.Method, req.URL.Path
					log.Error("panic", "method", method, "path", path, "error", v)
					code := http.StatusInternalServerError
					http.Error(res, http.StatusText(code), code)
				}
			}()
			next.ServeHTTP(res, req)
		})
	}
}
