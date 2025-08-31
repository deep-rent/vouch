package middleware

import "net/http"

func auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodOptions {
			next.ServeHTTP(res, req)
			return
		}
		next.ServeHTTP(res, req)
	})
}
