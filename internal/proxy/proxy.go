package proxy

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func New(target string) (http.Handler, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid target: %v", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	chain := proxy.Director
	proxy.Director = func(req *http.Request) {
		chain(req)
		// Preserve original host
		req.Header.Set("X-Forwarded-Host", req.Host)
		// Augment headers with the immediate peer
		if ip, _, err := net.SplitHostPort(req.RemoteAddr); err == nil && ip != "" {
			req.Header.Add("X-Forwarded-For", ip)
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

	return proxy, nil
}
