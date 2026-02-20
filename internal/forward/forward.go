package forward

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/config"
)

const (
	// CouchDBUserNameHeader is the header used to proxy the username to CouchDB.
	CouchDBUserNameHeader = "X-Auth-CouchDB-UserName"
	// CouchDBRolesHeader is the header used to proxy the roles to CouchDB.
	CouchDBRolesHeader = "X-Auth-CouchDB-Roles"
)

// Proxy is the main HTTP handler for the vouch proxy.
type Proxy struct {
	authenticator *auth.Authenticator
	config        *config.Config
	proxy         *httputil.ReverseProxy
	logger        *slog.Logger
}

// New creates a new Proxy handler.
func New(authenticator *auth.Authenticator, config *config.Config, logger *slog.Logger) *Proxy {
	proxy := httputil.NewSingleHostReverseProxy(config.CouchDBURL)
	return &Proxy{
		authenticator: authenticator,
		config:        config,
		proxy:         proxy,
		logger:        logger,
	}
}

// ServeHTTP handles incoming HTTP requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authenticate the request.
	claims, err := p.authenticator.Authenticate(r)
	if err != nil {
		p.logger.Info("Authentication failed", "error", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Add the username header.
	r.Header.Set(CouchDBUserNameHeader, claims.Subject())

	// Add the roles header.
	if roles, ok := jwt.Get[[]string](&claims.DynamicClaims, p.config.RolesClaim); ok {
		r.Header.Set(CouchDBRolesHeader, strings.Join(roles, ","))
	} else {
		p.logger.Debug("Roles claim not found or not in expected format", "claim", p.config.RolesClaim)
	}

	// Remove the original Authorization header to avoid it being passed to CouchDB.
	r.Header.Del("Authorization")

	// Forward the request to CouchDB.
	p.proxy.ServeHTTP(w, r)
}

// errorf writes a JSON error message to the response.
func (p *Proxy) errorf(w http.ResponseWriter, code int, format string, a ...interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	response := map[string]string{"error": "vouch_proxy", "reason": fmt.Sprintf(format, a...)}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		p.logger.Error("Failed to encode error response", "error", err)
	}
}
