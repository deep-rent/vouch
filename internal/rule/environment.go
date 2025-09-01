package rule

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Environment provides the context for evaluating rule expressions.
// It is populated with information from the HTTP request and the access token.
type Environment struct {
	// Method is the HTTP method of the request.
	Method string
	// Path is the request path (including the leading slash).
	Path string
	// DB is the name of the target CouchDB database.
	DB string
}

func NewEnvironment(tok jwt.Token, req *http.Request) Environment {
	path, method := req.URL.Path, req.Method
	return Environment{
		Method: method,
		Path:   path,
		DB:     database(path),
	}
}

// database extracts the name of the CouchDB database from the URL path.
// This is the first segment after the leading slash.
func database(path string) string {
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	segments := strings.SplitN(path, "/", 3)
	if len(segments) < 2 {
		return ""
	}
	first := segments[1]
	s, err := url.PathUnescape(first)
	if err != nil {
		return first
	}
	return s
}
