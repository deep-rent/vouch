// Copyright (c) 2025-present deep.rent GmbH (https://www.deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rules

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Environment provides the input context for rule evaluation.
// It carries request metadata (method, path, database) and the parsed token.
type Environment struct {
	Token jwt.Token
	// Method is the HTTP method of the request.
	Method string
	// Path is the request path (including the leading slash).
	Path string
	// DB is the name of the target CouchDB database.
	DB string
}

// NewEnvironment populates an Environment from a token and request.
// It extracts the HTTP method, raw path, and derives the database name.
func NewEnvironment(tok jwt.Token, req *http.Request) Environment {
	path, method := req.URL.Path, req.Method

	return Environment{
		Token:  tok,
		Method: method,
		Path:   path,
		DB:     Database(path),
	}
}

// Claim returns the value of a JWT claim by name.
// It returns nil when the claim is not set or cannot be decoded.
func (e Environment) Claim(name string) any {
	var v any
	if err := e.Token.Get(name, &v); err != nil {
		return nil
	}
	return v
}

// Database extracts the CouchDB Database name from a URL path.
// It returns the first path segment after the leading slash and performs
// a best-effort percent-decoding of that segment only.
func Database(path string) string {
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
	if strings.IndexByte(first, '%') == -1 {
		return first
	}
	s, err := url.PathUnescape(first)
	if err != nil {
		return first
	}
	return s
}
