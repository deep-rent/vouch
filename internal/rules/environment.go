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

// Environment provides the context for evaluating rule expressions.
// It is populated with information from the HTTP request and the access token.
type Environment struct {
	tok jwt.Token
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
		tok:    tok,
		Method: method,
		Path:   path,
		DB:     database(path),
	}
}

// Claim extracts the value of a JWT claim by name.
func (e Environment) Claim(name string) any {
	var v any
	if err := e.tok.Get(name, &v); err != nil {
		return nil
	}
	return v
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
	if strings.IndexByte(first, '%') == -1 {
		return first
	}
	s, err := url.PathUnescape(first)
	if err != nil {
		return first
	}
	return s
}
