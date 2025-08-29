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

package auth

import (
	"net/http"
	"net/url"
	"strings"
)

// Environment is the evaluation environment for expressions.
type Environment struct {
	// Claims exposes the claims from the JWT payload.
	Claims map[string]any
	// C is an alias of the `Claims` property.
	C map[string]any
	// Method is the HTTP method of the request.
	Method string
	// Path is the request path.
	Path string
	// DB is the name of the target CouchDB database.
	DB string

	// Utilities
	HasPrefix func(s, prefix string) bool
	HasSuffix func(s, suffix string) bool
}

// NewEnvironment creates an evaluation environment from JWT claims and
// the HTTP request.
func NewEnvironment(claims map[string]any, req *http.Request) Environment {
	path, method := req.URL.Path, req.Method
	return Environment{
		Claims:    claims,
		C:         claims,
		Method:    method,
		Path:      path,
		DB:        database(path),
		HasPrefix: strings.HasPrefix,
		HasSuffix: strings.HasSuffix,
	}
}

// database returns the name of the target database from the URL path.
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
