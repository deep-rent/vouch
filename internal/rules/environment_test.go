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

package rules_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEnvironment(t *testing.T) {
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/my-db/some_doc"},
	}
	tok := jwt.New()

	env := NewEnvironment(tok, req)

	assert.Equal(t, http.MethodPost, env.Method, "should set the method")
	assert.Equal(t, "/my-db/some_doc", env.Path, "should set the path")
	assert.Equal(t, "my-db", env.DB, "should extract the database name")
	assert.Same(t, tok, env.tok, "should set the token")
}

func TestEnvironmentClaim(t *testing.T) {
	tok := jwt.New()
	require.NoError(t, tok.Set("sub", "alice"))
	require.NoError(t, tok.Set("rol", []string{"admin", "editor"}))

	tests := []struct {
		// inputs
		name  string
		env   Environment
		claim string
		// expected outputs
		want any
	}{
		{
			name:  "existing string claim",
			env:   Environment{tok: tok},
			claim: "sub",
			want:  "alice",
		},
		{
			name:  "existing slice claim",
			env:   Environment{tok: tok},
			claim: "rol",
			want:  []string{"admin", "editor"},
		},
		{
			name:  "non-existent claim",
			env:   Environment{tok: tok},
			claim: "iss",
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.env.Claim(tc.claim)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDatabase(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{path: "", want: ""},
		{path: "/", want: ""},
		{path: "/mydb", want: "mydb"},
		{path: "/mydb/doc1", want: "mydb"},
		{path: "/_users/org.couchdb.user:alice", want: "_users"},
		{path: "mydb/doc1", want: "mydb"},
		{path: "/%24_users", want: "$_users"},
		{path: "/%24_users/doc1", want: "$_users"},
		{path: "/my-db_1.0", want: "my-db_1.0"},
		{path: "/a", want: "a"},
		{path: "/a/b", want: "a"},
		{path: "/%invalid", want: "%invalid"},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := database(tc.path)
			assert.Equal(t, tc.want, got)
		})
	}
}
