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
	"testing"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/expr-lang/expr"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEngine(t *testing.T) {
	t.Run("fails on empty rules", func(t *testing.T) {
		e, err := NewEngine(nil)
		require.Error(t, err)
		assert.Nil(t, e)
	})

	t.Run("compiles rules", func(t *testing.T) {
		e, err := NewEngine([]config.Rule{
			{When: "true", User: `"alice"`, Roles: `["admin"]`},
		})
		require.NoError(t, err)
		require.NotNil(t, e)
		require.Len(t, e.(*engine).rules, 1)
	})
}

func TestEngineEval(t *testing.T) {
	env := func() Environment {
		tok, err := jwt.NewBuilder().Subject("bob").Build()
		require.NoError(t, err)

		return Environment{
			tok:    tok,
			Method: "GET",
			Path:   "/db/doc",
			DB:     "db",
		}
	}

	t.Run("allow rule returns pass with user and roles", func(t *testing.T) {
		e, err := NewEngine([]config.Rule{
			{When: "true", User: `"alice"`, Roles: `["r1","r2"]`},
		})
		require.NoError(t, err)

		res, err := e.Eval(env())
		require.NoError(t, err)
		assert.True(t, res.Pass)
		assert.Equal(t, "alice", res.User)
		assert.Equal(t, "r1,r2", res.Roles)
	})

	t.Run("allow rule with only user", func(t *testing.T) {
		e, err := NewEngine([]config.Rule{
			{When: "true", User: `"bob"`},
		})
		require.NoError(t, err)

		res, err := e.Eval(env())
		require.NoError(t, err)
		assert.True(t, res.Pass)
		assert.Equal(t, "bob", res.User)
		assert.Empty(t, res.Roles)
	})

	t.Run("allow rule with only roles", func(t *testing.T) {
		e, err := NewEngine([]config.Rule{
			{When: "true", Roles: `["reader"]`},
		})
		require.NoError(t, err)

		res, err := e.Eval(env())
		require.NoError(t, err)
		assert.True(t, res.Pass)
		assert.Empty(t, res.User)
		assert.Equal(t, "reader", res.Roles)
	})

	t.Run("deny rule returns pass=false", func(t *testing.T) {
		e, err := NewEngine([]config.Rule{
			{Deny: true, When: "true"},
		})
		require.NoError(t, err)

		res, err := e.Eval(env())
		require.NoError(t, err)
		assert.False(t, res.Pass)
		assert.Empty(t, res.User)
		assert.Empty(t, res.Roles)
	})

	t.Run("ordering: first rule skips, second allows", func(t *testing.T) {
		e, err := NewEngine([]config.Rule{
			{When: "false"},
			{When: "true", User: `"carol"`},
		})
		require.NoError(t, err)

		res, err := e.Eval(env())
		require.NoError(t, err)
		assert.True(t, res.Pass)
		assert.Equal(t, "carol", res.User)
	})

	t.Run("ordering: first rule skips, second denies", func(t *testing.T) {
		e, err := NewEngine([]config.Rule{
			{When: "false"},
			{Deny: true, When: "true"},
			{When: "true", User: `"should_not_match"`},
		})
		require.NoError(t, err)

		res, err := e.Eval(env())
		require.NoError(t, err)
		assert.False(t, res.Pass)
	})

	t.Run("default deny when no rules match", func(t *testing.T) {
		e, err := NewEngine([]config.Rule{
			{When: "false"},
			{When: "Method == 'POST'"},
		})
		require.NoError(t, err)

		res, err := e.Eval(env()) // Method is GET
		require.NoError(t, err)
		assert.False(t, res.Pass)
	})

	t.Run("claim extraction works", func(t *testing.T) {
		e, err := NewEngine([]config.Rule{
			{When: "true", User: `Claim("sub")`},
		})
		require.NoError(t, err)

		res, err := e.Eval(env())
		require.NoError(t, err)
		assert.True(t, res.Pass)
		assert.Equal(t, "bob", res.User)
	})

	t.Run("claim extraction with default", func(t *testing.T) {
		e, err := NewEngine([]config.Rule{
			{When: "true", User: `Claim("unknown") ?? "default"`},
		})
		require.NoError(t, err)

		res, err := e.Eval(env())
		require.NoError(t, err)
		assert.True(t, res.Pass)
		assert.Equal(t, "default", res.User)
	})

	t.Run("runtime error propagates", func(t *testing.T) {
		// Craft a rule that compiles but returns a non-bool at runtime for 'when'.
		// We bypass NewEngine compiler safeguards by constructing Engine directly.
		prog, err := expr.Compile("1", expr.Env(Environment{})) // returns int
		require.NoError(t, err)
		badRule := Rule{when: prog} // deny=false, triggers type error in evalWhen
		e := &engine{rules: []Rule{badRule}}

		res, err := e.Eval(env())
		require.Error(t, err)
		assert.Empty(t, res)
	})
}

func TestEngineFunc(t *testing.T) {
	e := EngineFunc(func(Environment) (Result, error) { return Result{Pass: true, User: "x"}, nil })
	r, err := e.Eval(Environment{})
	require.NoError(t, err)
	require.True(t, r.Pass)
	require.Equal(t, "x", r.User)
}
