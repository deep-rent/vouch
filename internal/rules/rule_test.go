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

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func compile(t *testing.T, src string, opts ...expr.Option) *vm.Program {
	t.Helper()
	p, err := expr.Compile(src, append(
		[]expr.Option{expr.Env(Environment{})}, opts...,
	)...)
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	return p
}

func TestRuleEvalWhen(t *testing.T) {
	tests := []struct {
		// inputs
		name string
		expr string
		// expected outputs
		want bool
		fail bool
	}{
		{"returns true", "true", true, false},
		{"returns false", "false", false, false},
		{"wrong type", `"not-bool"`, false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &Rule{when: compile(t, tc.expr)}
			got, err := r.evalWhen(Environment{})

			if tc.fail {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRuleEvalUser(t *testing.T) {
	tests := []struct {
		// inputs
		name string
		rule *Rule
		// expected outputs
		want string
		fail bool
	}{
		{"nil expression", &Rule{user: nil}, "", false},
		{"string expression", &Rule{user: compile(t, `"alice"`)}, "alice", false},
		{"wrong type", &Rule{user: compile(t, "42")}, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.rule.evalUser(Environment{})

			if tc.fail {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRuleEvalRoles(t *testing.T) {
	tests := []struct {
		// inputs
		name string
		rule *Rule
		// expected outputs
		want string
		fail bool
	}{
		{"nil expression", &Rule{roles: nil}, "", false},
		{"string slice", &Rule{roles: compile(t, `["a","b"]`)}, "a,b", false},
		{"empty slice", &Rule{roles: compile(t, `[]`)}, "", false},
		{"non-slice type", &Rule{roles: compile(t, `"admin"`)}, "", true},
		{"slice with non-string", &Rule{roles: compile(t, `["a", 1]`)}, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.rule.evalRoles(Environment{})

			if tc.fail {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRuleEval(t *testing.T) {
	tests := []struct {
		// inputs
		name string
		rule Rule
		// expected outputs
		want result
		fail bool
	}{
		{
			name: "skip when condition is false",
			rule: Rule{when: compile(t, "false")},
			want: result{Skip: true},
		},
		{
			name: "deny when condition is true and deny mode is on",
			rule: Rule{deny: true, when: compile(t, "true")},
			want: result{Deny: true},
		},
		{
			name: "allow with user and roles",
			rule: Rule{
				when:  compile(t, "true"),
				user:  compile(t, `"alice"`),
				roles: compile(t, `["reader","writer"]`),
			},
			want: result{User: "alice", Roles: "reader,writer"},
		},
		{
			name: "allow with user and no roles",
			rule: Rule{
				when: compile(t, "true"),
				user: compile(t, `"bob"`),
			},
			want: result{User: "bob"},
		},
		{
			name: "allow with roles and no user",
			rule: Rule{
				when:  compile(t, "true"),
				roles: compile(t, `["editor"]`),
			},
			want: result{Roles: "editor"},
		},
		{
			name: "allow with no user or roles",
			rule: Rule{when: compile(t, "true")},
			want: result{},
		},
		{
			name: "error on invalid when expression",
			rule: Rule{when: compile(t, "1")},
			fail: true,
		},
		{
			name: "error on invalid user expression",
			rule: Rule{
				when: compile(t, "true"),
				user: compile(t, "1"),
			},
			fail: true,
		},
		{
			name: "error on invalid roles expression",
			rule: Rule{
				when:  compile(t, "true"),
				user:  compile(t, `"charlie"`),
				roles: compile(t, "1"),
			},
			fail: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.rule.Eval(Environment{})

			if tc.fail {
				require.Error(t, err)
				assert.Empty(t, got, "result should be zero value on error")
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
