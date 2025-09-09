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
	"testing"

	"github.com/deep-rent/vouch/internal/rules"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func compile(t *testing.T, src string) *vm.Program {
	t.Helper()
	p, err := expr.Compile(src, expr.Env(rules.Environment{}))
	if err != nil {
		t.Fatalf("compile %q: %v", src, err)
	}
	return p
}

func TestRuleEvalWhen(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		want     bool
		wantFail bool
	}{
		{"returns true", "true", true, false},
		{"returns false", "false", false, false},
		{"wrong type", `"not-bool"`, false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &rules.Rule{When: compile(t, tc.expr)}
			got, err := r.EvalWhen(rules.Environment{})

			if tc.wantFail {
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
		name     string
		rule     *rules.Rule
		want     string
		wantFail bool
	}{
		{"nil expression", &rules.Rule{User: nil}, "", false},
		{
			"string expression",
			&rules.Rule{User: compile(t, `"alice"`)},
			"alice",
			false,
		},
		{"wrong type", &rules.Rule{User: compile(t, "42")}, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.rule.EvalUser(rules.Environment{})

			if tc.wantFail {
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
		name     string
		rule     *rules.Rule
		want     string
		wantFail bool
	}{
		{"nil expression", &rules.Rule{Roles: nil}, "", false},
		{
			"string slice",
			&rules.Rule{Roles: compile(t, `["a","b"]`)},
			"a,b",
			false,
		},
		{"empty slice", &rules.Rule{Roles: compile(t, `[]`)}, "", false},
		{"non-slice type", &rules.Rule{Roles: compile(t, `"admin"`)}, "", true},
		{
			"slice with non-string",
			&rules.Rule{Roles: compile(t, `["a", 1]`)},
			"",
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.rule.EvalRoles(rules.Environment{})

			if tc.wantFail {
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
		name     string
		rule     rules.Rule
		want     rules.Action
		wantFail bool
	}{
		{
			name: "skip when condition is false",
			rule: rules.Rule{When: compile(t, "false")},
			want: rules.Action{Skip: true},
		},
		{
			name: "deny when condition is true and deny mode is on",
			rule: rules.Rule{Deny: true, When: compile(t, "true")},
			want: rules.Action{Deny: true},
		},
		{
			name: "allow with user and roles",
			rule: rules.Rule{
				When:  compile(t, "true"),
				User:  compile(t, `"alice"`),
				Roles: compile(t, `["reader","writer"]`),
			},
			want: rules.Action{
				Grant: rules.Scope{User: "alice", Roles: "reader,writer"},
			},
		},
		{
			name: "allow with user and no roles",
			rule: rules.Rule{
				When: compile(t, "true"),
				User: compile(t, `"bob"`),
			},
			want: rules.Action{Grant: rules.Scope{User: "bob"}},
		},
		{
			name: "allow with roles and no user",
			rule: rules.Rule{
				When:  compile(t, "true"),
				Roles: compile(t, `["editor"]`),
			},
			want: rules.Action{Grant: rules.Scope{Roles: "editor"}},
		},
		{
			name: "allow with no user or roles",
			rule: rules.Rule{When: compile(t, "true")},
			want: rules.Action{},
		},
		{
			name:     "error on invalid when expression",
			rule:     rules.Rule{When: compile(t, "1")},
			wantFail: true,
		},
		{
			name: "error on invalid user expression",
			rule: rules.Rule{
				When: compile(t, "true"),
				User: compile(t, "1"),
			},
			wantFail: true,
		},
		{
			name: "error on invalid roles expression",
			rule: rules.Rule{
				When:  compile(t, "true"),
				User:  compile(t, `"charlie"`),
				Roles: compile(t, "1"),
			},
			wantFail: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.rule.Eval(rules.Environment{})

			if tc.wantFail {
				require.Error(t, err)
				assert.Empty(t, got, "result should be zero value on error")
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
