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
		name    string
		expr    string
		want    bool
		wantErr bool
	}{
		{"returns true", "true", true, false},
		{"returns false", "false", false, false},
		{"wrong type", `"not-bool"`, false, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &rule{when: compile(t, tc.expr)}
			got, err := r.evalWhen(Environment{})

			if tc.wantErr {
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
		name    string
		rule    *rule
		want    string
		wantErr bool
	}{
		{"nil expression", &rule{user: nil}, "", false},
		{"string expression", &rule{user: compile(t, `"alice"`)}, "alice", false},
		{"wrong type", &rule{user: compile(t, "42")}, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.rule.evalUser(Environment{})

			if tc.wantErr {
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
		name    string
		rule    *rule
		want    string
		wantErr bool
	}{
		{"nil expression", &rule{roles: nil}, "", false},
		{"string slice", &rule{roles: compile(t, `["a","b"]`)}, "a,b", false},
		{"empty slice", &rule{roles: compile(t, `[]`)}, "", false},
		{"non-slice type", &rule{roles: compile(t, `"admin"`)}, "", true},
		{"slice with non-string", &rule{roles: compile(t, `["a", 1]`)}, "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.rule.evalRoles(Environment{})

			if tc.wantErr {
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
		name    string
		rule    rule
		want    result
		wantErr bool
	}{
		{
			name: "skip when condition is false",
			rule: rule{when: compile(t, "false")},
			want: result{Skip: true},
		},
		{
			name: "deny when condition is true and deny mode is on",
			rule: rule{deny: true, when: compile(t, "true")},
			want: result{Deny: true},
		},
		{
			name: "allow with user and roles",
			rule: rule{
				when:  compile(t, "true"),
				user:  compile(t, `"alice"`),
				roles: compile(t, `["reader","writer"]`),
			},
			want: result{User: "alice", Roles: "reader,writer"},
		},
		{
			name: "allow with user and no roles",
			rule: rule{
				when: compile(t, "true"),
				user: compile(t, `"bob"`),
			},
			want: result{User: "bob"},
		},
		{
			name: "allow with roles and no user",
			rule: rule{
				when:  compile(t, "true"),
				roles: compile(t, `["editor"]`),
			},
			want: result{Roles: "editor"},
		},
		{
			name: "allow with no user or roles",
			rule: rule{when: compile(t, "true")},
			want: result{},
		},
		{
			name:    "error on invalid when expression",
			rule:    rule{when: compile(t, "1")},
			wantErr: true,
		},
		{
			name: "error on invalid user expression",
			rule: rule{
				when: compile(t, "true"),
				user: compile(t, "1"),
			},
			wantErr: true,
		},
		{
			name: "error on invalid roles expression",
			rule: rule{
				when:  compile(t, "true"),
				user:  compile(t, `"charlie"`),
				roles: compile(t, "1"),
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.rule.Eval(Environment{})

			if tc.wantErr {
				assert.Error(t, err)
				assert.Empty(t, got, "result should be zero value on error")
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
