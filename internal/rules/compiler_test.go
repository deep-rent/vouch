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

	"github.com/deep-rent/vouch/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCompiler(t *testing.T) {
	c := NewCompiler()
	require.NotNil(t, c, "compiler should not be nil")
	assert.NotNil(t, c.when, "when options should be initialized")
	assert.NotNil(t, c.user, "user options should be initialized")
	assert.NotNil(t, c.roles, "roles options should be initialized")
}

func TestCompilerCompile(t *testing.T) {
	tests := []struct {
		// inputs
		name  string
		rules []config.Rule
		// expected outputs
		count int
		fail  bool
		err   string
	}{
		{
			name: "valid allow rule with all fields",
			rules: []config.Rule{
				{Deny: false, When: "true", User: `"alice"`, Roles: `["admin"]`},
			},
			count: 1,
		},
		{
			name: "valid allow rule with only when",
			rules: []config.Rule{
				{Deny: false, When: "true"},
			},
			count: 1,
		},
		{
			name: "valid deny rule",
			rules: []config.Rule{
				{Deny: true, When: "Method == 'DELETE'"},
			},
			count: 1,
		},
		{
			name: "deny rule with user and roles ignores them",
			rules: []config.Rule{
				{Deny: true, When: "true", User: `"alice"`, Roles: `["admin"]`},
			},
			count: 1,
		},
		{
			name: "multiple valid rules",
			rules: []config.Rule{
				{Deny: false, When: "true", User: `"alice"`},
				{Deny: true, When: "false"},
			},
			count: 2,
		},
		{
			name: "invalid when expression (syntax)",
			rules: []config.Rule{
				{Deny: false, When: "true &&"},
			},
			fail: true,
			err:  "rules[0].when: unexpected token EOF",
		},
		{
			name: "invalid when expression (type)",
			rules: []config.Rule{
				{Deny: false, When: `"a string"`},
			},
			fail: true,
			err:  "rules[0].when: expected bool, but got string",
		},
		{
			name: "invalid user expression (syntax)",
			rules: []config.Rule{
				{Deny: false, When: "true", User: "len()"},
			},
			fail: true,
			err:  "rules[0].user: invalid number of arguments",
		},
		{
			name: "invalid user expression (type)",
			rules: []config.Rule{
				{Deny: false, When: "true", User: "123"},
			},
			fail: true,
			err:  "rules[0].user: expected string, but got int",
		},
		{
			name: "valid roles expression with trailing comma",
			rules: []config.Rule{
				{Deny: false, When: "true", Roles: `["a",]`},
			},
			count: 1,
		},
		{
			name: "invalid roles expression (type)",
			rules: []config.Rule{
				{Deny: false, When: "true", Roles: `"not a slice"`},
			},
			fail: true,
			err:  "rules[0].roles: expected slice, but got string",
		},
		{
			name: "error in second rule",
			rules: []config.Rule{
				{Deny: false, When: "true"},
				{Deny: true, When: "123"},
			},
			fail: true,
			err:  "rules[1].when: expected bool, but got int",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCompiler()
			compiled, err := c.Compile(tc.rules)

			if tc.fail {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				return
			}

			require.NoError(t, err)
			require.Len(t, compiled, tc.count)

			for i, r := range tc.rules {
				assert.Equal(t, r.Deny, compiled[i].deny)
				assert.NotNil(t, compiled[i].when)
				if !r.Deny && r.User != "" {
					assert.NotNil(t, compiled[i].user)
				} else {
					assert.Nil(t, compiled[i].user)
				}
				if !r.Deny && r.Roles != "" {
					assert.NotNil(t, compiled[i].roles)
				} else {
					assert.Nil(t, compiled[i].roles)
				}
			}
		})
	}
}
