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
	"testing"
)

func env(claims map[string]any, db string) Environment {
	return Environment{
		Claims: claims,
		C:      claims,
		Method: "GET",
		Path:   "/" + db + "/_all_docs",
		DB:     db,
	}
}

func TestNewGuard_Errors(t *testing.T) {
	// Empty rules
	if _, err := NewGuard(nil); err == nil {
		t.Fatalf("expected error for empty rules")
	}

	// Invalid mode
	_, err := NewGuard([]Rule{
		{Mode: "block", When: "true", User: `"u"`},
	})
	if err == nil {
		t.Fatalf("expected error for invalid mode")
	}

	// Missing when
	_, err = NewGuard([]Rule{
		{Mode: "allow", When: "", User: `"u"`},
	})
	if err == nil {
		t.Fatalf("expected error for missing when")
	}

	// Deny must not define user
	_, err = NewGuard([]Rule{
		{Mode: "deny", When: "true", User: `"u"`},
	})
	if err == nil {
		t.Fatalf("expected error: deny rule with user")
	}

	// Deny must not define role
	_, err = NewGuard([]Rule{
		{Mode: "deny", When: "true", Role: `"_admin"`},
	})
	if err == nil {
		t.Fatalf("expected error: deny rule with role")
	}

	// Allow must define user
	_, err = NewGuard([]Rule{
		{Mode: "allow", When: "true"},
	})
	if err == nil {
		t.Fatalf("expected error: allow rule without user")
	}
}

func TestAuthorize_FirstMatchDeny(t *testing.T) {
	g, err := NewGuard([]Rule{
		{Mode: "deny", When: `DB == "secret"`},
		{Mode: "allow", When: `true`, User: `"u"`, Role: `""`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	p, u, ro, err := g.Authorize(env(nil, "secret"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if p || u != "" || ro != "" {
		t.Fatalf("expected deny to short-circuit; got allowed=%v user=%q role=%q", p, u, ro)
	}
}

func TestAuthorize_AllowUserAndRole(t *testing.T) {
	g, err := NewGuard([]Rule{
		{Mode: "allow", When: `true`, User: `"alice"`, Role: `"_admin,writer"`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p, u, ro, err := g.Authorize(env(nil, "db"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !p || u != "alice" || ro != "_admin,writer" {
		t.Fatalf("got allowed=%v user=%q role=%q", p, u, ro)
	}
}

func TestAuthorize_RolesArray(t *testing.T) {
	g, err := NewGuard([]Rule{
		{Mode: "allow", When: `true`, User: `"u"`, Role: `["writer","_admin"]`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p, u, ro, err := g.Authorize(env(nil, "db"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !p || u != "u" || ro != "writer,_admin" {
		t.Fatalf("got allowed=%v user=%q role=%q", p, u, ro)
	}
}

func TestAuthorize_OrderingFirstMatchWins(t *testing.T) {
	g, err := NewGuard([]Rule{
		// Admin first
		{Mode: "allow", When: `C["role"] == "admin"`, User: `C["user"]`, Role: `"_admin"`},
		// Fallback
		{Mode: "allow", When: `true`, User: `C["user"]`, Role: `"writer"`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	claims := map[string]any{"user": "bob", "role": "admin"}

	p, u, ro, err := g.Authorize(env(claims, "db"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if !p || u != "bob" || ro != "_admin" {
		t.Fatalf("first match should be admin; got allowed=%v user=%q role=%q", p, u, ro)
	}
}

func TestAuthorize_WhenNotBoolError(t *testing.T) {
	g, err := NewGuard([]Rule{
		{Mode: "allow", When: `"not_bool"`, User: `"u"`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, _, _, err := g.Authorize(env(nil, "db")); err == nil {
		t.Fatalf("expected error when 'when' is not bool")
	}
}

func TestAuthorize_UserNotStringError(t *testing.T) {
	g, err := NewGuard([]Rule{
		{Mode: "allow", When: `true`, User: `123`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, _, _, err := g.Authorize(env(nil, "db")); err == nil {
		t.Fatalf("expected error for non-string user")
	}
}

func TestAuthorize_RoleNotStringError(t *testing.T) {
	g, err := NewGuard([]Rule{
		{Mode: "allow", When: `true`, User: `"u"`, Role: `123`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, _, _, err := g.Authorize(env(nil, "db")); err == nil {
		t.Fatalf("expected error for non-string role")
	}
}

func TestAuthorize_UndefinedRole(t *testing.T) {
	g, err := NewGuard([]Rule{
		{Mode: "allow", When: `true`, User: `"u"`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	_, _, ro, err := g.Authorize(env(nil, "db"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if ro != "" {
		t.Fatalf("expected empty role; got %q", ro)
	}
}

func TestAuthorize_NoRuleMatches(t *testing.T) {
	g, err := NewGuard([]Rule{
		{Mode: "deny", When: `false`},
		{Mode: "allow", When: `false`, User: `"u"`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	p, u, ro, err := g.Authorize(env(nil, "db"))
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if p || u != "" || ro != "" {
		t.Fatalf("expected denied with no match; got allowed=%v user=%q role=%q", p, u, ro)
	}
}
