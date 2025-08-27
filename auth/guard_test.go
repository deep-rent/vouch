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
	"context"
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
		{Mode: "block", When: "true", UserName: `"u"`},
	})
	if err == nil {
		t.Fatalf("expected error for invalid mode")
	}

	// Missing when
	_, err = NewGuard([]Rule{
		{Mode: "allow", When: "", UserName: `"u"`},
	})
	if err == nil {
		t.Fatalf("expected error for missing when")
	}

	// Deny must not define user
	_, err = NewGuard([]Rule{
		{Mode: "deny", When: "true", UserName: `"u"`},
	})
	if err == nil {
		t.Fatalf("expected error: deny rule with user")
	}

	// Deny must not define role
	_, err = NewGuard([]Rule{
		{Mode: "deny", When: "true", Roles: `"_admin"`},
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
	auth, err := NewGuard([]Rule{
		{Mode: "deny", When: `DB == "secret"`},
		{Mode: "allow", When: `true`, UserName: `"u"`, Roles: `""`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	pass, user, role, runErr := auth.Authorize(context.Background(), env(nil, "secret"))
	if runErr != nil {
		t.Fatalf("authorize error: %v", runErr)
	}
	if pass || user != "" || role != "" {
		t.Fatalf("expected deny to short-circuit; got allowed=%v user=%q role=%q", pass, user, role)
	}
}

func TestAuthorize_AllowUsernameAndRole(t *testing.T) {
	auth, err := NewGuard([]Rule{
		{Mode: "allow", When: `true`, UserName: `"alice"`, Roles: `"_admin,writer"`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pass, user, role, runErr := auth.Authorize(context.Background(), env(nil, "db"))
	if runErr != nil {
		t.Fatalf("authorize error: %v", runErr)
	}
	if !pass || user != "alice" || role != "_admin,writer" {
		t.Fatalf("got allowed=%v user=%q role=%q", pass, user, role)
	}
}

func TestAuthorize_OrderingFirstMatchWins(t *testing.T) {
	auth, err := NewGuard([]Rule{
		// Admin first
		{Mode: "allow", When: `C["role"] == "admin"`, UserName: `C["user"]`, Roles: `"_admin"`},
		// Fallback
		{Mode: "allow", When: `true`, UserName: `C["user"]`, Roles: `"writer"`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	claims := map[string]any{"user": "bob", "role": "admin"}

	pass, user, role, runErr := auth.Authorize(context.Background(), env(claims, "db"))
	if runErr != nil {
		t.Fatalf("authorize error: %v", runErr)
	}
	if !pass || user != "bob" || role != "_admin" {
		t.Fatalf("first match should be admin; got allowed=%v user=%q role=%q", pass, user, role)
	}
}

func TestAuthorize_WhenNotBoolError(t *testing.T) {
	auth, err := NewGuard([]Rule{
		{Mode: "allow", When: `"not_bool"`, UserName: `"u"`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	_, _, _, runErr := auth.Authorize(context.Background(), env(nil, "db"))
	if runErr == nil {
		t.Fatalf("expected error when 'when' is not bool")
	}
}

func TestAuthorize_UserNotStringError(t *testing.T) {
	auth, err := NewGuard([]Rule{
		{Mode: "allow", When: `true`, UserName: `123`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, _, _, runErr := auth.Authorize(context.Background(), env(nil, "db")); runErr == nil {
		t.Fatalf("expected error for non-string user")
	}
}

func TestAuthorize_RoleNotStringError(t *testing.T) {
	auth, err := NewGuard([]Rule{
		{Mode: "allow", When: `true`, UserName: `"u"`, Roles: `123`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if _, _, _, runErr := auth.Authorize(context.Background(), env(nil, "db")); runErr == nil {
		t.Fatalf("expected error for non-string role")
	}
}

func TestAuthorize_UndefinedRole(t *testing.T) {
	auth, err := NewGuard([]Rule{
		{Mode: "allow", When: `true`, UserName: `"u"`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	_, _, role, runErr := auth.Authorize(context.Background(), env(nil, "db"))
	if runErr != nil {
		t.Fatalf("authorize error: %v", runErr)
	}
	if role != "" {
		t.Fatalf("expected empty role; got %q", role)
	}
}

func TestAuthorize_NoRuleMatches(t *testing.T) {
	auth, err := NewGuard([]Rule{
		{Mode: "deny", When: `false`},
		{Mode: "allow", When: `false`, UserName: `"u"`},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pass, user, role, runErr := auth.Authorize(context.Background(), env(nil, "db"))
	if runErr != nil {
		t.Fatalf("authorize error: %v", runErr)
	}
	if pass || user != "" || role != "" {
		t.Fatalf("expected denied with no match; got allowed=%v user=%q role=%q", pass, user, role)
	}
}
