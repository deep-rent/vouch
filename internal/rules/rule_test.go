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

func env() Environment { return Environment{} }

func TestEvalWhen_ReturnsBool(t *testing.T) {
	r := &Rule{when: compile(t, "true")}
	got, err := r.evalWhen(env())
	if err != nil {
		t.Fatalf("eval when: %v", err)
	}
	if !got {
		t.Fatalf("want true")
	}

	r = &Rule{when: compile(t, "false")}
	got, err = r.evalWhen(env())
	if err != nil {
		t.Fatalf("eval when: %v", err)
	}
	if got {
		t.Fatalf("want false")
	}
}

func TestEvalWhen_WrongType(t *testing.T) {
	r := &Rule{when: compile(t, `"not-bool"`)} // compiles but returns string
	_, err := r.evalWhen(env())
	if err == nil || err.Error() == "" {
		t.Fatal("expected error for non-bool when")
	}
}

func TestEvalUser_StringAndEmpty(t *testing.T) {
	r := &Rule{user: nil}
	u, err := r.evalUser(env())
	if err != nil {
		t.Fatalf("eval user (nil): %v", err)
	}
	if u != "" {
		t.Fatalf("want empty user, got %q", u)
	}

	r = &Rule{user: compile(t, `"alice"`)}
	u, err = r.evalUser(env())
	if err != nil {
		t.Fatalf("eval user: %v", err)
	}
	if u != "alice" {
		t.Fatalf("want alice, got %q", u)
	}
}

func TestEvalUser_WrongType(t *testing.T) {
	r := &Rule{user: compile(t, "42")} // non-string
	_, err := r.evalUser(env())
	if err == nil || err.Error() == "" {
		t.Fatal("expected error for non-string user")
	}
}

func TestEvalRoles_CommaJoinedAndEmpty(t *testing.T) {
	r := &Rule{roles: nil}
	rs, err := r.evalRoles(env())
	if err != nil {
		t.Fatalf("eval roles (nil): %v", err)
	}
	if rs != "" {
		t.Fatalf("want empty roles, got %q", rs)
	}

	r = &Rule{roles: compile(t, `["reader","writer","admin"]`)}
	rs, err = r.evalRoles(env())
	if err != nil {
		t.Fatalf("eval roles: %v", err)
	}
	if rs != "reader,writer,admin" {
		t.Fatalf("want reader,writer,admin; got %q", rs)
	}
}

func TestEvalRoles_NonSlice(t *testing.T) {
	r := &Rule{roles: compile(t, `"admin"`)} // not a slice
	_, err := r.evalRoles(env())
	if err == nil || err.Error() == "" {
		t.Fatal("expected error for roles returning non-slice")
	}
}

func TestEvalRoles_ElementWrongType(t *testing.T) {
	r := &Rule{roles: compile(t, `["reader", 1, "writer"]`)} // 1 is not string
	_, err := r.evalRoles(env())
	if err == nil || err.Error() == "" {
		t.Fatal("expected error for roles element type")
	}
}

func TestRuleEval_SkipWhenFalse(t *testing.T) {
	r := &Rule{
		deny:  false,
		when:  compile(t, "false"),
		user:  compile(t, `"alice"`),    // should not be evaluated
		roles: compile(t, `["reader"]`), // should not be evaluated
	}
	skip, deny, user, roles, err := r.Eval(env())
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if !skip || deny || user != "" || roles != "" {
		t.Fatalf("want skip=true, deny=false, empty user/roles; got skip=%v deny=%v user=%q roles=%q",
			skip, deny, user, roles)
	}
}

func TestRuleEval_DenyWhenMatched(t *testing.T) {
	r := &Rule{
		deny:  true,
		when:  compile(t, "true"),
		user:  compile(t, `"alice"`),    // must not be evaluated
		roles: compile(t, `["reader"]`), // must not be evaluated
	}
	skip, deny, user, roles, err := r.Eval(env())
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if skip || !deny || user != "" || roles != "" {
		t.Fatalf("want skip=false, deny=true, empty user/roles; got skip=%v deny=%v user=%q roles=%q",
			skip, deny, user, roles)
	}
}

func TestRuleEval_AllowWithUserAndRoles(t *testing.T) {
	r := &Rule{
		deny:  false,
		when:  compile(t, "true"),
		user:  compile(t, `"alice"`),
		roles: compile(t, `["reader","writer"]`),
	}
	skip, deny, user, roles, err := r.Eval(env())
	if err != nil {
		t.Fatalf("Eval: %v", err)
	}
	if skip || deny {
		t.Fatalf("want applied allow rule; got skip=%v deny=%v", skip, deny)
	}
	if user != "alice" || roles != "reader,writer" {
		t.Fatalf("want user=alice roles=reader,writer; got user=%q roles=%q", user, roles)
	}
}

func TestRuleEval_UserErrorPropagates(t *testing.T) {
	r := &Rule{
		deny:  false,
		when:  compile(t, "true"),
		user:  compile(t, "42"), // invalid type
		roles: compile(t, `["reader"]`),
	}
	_, _, _, _, err := r.Eval(env())
	if err == nil {
		t.Fatal("expected error from user evaluation")
	}
}

func TestRuleEval_RolesErrorClearsUserAndReturnsError(t *testing.T) {
	r := &Rule{
		deny:  false,
		when:  compile(t, "true"),
		user:  compile(t, `"alice"`),
		roles: compile(t, `["reader", 1]`), // invalid element
	}
	_, _, user, _, err := r.Eval(env())
	if err == nil {
		t.Fatal("expected error from roles evaluation")
	}
	if user != "" {
		t.Fatalf("user should be cleared on roles error, got %q", user)
	}
}
