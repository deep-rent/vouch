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

// Rule defines a single authorization policy. The expressions within the rule
// are evaluated against the incoming request and the authenticated user's
// session data.
//
// The `When` expression is always evaluated first. If it returns true, the
// rule is considered applicable to the request.
//
// If the rule's `Mode` is "deny", and the `When` condition is met, the request
// is immediately denied.
//
// If the `Mode` is "allow", and the `When` condition is met, then access is
// granted by invoking the `User` and `Role` expressions to determine the
// user's identity and permissions in CouchDB.
type Rule struct {
	// Mode specifies the rule's behavior, either "allow" or "deny".
	Mode string `json:"mode"`

	// When is a required expression that determines if the rule applies to the
	// current request.
	When string `json:"when"`

	// UserName is a string expression that returns the CouchDB username. It is
	// required for "allow" mode and must be omitted in "deny" mode.
	UserName string `json:"userName,omitempty"`

	// Roles is an expression producing a either a single CouchDB role name, a
	// comma-separated list of roles, or a slice of roles. It can only be used
	// with "allow" mode.
	Roles string `json:"roles,omitempty"`
}

// Defines the possible rule modes.
const (
	ModeAllow = "allow"
	ModeDeny  = "deny"
)
