// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
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

package stamper_test

import (
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/vouch/internal/bouncer"
	"github.com/deep-rent/vouch/internal/stamper"
	"github.com/stretchr/testify/assert"
)

func TestStamper_Stamp(t *testing.T) {
	cfg := &stamper.Config{
		UserNameHeader: "X-User",
		RolesHeader:    "X-Roles",
	}
	s := stamper.New(cfg)

	t.Run("WithRoles", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		user := &bouncer.User{
			Name:  "alice",
			Roles: []string{"admin", "editor"},
		}

		s.Stamp(req, user)

		assert.Equal(t, "alice", req.Header.Get("X-User"))
		assert.Equal(t, "admin,editor", req.Header.Get("X-Roles"))
	})

	t.Run("WithoutRoles", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		// Simulate a spoofing attempt from the client
		req.Header.Set("X-Roles", "admin")

		user := &bouncer.User{
			Name:  "bob",
			Roles: nil,
		}

		s.Stamp(req, user)

		assert.Equal(t, "bob", req.Header.Get("X-User"))
		assert.Empty(
			t,
			req.Header.Get("X-Roles"),
			"Roles header should be removed if user has no roles",
		)
	})

	t.Run("OverwritesExisting", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-User", "hacker")
		req.Header.Set("X-Roles", "root")

		user := &bouncer.User{
			Name:  "alice",
			Roles: []string{"guest"},
		}

		s.Stamp(req, user)

		assert.Equal(t, "alice", req.Header.Get("X-User"))
		assert.Equal(t, "guest", req.Header.Get("X-Roles"))
	})
}
