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

package stamper

import (
	"net/http"
	"strings"

	"github.com/deep-rent/vouch/internal/bouncer"
)

type Config struct {
	UserNameHeader string // The header to set with the authenticated user's name.
	RolesHeader    string // The header to set with the user's roles.
}

type Stamper struct {
	userNameHeader string
	rolesHeader    string
}

func New(cfg *Config) *Stamper {
	return &Stamper{
		userNameHeader: cfg.UserNameHeader,
		rolesHeader:    cfg.RolesHeader,
	}
}

func (s *Stamper) Stamp(req *http.Request, user *bouncer.User) {
	req.Header.Set(s.userNameHeader, user.Name)

	if len(user.Roles) == 0 {
		req.Header.Del(s.rolesHeader)
	} else {
		req.Header.Set(s.rolesHeader, strings.Join(user.Roles, ","))
	}
}
