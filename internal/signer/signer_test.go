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

package signer_test

import (
	"testing"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/stretchr/testify/require"
)

func TestMatch(t *testing.T) {
	s := New(config.Signer{Secret: "secret"})
	got := s.Sign("test")
	// echo -n "test" | openssl dgst -sha256 -hmac "secret"
	require.Equal(t, "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914", got)
}

func TestEmptyKey(t *testing.T) {
	s := New(config.Signer{})
	require.Nil(t, s)
}
