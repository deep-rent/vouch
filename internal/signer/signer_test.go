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
	"crypto/sha1"
	"crypto/sha512"
	"hash"
	"testing"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/signer"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	tests := []struct {
		name string
		alg  func() hash.Hash
		want string
	}{
		{
			name: "sha256 (default)",
			alg:  nil,
			want: "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914",
		},
		{
			name: "sha1",
			alg:  sha1.New,
			want: "1aa349585ed7ecbd3b9c486a30067e395ca4b356",
		},
		{
			name: "sha512",
			alg:  sha512.New,
			want: "f8a4f0a209167bc192a1bffaa01ecdb09e06c57f96530d92ec9ccea0090d290e55071306d6b654f26ae0c8721f7e48a2d7130b881151f2cec8d61d941a6be88a",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Signer{
				Secret:    "secret",
				Algorithm: tc.alg,
			}
			s := signer.New(cfg)
			require.NotNil(t, s)

			// echo -n "test" | openssl dgst -<alg> -hmac "secret"
			got := s.Sign("test")
			require.Equal(t, tc.want, got)
		})
	}
}

func TestEmptyKey(t *testing.T) {
	s := signer.New(config.Signer{})
	require.Nil(t, s)
}
