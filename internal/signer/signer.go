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

package signer

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"

	"github.com/deep-rent/vouch/internal/config"
)

// Signer computes deterministic HMAC tags using a static secret.
// It is used to produce CouchDB proxy authentication tokens for securing
// the communication between the proxy and CouchDB.
type Signer struct {
	key []byte
	alg func() hash.Hash
}

// Sign returns the lowercase hex-encoded HMAC of the provided user name
// using the underlying secret key and hash algorithm. The output is
// deterministic for the same input and key.
func (s *Signer) Sign(user string) string {
	mac := hmac.New(s.alg, s.key)
	// Writing cannot fail for in-memory hashes, so the write error is
	// intentionally ignored.
	_, _ = mac.Write([]byte(user))
	return hex.EncodeToString(mac.Sum(nil))
}

// New returns a new Signer that derives its HMAC key from the given secret.
// If the secret is empty, nil will be returned.
func New(cfg config.Signer) *Signer {
	key := []byte(cfg.Secret)
	if len(key) == 0 {
		return nil
	}
	alg := cfg.Algorithm
	if alg == nil {
		alg = sha256.New
	}
	return &Signer{
		key: key,
		alg: alg,
	}
}
