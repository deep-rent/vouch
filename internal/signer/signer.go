package signer

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"strings"

	"github.com/deep-rent/vouch/internal/util"
)

// MinimumKeyLength is the recommended minimum length for secret keys.
const MinimumKeyLength = 32

// DefaultAlgorithm is the name of the default hash algorithm.
const DefaultAlgorithm = "sha256"

// Algorithm defines a hash function constructor.
type Algorithm func() hash.Hash

// algorithms associates string identifiers with Algorithms. The keys
// correspond to the names recognized by CouchDB.
//
// This map must not be modified at runtime.
var algorithms = map[string]Algorithm{
	"sha":    sha1.New,
	"sha224": sha256.New224,
	"sha256": sha256.New,
	"sha384": sha512.New384,
	"sha512": sha512.New,
}

// ResolveAlgorithm looks up an Algorithm by name. The name is case-sensitive
// and leading or trailing whitespace does not affect the lookup. An empty
// name yields DefaultAlgorithm(). If no such algorithm exists, nil is returned.
func ResolveAlgorithm(name string) Algorithm {
	name = strings.TrimSpace(name)
	if name == "" {
		name = DefaultAlgorithm
	}
	return algorithms[name]
}

// SupportedAlgorithms returns the list of supported algorithm names.
func SupportedAlgorithms() []string {
	return util.Keys(algorithms)
}

// Signer computes opaque tokens to secure the communication between
// the proxy and CouchDB. It uses a secret key shared between both parties to
// sign user names.
type Signer interface {
	// Sign hashes the given user name to obtain a proxy authentication token.
	// The result is deterministic for the same user and key.
	Sign(user string) string
}

// New creates a new Signer using a secret key and options.
// If the key is empty, this function panics. The key should contain at least
// 32 characters to achieve sufficient entropy, although a length check is
// not performed.
func New(key string, opts ...Option) Signer {
	if key == "" {
		panic("key must not be empty")
	}
	s := &signer{
		key: []byte(key),
		alg: algorithms[DefaultAlgorithm],
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Option customizes the behavior of a Signer.
type Option func(*signer)

// WithAlgorithm sets the hash algorithm used for signing.
//
// If nil is given, this option is ignored. By default, SHA-256 is used.
func WithAlgorithm(alg Algorithm) Option {
	return func(s *signer) {
		if alg != nil {
			s.alg = alg
		}
	}
}

// signer is the default implementation of Signer.
type signer struct {
	key []byte
	alg Algorithm
}

// Sign implements the Signer interface.
func (s *signer) Sign(user string) string {
	mac := hmac.New(s.alg, s.key)
	// Writing cannot fail for in-memory hashes, so the write error is
	// intentionally ignored.
	_, _ = mac.Write([]byte(user))
	return hex.EncodeToString(mac.Sum(nil))
}
