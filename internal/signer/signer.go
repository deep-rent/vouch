package signer

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
)

type Algorithm func() hash.Hash

var Algorithms = map[string]Algorithm{
	"sha":    sha1.New,
	"sha224": sha256.New224,
	"sha256": sha256.New,
	"sha384": sha512.New384,
	"sha512": sha512.New,
}

type Signer interface {
	Sign(user string) string
}

func New(key string, opts ...Option) Signer {
	s := &signer{
		key: []byte(key),
		alg: Algorithms["sha256"],
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type Option func(*signer)

func WithAlgorithm(alg Algorithm) Option {
	return func(s *signer) {
		if alg != nil {
			s.alg = alg
		}
	}
}

type signer struct {
	key []byte
	alg Algorithm
}

func (s *signer) Sign(user string) string {
	mac := hmac.New(s.alg, s.key)
	// Writing cannot fail for in-memory hashes, so the write error is
	// intentionally ignored.
	_, _ = mac.Write([]byte(user))
	return hex.EncodeToString(mac.Sum(nil))
}
