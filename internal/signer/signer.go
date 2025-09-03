package signer

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"hash"
)

type Signer struct {
	mac hash.Hash
}

func (s *Signer) Sign(user string) string {
	_, _ = s.mac.Write([]byte(user))
	return hex.EncodeToString(s.mac.Sum(nil))
}

func New(secret string) *Signer {
	if secret == "" {
		return nil
	}
	return &Signer{
		mac: hmac.New(sha1.New, []byte(secret)),
	}
}
