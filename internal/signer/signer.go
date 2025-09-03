package signer

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
)

type Signer struct {
	key []byte
}

func (s *Signer) Sign(user string) string {
	mac := hmac.New(sha1.New, s.key)
	_, _ = mac.Write([]byte(user))
	return hex.EncodeToString(mac.Sum(nil))
}

func New(secret string) *Signer {
	if secret == "" {
		return nil
	}
	return &Signer{
		key: []byte(secret),
	}
}
