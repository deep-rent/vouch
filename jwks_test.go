package traefikplugincouchdb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Helpers

func base64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func newRSAJWK(kid string, pub *rsa.PublicKey, use, alg string) jwk {
	return jwk{
		Kty: "RSA",
		Kid: kid,
		Use: use,
		Alg: alg,
		N:   base64url(pub.N.Bytes()),
		E:   base64url(intToBytes(int64(pub.E))),
	}
}

func newECJWK(kid string, pub *ecdsa.PublicKey, use, alg string) jwk {
	return jwk{
		Kty: "EC",
		Kid: kid,
		Use: use,
		Alg: alg,
		Crv: curveName(pub.Curve),
		X:   base64url(pub.X.Bytes()),
		Y:   base64url(pub.Y.Bytes()),
	}
}

func curveName(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return ""
	}
}

func jwksJSON(keys ...jwk) string {
	set := jwks{Keys: keys}
	b, _ := json.Marshal(set)
	return string(b)
}

func intToBytes(v int64) []byte {
	if v == 0 {
		return []byte{0}
	}
	out := make([]byte, 0, 8)
	for v > 0 {
		out = append([]byte{byte(v & 0xff)}, out...)
		v >>= 8
	}
	return out
}

// Tests

func TestParseJWKS_RSA_OK(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	kid := "kid1"
	j := jwksJSON(newRSAJWK(kid, &rk.PublicKey, "sig", "RS256"))

	m, err := parseJWKS(j)
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if len(m) != 1 {
		t.Fatalf("want 1 key, got %d", len(m))
	}
	key, ok := m[kid]
	if !ok {
		t.Fatalf("missing kid %q", kid)
	}
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", key)
	}
	if pub.E != rk.PublicKey.E || pub.N.Cmp(rk.PublicKey.N) != 0 {
		t.Fatalf("rsa public key mismatch")
	}
}

func TestParseJWKS_RSA_PS256_OK_NoAlgAlsoOK(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	j := jwksJSON(
		newRSAJWK("ps256", &rk.PublicKey, "sig", "PS256"),
		newRSAJWK("noalg", &rk.PublicKey, "sig", ""),
	)

	m, err := parseJWKS(j)
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("want 2 keys, got %d", len(m))
	}
	if _, ok := m["ps"].(*rsa.PublicKey); !ok {
		t.Fatalf("missing or wrong type for ps")
	}
	if _, ok := m["noalg"].(*rsa.PublicKey); !ok {
		t.Fatalf("missing or wrong type for noalg")
	}
}

func TestParseJWKS_EC_OK(t *testing.T) {
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	kid := "kidEC"
	j := jwksJSON(newECJWK(kid, &ek.PublicKey, "sig", "ES256"))

	m, err := parseJWKS(j)
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if len(m) != 1 {
		t.Fatalf("want 1 key, got %d", len(m))
	}
	key, ok := m[kid]
	if !ok {
		t.Fatalf("missing kid %q", kid)
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
	}
	if pub.X.Cmp(ek.X) != 0 || pub.Y.Cmp(ek.Y) != 0 || pub.Curve != ek.Curve {
		t.Fatalf("ecdsa public key mismatch")
	}
}

func TestParseJWKS_SkipNonSigUse(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	j := jwksJSON(newRSAJWK("encKey", &rk.PublicKey, "enc", "RS256"))

	m, err := parseJWKS(j)
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(m))
	}
}

func TestParseJWKS_DuplicateKID(t *testing.T) {
	rk1, _ := rsa.GenerateKey(rand.Reader, 2048)
	rk2, _ := rsa.GenerateKey(rand.Reader, 2048)
	j := jwksJSON(
		newRSAJWK("dup", &rk1.PublicKey, "sig", "RS256"),
		newRSAJWK("dup", &rk2.PublicKey, "sig", "RS256"),
	)

	_, err := parseJWKS(j)
	if err == nil || !strings.Contains(err.Error(), "duplicate kid") {
		t.Fatalf("expected duplicate kid error, got %v", err)
	}
}

func TestParseJWKS_RSA_BadAlgIsSkipped(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	j := jwksJSON(newRSAJWK("bad", &rk.PublicKey, "sig", "ES256"))

	m, err := parseJWKS(j)
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(m))
	}
}

func TestParseJWKS_EC_MismatchedAlgCurveSkipped(t *testing.T) {
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k := newECJWK("mismatch", &ek.PublicKey, "sig", "ES384")
	j := jwksJSON(k)

	m, err := parseJWKS(j)
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(m))
	}
}

func TestParseJWKS_RSA_MissingParamsError(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	n := base64url(rk.N.Bytes())
	j := jwksJSON(jwk{Kty: "RSA", Kid: "k1", Use: "sig", N: n})

	_, err := parseJWKS(j)
	if err == nil {
		t.Fatalf("expected error for missing rsa parameters")
	}
}

func TestParseJWKS_UnsupportedKtyIgnored(t *testing.T) {
	set := jwks{Keys: []jwk{{
		Kty: "OKP",
		Kid: "x",
		Use: "sig",
		Alg: "EdDSA",
		Crv: "Ed25519",
		X:   "AQ",
	}}}
	b, _ := json.Marshal(set)
	m, err := parseJWKS(string(b))
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(m))
	}
}

func TestParseJWKS_EC_NoAlgAccepted(t *testing.T) {
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	j := jwksJSON(newECJWK("ec-noalg", &ek.PublicKey, "sig", ""))

	m, err := parseJWKS(j)
	if err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	if len(m) != 1 {
		t.Fatalf("want 1 key, got %d", len(m))
	}
	if _, ok := m["ec-noalg"].(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey for ec-noalg")
	}
}
