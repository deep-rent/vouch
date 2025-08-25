package traefikplugincouchdb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// parseJWKS builds a map of keys by kid. The returned map can be empty if no
// valid keys are found. Only public RSA and EC keys are supported.
func parseJWKS(raw string) (map[string]any, error) {
	var set jwks
	if err := json.Unmarshal([]byte(raw), &set); err != nil {
		return nil, err
	}
	out := make(map[string]any)
	for _, k := range set.Keys {
		if k.Use != "sig" {
			continue // Skip keys not meant for signing.
		}
		if k.Kid == "" {
			continue
		}
		// Prevent ambiguous selection.
		if _, dup := out[k.Kid]; dup {
			return nil, fmt.Errorf("duplicate kid %q", k.Kid)
		}
		switch strings.ToUpper(k.Kty) {
		case "RSA":
			switch k.Alg {
			case "":
			case "RS256":
			case "RS384":
			case "RS512":
			case "PS256":
			case "PS384":
			case "PS512":
			default:
				continue
			}
			pk, err := rsaKey(k.N, k.E)
			if err != nil {
				return nil, fmt.Errorf("rsa kid=%s: %w", k.Kid, err)
			}
			out[k.Kid] = pk
		case "EC":
			switch k.Alg {
			case "":
			case "ES256":
				if k.Crv != "P-256" {
					continue
				}
			case "ES384":
				if k.Crv != "P-384" {
					continue
				}
			case "ES512":
				if k.Crv != "P-521" {
					continue
				}
			default:
				continue
			}
			pk, err := ecdsaKey(k.Crv, k.X, k.Y)
			if err != nil {
				return nil, fmt.Errorf("ec kid=%s: %w", k.Kid, err)
			}
			out[k.Kid] = pk
		default:
			continue // Ignore unsupported key types.
		}
	}
	return out, nil
}

func rsaKey(ns, es string) (*rsa.PublicKey, error) {
	if ns == "" || es == "" {
		return nil, errors.New("missing rsa parameters")
	}
	nb, err := base64.RawURLEncoding.DecodeString(ns)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(es)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	n := new(big.Int).SetBytes(nb)
	e := int(new(big.Int).SetBytes(eb).Int64())
	if e <= 0 {
		return nil, errors.New("invalid exponent")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

func ecdsaKey(crv, xs, ys string) (*ecdsa.PublicKey, error) {
	if crv == "" || xs == "" || ys == "" {
		return nil, errors.New("missing ec parameters")
	}
	xb, err := base64.RawURLEncoding.DecodeString(xs)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(ys)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve %q", crv)
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
