// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/jamesonarnett/idpdoctor/internal/cert"
)

// Key-source errors.
var (
	ErrNoKeys      = errors.New("jwt: no verification keys supplied")
	ErrJWKSFetch   = errors.New("jwt: JWKS fetch failed")
	ErrJWKSInvalid = errors.New("jwt: JWKS document invalid")
	ErrPEMInvalid  = errors.New("jwt: PEM key invalid")
)

// maxJWKS bounds a fetched document; real JWKS are a few KB.
const maxJWKS = 1 << 20

// Keys says where verification keys come from. Exactly as in the MCP
// schema: jwks_json (inline), jwks_url (fetched only because the caller
// asked), or pem (a public key or certificate).
type Keys struct {
	JWKSJSON string `json:"jwks_json,omitempty" jsonschema:"a JWKS document as a JSON string"`
	JWKSURL  string `json:"jwks_url,omitempty" jsonschema:"URL to fetch the JWKS from; the only network call the tool makes"`
	PEM      string `json:"pem,omitempty" jsonschema:"a PEM public key or certificate"`
}

// Empty reports whether no key source was given.
func (k Keys) Empty() bool { return k.JWKSJSON == "" && k.JWKSURL == "" && k.PEM == "" }

// jwk is the subset of RFC 7517 needed to rebuild RSA and EC public keys.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// keyEntry is one usable verification key.
type keyEntry struct {
	KID string
	Use string
	Alg string
	Key crypto.PublicKey
}

// keySet is the resolved key material plus how it was obtained.
type keySet struct {
	Entries []keyEntry
	Source  string // "jwks_json" | "jwks_url" | "pem"
	// FetchStatus is the HTTP status when Source is jwks_url.
	FetchStatus int
}

func (s *keySet) kids() []string {
	out := make([]string, 0, len(s.Entries))
	for _, e := range s.Entries {
		if e.KID != "" {
			out = append(out, e.KID)
		}
	}
	return out
}

// resolveKeys loads keys from whichever source is set. client is used only
// for jwks_url; tests pass an httptest client.
func resolveKeys(ctx context.Context, k Keys, client *http.Client) (*keySet, error) {
	switch {
	case k.PEM != "":
		pub, err := parsePEMPublicKey(k.PEM)
		if err != nil {
			return nil, err
		}
		return &keySet{Entries: []keyEntry{{Key: pub}}, Source: "pem"}, nil
	case k.JWKSJSON != "":
		entries, err := parseJWKS([]byte(k.JWKSJSON))
		if err != nil {
			return nil, err
		}
		return &keySet{Entries: entries, Source: "jwks_json"}, nil
	case k.JWKSURL != "":
		body, status, err := fetchJWKS(ctx, client, k.JWKSURL)
		if err != nil {
			return &keySet{Source: "jwks_url", FetchStatus: status}, err
		}
		entries, err := parseJWKS(body)
		if err != nil {
			return &keySet{Source: "jwks_url", FetchStatus: status}, err
		}
		return &keySet{Entries: entries, Source: "jwks_url", FetchStatus: status}, nil
	}
	return nil, ErrNoKeys
}

func fetchJWKS(ctx context.Context, client *http.Client, url string) ([]byte, int, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKS))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("%w: read body: %v", ErrJWKSFetch, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("%w: HTTP %d", ErrJWKSFetch, resp.StatusCode)
	}
	return body, resp.StatusCode, nil
}

// parseJWKS accepts a full JWKS ({"keys":[...]}) or a single JWK object.
func parseJWKS(body []byte) ([]keyEntry, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrJWKSInvalid, err)
	}
	if set.Keys == nil {
		var single jwk
		if err := json.Unmarshal(body, &single); err != nil || single.Kty == "" {
			return nil, fmt.Errorf("%w: no keys array", ErrJWKSInvalid)
		}
		set.Keys = []jwk{single}
	}
	var out []keyEntry
	for _, k := range set.Keys {
		pub, err := k.publicKey()
		if err != nil {
			// Skip keys we cannot use (oct, unknown curves) rather than fail the set.
			continue
		}
		out = append(out, keyEntry{KID: k.Kid, Use: k.Use, Alg: k.Alg, Key: pub})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no usable RSA/EC keys", ErrJWKSInvalid)
	}
	return out, nil
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64url(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64url(k.E)
		if err != nil {
			return nil, err
		}
		if len(n) == 0 || len(e) == 0 || len(e) > 8 {
			return nil, fmt.Errorf("bad RSA parameters")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err := b64url(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64url(k.Y)
		if err != nil {
			return nil, err
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !curve.IsOnCurve(pub.X, pub.Y) {
			return nil, fmt.Errorf("EC point not on curve")
		}
		return pub, nil
	}
	return nil, fmt.Errorf("unsupported kty %q", k.Kty)
}

func b64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// parsePEMPublicKey accepts a PUBLIC KEY (PKIX), RSA PUBLIC KEY (PKCS1) or
// CERTIFICATE block.
func parsePEMPublicKey(s string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(s)))
	if block == nil {
		// Maybe a bare base64 certificate as found in metadata.
		if c, err := cert.Parse(s); err == nil {
			return c.PublicKey, nil
		}
		return nil, fmt.Errorf("%w: no PEM block", ErrPEMInvalid)
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPEMInvalid, err)
		}
		return pub, nil
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPEMInvalid, err)
		}
		return pub, nil
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPEMInvalid, err)
		}
		return c.PublicKey, nil
	}
	return nil, fmt.Errorf("%w: unsupported block %q", ErrPEMInvalid, block.Type)
}
