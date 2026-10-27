// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// JWTParams describes a healthy id_token.
type JWTParams struct {
	Issuer   string
	Audience string
	Subject  string
	Email    string
	Nonce    string
	KID      string
	Now      time.Time
	TTL      time.Duration
	// Alg is RS256 unless a mutator changes it ("none", "HS256").
	Alg string
	// AccessToken, when set, adds a matching at_hash claim; the at_hash
	// mutator then breaks the match.
	AccessToken string
	// ExtraHeader lets a mutator inject jwk/jku/x5u.
	ExtraHeader map[string]any
}

// DefaultJWTParams is the healthy baseline.
func DefaultJWTParams() JWTParams {
	return JWTParams{
		Issuer:   "https://login.example.com/tenant-1/v2.0",
		Audience: "client-abc123",
		Subject:  "user-00000000-1111-2222-3333-444444444444",
		Email:    "alice@example.com",
		Nonce:    "n-0S6_WzA2Mj",
		KID:      "test-key-1",
		Now:      FixedNow,
		TTL:      time.Hour,
		Alg:      "RS256",
	}
}

// Claims builds the claim set for p.
func (p JWTParams) Claims() jwt.MapClaims {
	c := jwt.MapClaims{
		"iss":   p.Issuer,
		"aud":   p.Audience,
		"sub":   p.Subject,
		"email": p.Email,
		"nonce": p.Nonce,
		"iat":   p.Now.Unix(),
		"nbf":   p.Now.Unix(),
		"exp":   p.Now.Add(p.TTL).Unix(),
	}
	if p.AccessToken != "" {
		c["at_hash"] = AtHash256(p.AccessToken)
	}
	return c
}

// AtHash256 is the OIDC at_hash for an RS256/ES256 token: base64url of the
// left 16 bytes of SHA-256(access_token). Kept local so fixture does not
// import the validator it exists to test.
func AtHash256(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// JWTMutator edits the claims/header/params before signing.
type JWTMutator struct {
	Name  string
	Code  finding.Code
	Apply func(c jwt.MapClaims, p *JWTParams) Label
}

var jwtMutators = map[string]JWTMutator{}

func registerJWT(m JWTMutator) { jwtMutators[m.Name] = m }

// JWTMutatorByName looks up a JWT mutator.
func JWTMutatorByName(name string) (JWTMutator, bool) {
	m, ok := jwtMutators[name]
	return m, ok
}

// JWTMutators returns every JWT mutator in name order.
func JWTMutators() []JWTMutator {
	out := make([]JWTMutator, 0, len(jwtMutators))
	for _, m := range jwtMutators {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// MintJWT signs a token for p with key, applying mutators first. For alg
// none it emits header.payload. (empty signature); for HS256 it signs with
// the PEM public key bytes as the secret, the classic confusion attack.
func MintJWT(p JWTParams, key *rsa.PrivateKey, muts ...JWTMutator) (string, []Label, error) {
	tok, labels, _, err := MintJWTFull(p, key, muts...)
	return tok, labels, err
}

// MintJWTFull is MintJWT plus the effective params: mutators may change
// them (alg, kid, the access token behind at_hash) and a caller building
// the matching Expected needs the final values.
func MintJWTFull(p JWTParams, key *rsa.PrivateKey, muts ...JWTMutator) (string, []Label, JWTParams, error) {
	claims := p.Claims()
	var labels []Label
	for _, m := range muts {
		labels = append(labels, m.Apply(claims, &p))
	}
	var tok *jwt.Token
	var signed string
	var err error
	switch p.Alg {
	case "none":
		tok = jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		setHeader(tok, p)
		signed, err = tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	case "HS256":
		tok = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		setHeader(tok, p)
		pub := (&Keys{Key: key}).publicPEM()
		signed, err = tok.SignedString([]byte(pub))
	default:
		tok = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		setHeader(tok, p)
		signed, err = tok.SignedString(key)
	}
	if err != nil {
		return "", nil, p, err
	}
	return signed, labels, p, nil
}

func setHeader(tok *jwt.Token, p JWTParams) {
	if p.KID != "" {
		tok.Header["kid"] = p.KID
	}
	for k, v := range p.ExtraHeader {
		tok.Header[k] = v
	}
}

// publicPEM renders the public key in SPKI PEM form.
func (k *Keys) publicPEM() string {
	der, err := marshalPKIX(&k.Key.PublicKey)
	if err != nil {
		return ""
	}
	return "-----BEGIN PUBLIC KEY-----\n" + base64.StdEncoding.EncodeToString(der) + "\n-----END PUBLIC KEY-----\n"
}

// JWK is the subset of RFC 7517 an RSA signing key needs.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSet is a JWKS document.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// RSAJWK converts a public key to a JWK.
func RSAJWK(kid string, pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA", Use: "sig", Kid: kid, Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// JWKS renders a JWKS JSON document for the given keys.
func JWKS(keys ...JWK) string {
	b, _ := json.Marshal(JWKSet{Keys: keys})
	return string(b)
}

// JWKSHandler serves a fixed JWKS body with the given status, for httptest.
func JWKSHandler(body string, status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

func init() {
	registerJWT(JWTMutator{Name: "jwt_expired", Code: finding.JWTExpiredOrNotYetValid,
		Apply: func(c jwt.MapClaims, p *JWTParams) Label {
			c["iat"] = p.Now.Add(-2 * time.Hour).Unix()
			c["nbf"] = p.Now.Add(-2 * time.Hour).Unix()
			c["exp"] = p.Now.Add(-time.Hour).Unix()
			return Label{Code: finding.JWTExpiredOrNotYetValid, Path: "/claims/exp"}
		}})
	registerJWT(JWTMutator{Name: "jwt_not_yet_valid", Code: finding.JWTExpiredOrNotYetValid,
		Apply: func(c jwt.MapClaims, p *JWTParams) Label {
			c["nbf"] = p.Now.Add(10 * time.Minute).Unix()
			return Label{Code: finding.JWTExpiredOrNotYetValid, Path: "/claims/nbf"}
		}})
	registerJWT(JWTMutator{Name: "jwt_aud_mismatch", Code: finding.JWTAudOrAzpMismatch,
		Apply: func(c jwt.MapClaims, p *JWTParams) Label {
			c["aud"] = "api://some-other-client"
			return Label{Code: finding.JWTAudOrAzpMismatch, Path: "/claims/aud", Needs: []string{"client_id"}}
		}})
	registerJWT(JWTMutator{Name: "jwt_multi_aud_no_azp", Code: finding.JWTAudOrAzpMismatch,
		Apply: func(c jwt.MapClaims, p *JWTParams) Label {
			c["aud"] = []string{p.Audience, "api://second"}
			return Label{Code: finding.JWTAudOrAzpMismatch, Path: "/claims/azp", Needs: []string{"client_id"}}
		}})
	registerJWT(JWTMutator{Name: "jwt_iss_mismatch", Code: finding.OIDCIssuerMismatch,
		Apply: func(c jwt.MapClaims, p *JWTParams) Label {
			// Entra v1 vs v2 endpoint: the single most common OIDC issuer ticket.
			c["iss"] = strings.TrimSuffix(p.Issuer, "/v2.0") + "/"
			return Label{Code: finding.OIDCIssuerMismatch, Path: "/claims/iss", Needs: []string{"issuer"}}
		}})
	registerJWT(JWTMutator{Name: "jwt_kid_unknown", Code: finding.JWTKidNotFoundInJWKS,
		Apply: func(c jwt.MapClaims, p *JWTParams) Label {
			p.KID = "rotated-key-9"
			return Label{Code: finding.JWTKidNotFoundInJWKS, Path: "/header/kid"}
		}})
	registerJWT(JWTMutator{Name: "jwt_alg_none", Code: finding.JWTAlgNoneOrConfusion,
		Apply: func(c jwt.MapClaims, p *JWTParams) Label {
			p.Alg = "none"
			return Label{Code: finding.JWTAlgNoneOrConfusion, Path: "/header/alg"}
		}})
	registerJWT(JWTMutator{Name: "jwt_hs256_confusion", Code: finding.JWTAlgNoneOrConfusion,
		Apply: func(c jwt.MapClaims, p *JWTParams) Label {
			p.Alg = "HS256"
			return Label{Code: finding.JWTAlgNoneOrConfusion, Path: "/header/alg"}
		}})
	registerJWT(JWTMutator{Name: "jwt_nonce_mismatch", Code: finding.OIDCRequestBindingMismatch,
		Apply: func(c jwt.MapClaims, p *JWTParams) Label {
			// A stale tab replays an older authorization: the session nonce
			// no longer matches the one baked into the id_token.
			c["nonce"] = "n-stale-from-older-request"
			return Label{Code: finding.OIDCRequestBindingMismatch, Path: "/claims/nonce", Needs: []string{"nonce"}}
		}})
	registerJWT(JWTMutator{Name: "jwt_at_hash_mismatch", Code: finding.OIDCRequestBindingMismatch,
		Apply: func(c jwt.MapClaims, p *JWTParams) Label {
			// The id_token was issued with a different access token than the
			// one the client presents (mixed-up responses).
			p.AccessToken = "access-token-secret-presented"
			c["at_hash"] = AtHash256("access-token-secret-issued-with-the-id-token")
			return Label{Code: finding.OIDCRequestBindingMismatch, Path: "/claims/at_hash", Needs: []string{"access_token"}}
		}})
	registerJWT(JWTMutator{Name: "jwt_jku_header", Code: finding.JWTAlgNoneOrConfusion,
		Apply: func(c jwt.MapClaims, p *JWTParams) Label {
			p.ExtraHeader = map[string]any{"jku": "https://attacker.example/jwks.json"}
			return Label{Code: finding.JWTAlgNoneOrConfusion, Path: "/header/jku"}
		}})
}
