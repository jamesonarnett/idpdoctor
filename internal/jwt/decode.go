// SPDX-License-Identifier: Apache-2.0

// Package jwt decodes and validates JWTs (OIDC id_tokens and OAuth access
// tokens) against a JWKS or PEM key, reporting every failing claim rather
// than the first. golang-jwt does parsing and signature verification; claim
// checks are explicit here so each one yields its own evidence.
package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/redact"
)

// ErrMalformed wraps golang-jwt's malformed-token errors.
var ErrMalformed = errors.New("jwt: malformed token")

// Claims is a decoded claim set whose JSON form is always redacted. Values
// stay intact in memory for server-side comparison.
type Claims map[string]any

// MarshalJSON masks PII-class claims (see redact.Claims).
func (c Claims) MarshalJSON() ([]byte, error) {
	return json.Marshal(redact.Claims(map[string]any(c)))
}

// Decoded is the jwt_decode output.
type Decoded struct {
	Header map[string]any `json:"header"`
	Claims Claims         `json:"claims"`
	// KindGuess is id_token, access_token or unknown, from claim shape.
	KindGuess string `json:"kind_guess"`
	// ExpInSeconds is exp - now; negative means expired. 0 when exp absent.
	ExpInSeconds int64             `json:"exp_in_seconds"`
	Alg          string            `json:"alg"`
	KID          string            `json:"kid,omitempty"`
	Findings     []finding.Finding `json:"findings"`
	// raw is the compact token, kept for Validate; never serialised.
	raw string
}

// Decode parses without verifying and reports header-level red flags
// (alg none, jku/jwk/x5u, suspicious kid). It never touches the network.
func Decode(token string, now time.Time) (*Decoded, error) {
	token = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(token), "Bearer "))
	parser := gojwt.NewParser()
	claims := gojwt.MapClaims{}
	tok, _, err := parser.ParseUnverified(token, claims)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	d := &Decoded{
		Header:   tok.Header,
		Claims:   Claims(claims),
		Findings: []finding.Finding{},
		raw:      token,
	}
	d.Alg, _ = tok.Header["alg"].(string)
	d.KID, _ = tok.Header["kid"].(string)
	d.KindGuess = guessKind(claims)
	if exp, ok := numericClaim(claims, "exp"); ok {
		d.ExpInSeconds = exp - now.Unix()
	}
	d.Findings = append(d.Findings, headerFindings(tok.Header)...)
	return d, nil
}

// Raw returns the compact token for Validate.
func (d *Decoded) Raw() string { return d.raw }

// headerFindings are the RFC 8725 red flags visible without any key.
func headerFindings(h map[string]any) []finding.Finding {
	var out []finding.Finding
	alg, _ := h["alg"].(string)
	if strings.EqualFold(alg, "none") || alg == "" {
		out = append(out, finding.New(finding.JWTAlgNoneOrConfusion, finding.Evidence{
			Path: "/header/alg", Actual: alg, Expected: "an asymmetric algorithm such as RS256", Note: "unsigned token",
		}))
	}
	for _, k := range []string{"jku", "jwk", "x5u", "x5c"} {
		if _, ok := h[k]; ok {
			note := "header lets the token nominate its own key; an SP must ignore it and use the OP's configured JWKS"
			f := finding.New(finding.JWTAlgNoneOrConfusion, finding.Evidence{Path: "/header/" + k, Actual: "present", Note: note})
			if k == "x5c" {
				// x5c is legitimate from some OPs; flag softly.
				f.Severity = finding.SeverityWarn
				f.Confidence = 0.6
			}
			out = append(out, f)
		}
	}
	if kid, _ := h["kid"].(string); strings.ContainsAny(kid, "/\\'\"` ;") || strings.Contains(kid, "..") {
		out = append(out, finding.New(finding.JWTAlgNoneOrConfusion, finding.Evidence{
			Path: "/header/kid", Actual: redact.Value("kid", kid), Note: "kid contains path or quote characters (injection probe)",
		}))
	}
	return out
}

// guessKind is a heuristic: id_tokens carry nonce/at_hash/auth_time and a
// client_id audience; access tokens carry scp/scope/roles and resource auds.
func guessKind(c gojwt.MapClaims) string {
	for _, k := range []string{"nonce", "at_hash", "c_hash", "auth_time"} {
		if _, ok := c[k]; ok {
			return "id_token"
		}
	}
	for _, k := range []string{"scp", "scope", "roles", "client_id", "cnf"} {
		if _, ok := c[k]; ok {
			return "access_token"
		}
	}
	if typ, _ := c["typ"].(string); strings.EqualFold(typ, "at+jwt") {
		return "access_token"
	}
	return "unknown"
}

// numericClaim reads a NumericDate-ish claim as integer seconds.
func numericClaim(c gojwt.MapClaims, name string) (int64, bool) {
	switch v := c[name].(type) {
	case float64:
		return int64(v), true
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i, true
		}
		if f, err := v.Float64(); err == nil {
			return int64(f), true
		}
	case int64:
		return v, true
	}
	return 0, false
}

// audiences normalises aud (string or array) to a slice.
func audiences(c gojwt.MapClaims) []string {
	switch v := c["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}
