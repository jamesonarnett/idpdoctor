// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"strings"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/redact"
)

// ArtifactKind is the Report label for JWTs.
const ArtifactKind = "jwt"

// DefaultAllowedAlgs is the asymmetric allow-list used when expected does
// not name one. HS* is deliberately absent: an OP-issued id_token verified
// with a shared secret is the key-confusion attack.
var DefaultAllowedAlgs = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

const maxIDTokenLifetime = time.Hour

// Options carries the non-expected inputs to Validate.
type Options struct {
	Keys   Keys
	Client *http.Client // used only for Keys.JWKSURL; nil means a default 10s client
}

// Result is the jwt_validate output: the decode view plus the report.
type Result struct {
	*Decoded
	Report *finding.Report
}

type validator struct {
	ctx  context.Context
	d    *Decoded
	exp  expected.Expected
	opts Options
	now  time.Time
	skew time.Duration
	r    *finding.Report
}

// Validate runs every check against an already-decoded token.
func Validate(ctx context.Context, d *Decoded, exp expected.Expected, opts Options, now time.Time) (*Result, error) {
	effective, err := exp.NowOr(now)
	if err != nil {
		return nil, err
	}
	v := &validator{ctx: ctx, d: d, exp: exp, opts: opts, now: effective, skew: exp.Skew(), r: finding.NewReport(ArtifactKind)}
	for _, f := range d.Findings {
		v.r.Add(f)
	}
	allowed := v.checkAlg()
	v.checkSignature(allowed)
	v.checkIssuer()
	v.checkAudience()
	v.checkTimes()
	v.checkNonce()
	v.checkAtHash()
	finding.Sort(v.r.Findings)
	return &Result{Decoded: d, Report: v.r}, nil
}

func (v *validator) add(name string, st finding.CheckStatus, detail, needs string) {
	v.r.AddCheck(finding.Check{Name: name, Status: st, Detail: detail, Needs: needs})
}

func (v *validator) claims() gojwt.MapClaims { return gojwt.MapClaims(v.d.Claims) }

// --- alg ----------------------------------------------------------------------

func (v *validator) checkAlg() []string {
	allowed := v.exp.AllowedAlgs
	if len(allowed) == 0 {
		allowed = DefaultAllowedAlgs
	}
	alg := v.d.Alg
	switch {
	case alg == "" || strings.EqualFold(alg, "none"):
		v.add("alg_allowed", finding.CheckFail, "alg is none", "")
		return allowed // finding already added by Decode
	case strings.HasPrefix(alg, "HS") && !v.opts.Keys.Empty() && v.opts.Keys.PEM == "":
		// JWKS keys are public; an HMAC token "verified" with one is confusion.
		v.add("alg_allowed", finding.CheckFail, alg+" (symmetric) against a public-key source", "")
		v.r.Add(finding.New(finding.JWTAlgNoneOrConfusion, finding.Evidence{Path: "/header/alg", Actual: alg, Expected: strings.Join(allowed, " "), Note: "HMAC algorithm presented to an SP holding only public keys (RS/HS confusion)"}))
	case !contains(allowed, alg):
		v.add("alg_allowed", finding.CheckFail, alg+" not in allow-list", "")
		v.r.Add(finding.New(finding.JWTAlgNoneOrConfusion, finding.Evidence{Path: "/header/alg", Actual: alg, Expected: strings.Join(allowed, " ")}))
	default:
		v.add("alg_allowed", finding.CheckPass, alg, "")
		if strings.HasPrefix(alg, "HS") {
			v.r.Add(finding.New(finding.PostureWeakAlgorithm, finding.Evidence{Path: "/header/alg", Actual: alg, Expected: "RS256 / ES256", Note: "symmetric id_token signing: every verifier holds the signing key"}))
		}
	}
	return allowed
}

// --- signature ----------------------------------------------------------------

func (v *validator) checkSignature(allowed []string) {
	if v.opts.Keys.Empty() {
		v.add("kid_found", finding.CheckSkip, "no keys supplied", "jwks_url")
		v.add("signature", finding.CheckSkip, "no keys supplied", "jwks_url")
		return
	}
	set, err := resolveKeys(v.ctx, v.opts.Keys, v.opts.Client)
	if err != nil {
		detail := err.Error()
		v.add("kid_found", finding.CheckFail, detail, "")
		v.add("signature", finding.CheckFail, "keys unavailable", "")
		ev := finding.Evidence{Path: "/keys/" + sourceName(v.opts.Keys), Actual: detail}
		if set != nil && set.FetchStatus != 0 {
			ev.Actual = fmt.Sprintf("HTTP %d", set.FetchStatus)
		}
		switch {
		case errors.Is(err, ErrPEMInvalid):
			v.r.Add(finding.New(finding.CertExpiredOrWeak, ev))
		default:
			v.r.Add(finding.New(finding.JWTKidNotFoundInJWKS, ev))
		}
		return
	}

	key, detail := selectKey(set, v.d.KID)
	if key == nil {
		v.add("kid_found", finding.CheckFail, detail, "")
		v.add("signature", finding.CheckSkip, "no key to verify with", "")
		v.r.Add(finding.New(finding.JWTKidNotFoundInJWKS, finding.Evidence{Path: "/header/kid", Actual: v.d.KID, Expected: "one of: " + strings.Join(set.kids(), ", "), Note: detail}))
		return
	}
	v.add("kid_found", finding.CheckPass, detail, "")

	if strings.EqualFold(v.d.Alg, "none") || v.d.Alg == "" {
		v.add("signature", finding.CheckFail, "unsigned token", "")
		return
	}
	_, err = gojwt.NewParser(gojwt.WithValidMethods(allowed), gojwt.WithoutClaimsValidation()).
		ParseWithClaims(v.d.raw, gojwt.MapClaims{}, func(*gojwt.Token) (any, error) { return key, nil })
	switch {
	case err == nil:
		v.add("signature", finding.CheckPass, "verified with "+set.Source+keyDesc(key), "")
	case errors.Is(err, gojwt.ErrTokenSignatureInvalid):
		v.add("signature", finding.CheckFail, "signature does not verify", "")
		f := finding.New(finding.JWTKidNotFoundInJWKS, finding.Evidence{Path: "/signature", Actual: "invalid for key " + orNoKid(v.d.KID), Expected: "verifies with " + set.Source, Note: "kid matched but the signature does not verify: stale JWKS cache, token from another tenant, or tampered"})
		f.Title = "Signature does not verify with the JWKS key for this kid"
		v.r.Add(f)
	case errors.Is(err, gojwt.ErrTokenUnverifiable), errors.Is(err, gojwt.ErrInvalidKeyType):
		v.add("signature", finding.CheckFail, "key type does not match alg", "")
		v.r.Add(finding.New(finding.JWTAlgNoneOrConfusion, finding.Evidence{Path: "/header/alg", Actual: v.d.Alg, Note: "key type does not match the algorithm (" + err.Error() + ")"}))
	default:
		v.add("signature", finding.CheckFail, err.Error(), "")
		v.r.Add(finding.New(finding.JWTKidNotFoundInJWKS, finding.Evidence{Path: "/signature", Actual: err.Error()}))
	}
}

// selectKey picks the key for kid; with no kid and exactly one key it uses
// that (a common single-key OP), otherwise it refuses to guess.
func selectKey(set *keySet, kid string) (any, string) {
	if len(set.Entries) == 1 && set.Entries[0].KID == "" {
		// A PEM key (or a kid-less JWKS entry): nothing to match against.
		return set.Entries[0].Key, "single key from " + set.Source + " (no kid to match)"
	}
	if kid == "" {
		if len(set.Entries) == 1 {
			return set.Entries[0].Key, "no kid; single key in " + set.Source
		}
		return nil, fmt.Sprintf("no kid and %d candidate keys; cannot choose", len(set.Entries))
	}
	for _, e := range set.Entries {
		if e.KID == kid {
			if e.Use != "" && e.Use != "sig" {
				return nil, "kid found but use=" + e.Use + " (not a signing key)"
			}
			return e.Key, "kid " + kid + " found in " + set.Source
		}
	}
	return nil, "kid " + kid + " not present (keys rotated or wrong tenant)"
}

func keyDesc(k any) string {
	switch t := k.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf(" (RSA %d)", t.N.BitLen())
	case *ecdsa.PublicKey:
		return " (" + t.Curve.Params().Name + ")"
	}
	return ""
}

func sourceName(k Keys) string {
	switch {
	case k.JWKSURL != "":
		return "jwks_url"
	case k.JWKSJSON != "":
		return "jwks_json"
	}
	return "pem"
}

func orNoKid(kid string) string {
	if kid == "" {
		return "(no kid)"
	}
	return kid
}

// --- iss / aud / azp --------------------------------------------------------------

func (v *validator) checkIssuer() {
	got, _ := v.claims()["iss"].(string)
	want := v.exp.Issuer
	if want == "" {
		v.add("iss", finding.CheckSkip, "iss is "+got, "issuer")
		return
	}
	if got == want {
		v.add("iss", finding.CheckPass, "matches issuer", "")
		return
	}
	v.add("iss", finding.CheckFail, "does not match issuer", "")
	v.r.Add(finding.New(finding.OIDCIssuerMismatch, finding.Evidence{Path: "/claims/iss", Actual: got, Expected: want, Note: issuerNote(got, want)}))
}

func issuerNote(got, want string) string {
	switch {
	case strings.TrimSuffix(got, "/") == strings.TrimSuffix(want, "/"):
		return "differs only by trailing slash"
	case strings.Contains(got, "sts.windows.net") && strings.Contains(want, "login.microsoftonline.com"),
		strings.Contains(want, "sts.windows.net") && strings.Contains(got, "login.microsoftonline.com"):
		return "Entra v1 (sts.windows.net) vs v2 (login.microsoftonline.com/.../v2.0) issuer: request tokens from the endpoint version the SP is configured for"
	case strings.Contains(got, "{tenantid}") || strings.Contains(want, "{tenantid}"):
		return "unresolved {tenantid} placeholder"
	case strings.EqualFold(got, want):
		return "differs only by case"
	}
	return ""
}

func (v *validator) checkAudience() {
	want := v.exp.Audience
	if want == "" {
		want = v.exp.ClientID
	}
	auds := audiences(v.claims())
	azp, _ := v.claims()["azp"].(string)
	if want == "" {
		v.add("aud", finding.CheckSkip, "aud is "+strings.Join(auds, ", "), "client_id")
		v.add("azp", finding.CheckSkip, "azp is "+orAbsent(azp), "client_id")
		return
	}
	if !contains(auds, want) {
		v.add("aud", finding.CheckFail, "does not contain client_id", "")
		v.r.Add(finding.New(finding.JWTAudOrAzpMismatch, finding.Evidence{Path: "/claims/aud", Actual: strings.Join(auds, ", "), Expected: want, Note: audNote(auds, v.d.KindGuess)}))
	} else {
		v.add("aud", finding.CheckPass, "contains client_id", "")
	}
	// OIDC Core 3.1.3.7 rules 4 and 5.
	switch {
	case len(auds) > 1 && azp == "":
		v.add("azp", finding.CheckFail, "multiple audiences but no azp", "")
		v.r.Add(finding.New(finding.JWTAudOrAzpMismatch, finding.Evidence{Path: "/claims/azp", Actual: "", Expected: want, Note: "OIDC Core 3.1.3.7: azp is required when aud has more than one value"}))
	case azp != "" && azp != want:
		v.add("azp", finding.CheckFail, "azp is not this client", "")
		v.r.Add(finding.New(finding.JWTAudOrAzpMismatch, finding.Evidence{Path: "/claims/azp", Actual: azp, Expected: want}))
	case azp == "":
		v.add("azp", finding.CheckPass, "absent (single audience)", "")
	default:
		v.add("azp", finding.CheckPass, "matches client_id", "")
	}
}

func audNote(auds []string, kind string) string {
	if kind == "access_token" {
		return "this looks like an access token (scp/roles present); id_token validation must not accept it"
	}
	if len(auds) == 0 {
		return "no aud claim"
	}
	return ""
}

// --- time claims ----------------------------------------------------------------

func (v *validator) checkTimes() {
	c := v.claims()
	nowStr := v.now.UTC().Format(time.RFC3339)
	exp, hasExp := numericClaim(c, "exp")
	nbf, hasNbf := numericClaim(c, "nbf")
	iat, hasIat := numericClaim(c, "iat")

	switch {
	case !hasExp:
		v.add("exp", finding.CheckFail, "absent", "")
		v.r.Add(finding.New(finding.JWTExpiredOrNotYetValid, finding.Evidence{Path: "/claims/exp", Actual: "", Expected: "present", Note: "token without expiry"}))
	case time.Unix(exp, 0).Add(v.skew).Before(v.now) || time.Unix(exp, 0).Add(v.skew).Equal(v.now):
		v.add("exp", finding.CheckFail, "expired", "")
		v.r.Add(finding.New(finding.JWTExpiredOrNotYetValid, finding.Evidence{Path: "/claims/exp", Actual: unixStr(exp), Expected: "> " + nowStr + " - skew " + v.skew.String(), Note: "expired " + v.now.Sub(time.Unix(exp, 0)).Round(time.Second).String() + " ago"}))
	default:
		v.add("exp", finding.CheckPass, "expires in "+time.Unix(exp, 0).Sub(v.now).Round(time.Second).String(), "")
	}

	switch {
	case !hasNbf:
		v.add("nbf", finding.CheckPass, "absent", "")
	case time.Unix(nbf, 0).After(v.now.Add(v.skew)):
		v.add("nbf", finding.CheckFail, "not yet valid", "")
		v.r.Add(finding.New(finding.JWTExpiredOrNotYetValid, finding.Evidence{Path: "/claims/nbf", Actual: unixStr(nbf), Expected: "<= " + nowStr + " + skew " + v.skew.String(), Note: "issuer clock ahead of the SP"}))
	default:
		v.add("nbf", finding.CheckPass, "ok", "")
	}

	switch {
	case !hasIat:
		v.add("iat", finding.CheckWarn, "absent", "")
	case time.Unix(iat, 0).After(v.now.Add(v.skew)):
		v.add("iat", finding.CheckFail, "issued in the future", "")
		v.r.Add(finding.New(finding.JWTExpiredOrNotYetValid, finding.Evidence{Path: "/claims/iat", Actual: unixStr(iat), Expected: "<= " + nowStr + " + skew " + v.skew.String()}))
	default:
		v.add("iat", finding.CheckPass, "ok", "")
	}

	if hasExp && hasIat && v.d.KindGuess == "id_token" {
		if life := time.Unix(exp, 0).Sub(time.Unix(iat, 0)); life > maxIDTokenLifetime {
			v.r.Add(finding.New(finding.PostureValidityWindowTooLong, finding.Evidence{Path: "/claims/exp", Actual: life.String(), Expected: "<= " + maxIDTokenLifetime.String(), Note: "id_token lifetime"}))
		}
	}
}

func unixStr(t int64) string { return time.Unix(t, 0).UTC().Format(time.RFC3339) }

// --- nonce ---------------------------------------------------------------------

func (v *validator) checkNonce() {
	got, _ := v.claims()["nonce"].(string)
	want := v.exp.Nonce
	if want == "" {
		v.add("nonce", finding.CheckSkip, "nonce "+presence(got), "nonce")
		return
	}
	if got == want {
		v.add("nonce", finding.CheckPass, "matches", "")
		return
	}
	v.add("nonce", finding.CheckFail, "does not match the request nonce", "")
	v.r.Add(finding.New(finding.OIDCRequestBindingMismatch, finding.Evidence{Path: "/claims/nonce", Actual: redact.Value("nonce", got), Expected: redact.Value("nonce", want), Note: "nonce " + presence(got)}))
}

// --- at_hash -------------------------------------------------------------------

// checkAtHash binds the id_token to the access token issued with it (OIDC
// Core 3.1.3.6 / 3.2.2.9): at_hash is the left half of hash(access_token)
// where the hash family comes from alg (RS256 -> SHA-256, ES384 -> SHA-384,
// ...). The access token is a bearer credential: it is hashed here and
// never written anywhere.
func (v *validator) checkAtHash() {
	got, _ := v.claims()["at_hash"].(string)
	if v.exp.AccessToken == "" {
		v.add("at_hash", finding.CheckSkip, "at_hash "+presence(got), "access_token")
		return
	}
	want, err := AtHash(v.d.Alg, v.exp.AccessToken)
	if err != nil {
		v.add("at_hash", finding.CheckSkip, err.Error(), "")
		return
	}
	switch {
	case got == "" && strings.Contains(v.exp.ResponseType, "token"):
		// Required when the access token came from the authorization endpoint.
		v.add("at_hash", finding.CheckFail, "absent but response_type includes token", "")
		v.r.Add(finding.New(finding.OIDCRequestBindingMismatch, finding.Evidence{Path: "/claims/at_hash", Actual: "", Expected: "present", Note: "at_hash is REQUIRED for response_type " + v.exp.ResponseType}))
	case got == "":
		v.add("at_hash", finding.CheckWarn, "absent (optional for the code flow)", "")
	case got == want:
		v.add("at_hash", finding.CheckPass, "matches access_token", "")
	default:
		v.add("at_hash", finding.CheckFail, "does not match access_token", "")
		v.r.Add(finding.New(finding.OIDCRequestBindingMismatch, finding.Evidence{
			Path: "/claims/at_hash", Actual: redact.Value("at_hash", got), Expected: redact.Value("at_hash", want),
			Note: "the access token presented is not the one issued with this id_token (different response, or hash family mismatch for " + v.d.Alg + ")",
		}))
	}
}

// AtHash computes the at_hash (or c_hash) value for alg over token.
func AtHash(alg, token string) (string, error) {
	var h hash.Hash
	switch {
	case strings.HasSuffix(alg, "256"):
		h = sha256.New()
	case strings.HasSuffix(alg, "384"):
		h = sha512.New384()
	case strings.HasSuffix(alg, "512"):
		h = sha512.New()
	default:
		return "", fmt.Errorf("no hash family for alg %q", alg)
	}
	h.Write([]byte(token))
	sum := h.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2]), nil
}

func presence(s string) string {
	if s == "" {
		return "absent"
	}
	return "present"
}

func orAbsent(s string) string {
	if s == "" {
		return "absent"
	}
	return s
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
