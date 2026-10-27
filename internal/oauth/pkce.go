// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/redact"
)

// RFC 7636 4.1 verifier length bounds.
const (
	minVerifierLen = 43
	maxVerifierLen = 128
)

// S256 is the RFC 7636 4.2 transform: BASE64URL-ENCODE(SHA256(ASCII(verifier)))
// without padding.
func S256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// unreserved reports whether every byte is in RFC 7636's verifier alphabet
// [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~".
func unreserved(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

// checkPKCE compares the verifier the client sent at the token endpoint with
// the challenge it sent at /authorize. Values only ever appear redacted.
func (e *explainer) checkPKCE() {
	v, ch := e.exp.CodeVerifier, e.exp.CodeChallenge
	if v == "" && ch == "" {
		e.add("pkce", finding.CheckSkip, "no PKCE values supplied", "code_verifier")
		return
	}
	var problems []string
	if v != "" {
		if n := len(v); n < minVerifierLen || n > maxVerifierLen {
			problems = append(problems, "verifier length "+strconv.Itoa(n))
			e.r.Add(finding.New(finding.OAuthPKCEVerifierMismatch, finding.Evidence{Path: PathRequestCodeVerifier,
				Actual: "length " + strconv.Itoa(n), Expected: "43..128 characters", Note: "RFC 7636 4.1"}))
		}
		if !unreserved(v) {
			problems = append(problems, "verifier alphabet")
			e.r.Add(finding.New(finding.OAuthPKCEVerifierMismatch, finding.Evidence{Path: PathRequestCodeVerifier,
				Actual: "contains characters outside the unreserved set", Expected: "[A-Z a-z 0-9 - . _ ~]", Note: "RFC 7636 4.1"}))
		}
	}
	switch {
	case v == "":
		e.finishPKCE(problems, "code_verifier", "challenge supplied but no verifier to compare it with")
		return
	case ch == "":
		e.finishPKCE(problems, "code_challenge", "verifier supplied but no challenge to compare it with")
		return
	}
	if p := e.compareChallenge(v, ch); p != "" {
		problems = append(problems, p)
	}
	e.finishPKCE(problems, "", "verifier matches challenge ("+e.method()+")")
}

// method is the effective code_challenge_method: RFC 7636 4.3 defaults an
// absent method to plain.
func (e *explainer) method() string {
	if e.exp.CodeChallengeMethod == "" {
		return "plain"
	}
	return e.exp.CodeChallengeMethod
}

// compareChallenge applies the declared method and, on mismatch, checks the
// other method too: a match under the wrong one is the method-mismatch bug
// (library defaulted to plain, or the verifier was sent as the challenge).
func (e *explainer) compareChallenge(v, ch string) string {
	red := func(s string) string { return redact.Value("code_challenge", s) }
	switch e.method() {
	case "S256":
		if S256(v) == ch {
			return ""
		}
		note := "BASE64URL(SHA256(code_verifier)) != code_challenge: the verifier sent to the token endpoint is not the one this challenge was derived from"
		if v == ch {
			note = "method mismatch: code_challenge equals the raw verifier (plain) but code_challenge_method says S256"
		}
		e.r.Add(finding.New(finding.OAuthPKCEVerifierMismatch,
			finding.Evidence{Path: PathRequestCodeVerifier, Actual: red(S256(v)), Expected: red(ch), Note: note},
			finding.Evidence{Path: PathRequestCodeChallengeMethod, Actual: "S256"}))
		return "S256 mismatch"
	case "plain":
		if v == ch {
			return ""
		}
		note, wantMethod := "plain method: code_verifier must equal code_challenge byte for byte", ""
		if S256(v) == ch {
			note = "method mismatch: code_challenge is the S256 of the verifier but code_challenge_method is plain (or absent, which defaults to plain)"
			wantMethod = "S256"
		}
		e.r.Add(finding.New(finding.OAuthPKCEVerifierMismatch,
			finding.Evidence{Path: PathRequestCodeVerifier, Actual: redact.Value("code_verifier", v), Expected: red(ch), Note: note},
			finding.Evidence{Path: PathRequestCodeChallengeMethod, Actual: e.method(), Expected: wantMethod}))
		return "plain mismatch"
	}
	e.r.Add(finding.New(finding.OAuthPKCEVerifierMismatch, finding.Evidence{Path: PathRequestCodeChallengeMethod,
		Actual: e.exp.CodeChallengeMethod, Expected: "S256 or plain", Note: "RFC 7636 4.3 defines only S256 and plain"}))
	return "unknown method " + e.exp.CodeChallengeMethod
}

// finishPKCE records the pkce check outcome.
func (e *explainer) finishPKCE(problems []string, needs, okDetail string) {
	switch {
	case len(problems) > 0:
		e.add("pkce", finding.CheckFail, strings.Join(problems, "; "), "")
	case needs != "":
		e.add("pkce", finding.CheckSkip, okDetail, needs)
	default:
		e.add("pkce", finding.CheckPass, okDetail, "")
	}
}

// checkPKCEPosture is the posture lane: a public client must use S256. It
// fires on a successful flow too; that is the point of the lane.
func (e *explainer) checkPKCEPosture() {
	switch e.exp.ClientType {
	case "":
		e.add("pkce_posture", finding.CheckSkip, "client type unknown", "client_type")
		return
	case "confidential":
		e.add("pkce_posture", finding.CheckPass, "confidential client (PKCE still recommended)", "")
		return
	case "public":
	default:
		e.add("pkce_posture", finding.CheckSkip, "unrecognised client_type "+e.exp.ClientType, "")
		return
	}
	hasPKCE := e.exp.CodeChallenge != "" || e.exp.CodeVerifier != "" || e.exp.CodeChallengeMethod != ""
	switch {
	case hasPKCE && e.method() == "plain":
		e.add("pkce_posture", finding.CheckWarn, "public client using plain PKCE", "")
		e.r.Add(finding.New(finding.PosturePKCEPlainOrAbsent, finding.Evidence{Path: PathRequestCodeChallengeMethod,
			Actual: e.method(), Expected: "S256", Note: "plain sends the verifier itself as the challenge, so an intercepted authorization request defeats PKCE"}))
	case !hasPKCE && e.codeFlow():
		e.add("pkce_posture", finding.CheckWarn, "public client without PKCE", "")
		e.r.Add(finding.New(finding.PosturePKCEPlainOrAbsent, finding.Evidence{Path: PathRequestCodeChallenge,
			Actual: "", Expected: "an S256 code_challenge", Note: "a public client has no secret, so without PKCE an intercepted code can be redeemed by anyone"}))
	case !hasPKCE:
		e.add("pkce_posture", finding.CheckPass, "not a code flow", "")
	default:
		e.add("pkce_posture", finding.CheckPass, "public client uses S256", "")
	}
}

// codeFlow reports whether the request was an authorization-code flow:
// response_type contains code, or (unstated) the artifact carries a code.
func (e *explainer) codeFlow() bool {
	if e.exp.ResponseType == "" {
		return e.s.HasCode
	}
	for _, f := range strings.Fields(e.exp.ResponseType) {
		if f == "code" {
			return true
		}
	}
	return false
}
