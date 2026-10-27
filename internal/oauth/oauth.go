// SPDX-License-Identifier: Apache-2.0

// Package oauth explains an OAuth 2.0 / OIDC authorization-code flow
// artifact: the redirect the browser landed on (error or success) or the
// JSON error body the token endpoint returned. It classifies the error into
// one catalog code and, given the request context in expected, runs the
// deterministic checks: exact redirect_uri match (RFC 6749 3.1.2.3), PKCE
// (RFC 7636) and client-type/grant-type compatibility.
//
// The authorization code, PKCE verifier and challenge, and any token are
// bearer secrets: they are reported only through redact.Value.
package oauth

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/redact"
)

// ArtifactKind is the Report label for OAuth redirects and error bodies.
const ArtifactKind = "oauth_redirect"

// Source values for Summary.Source.
const (
	SourceRedirectURL = "redirect_url"
	SourceErrorBody   = "error_body"
)

// ErrUnrecognised reports input that is neither a redirect with error/code
// parameters, a bare query string, nor a JSON error body.
var ErrUnrecognised = errors.New("oauth: not a redirect URL, query string or JSON error body with error or code")

// Summary is the parsed, redacted view of the artifact.
type Summary struct {
	Source           string `json:"source"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	// VendorCode is the vendor's own error number found in the description
	// (AADSTS50011, Okta E0000004).
	VendorCode string `json:"vendor_code,omitempty"`
	Vendor     string `json:"vendor"`
	State      string `json:"state,omitempty"`
	HasCode    bool   `json:"has_code"`
	// CodeRedacted is redact.Value("code", code); the code itself never
	// leaves Parse.
	CodeRedacted string `json:"code,omitempty"`
	RedirectHost string `json:"redirect_host,omitempty"`
	RedirectPath string `json:"redirect_path,omitempty"`
	// Params lists the parameter names present (never their values).
	Params []string `json:"params"`
}

// Result is the oauth_error_explain output.
type Result struct {
	Summary Summary         `json:"summary"`
	Report  *finding.Report `json:"report"`
}

// Parse recognises the three artifact shapes. A redirect carrying code and
// no error is a healthy success redirect, not an error.
func Parse(artifact string) (Summary, error) {
	a := strings.TrimSpace(artifact)
	if strings.HasPrefix(a, "{") {
		return parseJSON(a)
	}
	if u, err := url.Parse(a); err == nil && u.Scheme != "" && (u.Host != "" || u.Opaque != "" || u.Path != "") && (u.RawQuery != "" || u.Fragment != "") {
		params := mergeParams(u.RawQuery, fragmentQuery(u))
		s, err := fromParams(params, SourceRedirectURL)
		if err != nil {
			return Summary{}, err
		}
		s.RedirectHost, s.RedirectPath = u.Host, u.Path
		s.Vendor = detectVendor(s)
		return s, nil
	}
	if strings.Contains(a, "=") {
		// fromParams rejects anything without error or code, so prose
		// containing "=" still comes back ErrUnrecognised.
		params := mergeParams(strings.TrimLeft(a, "?#"), "")
		s, err := fromParams(params, SourceRedirectURL)
		if err != nil {
			return Summary{}, err
		}
		s.Vendor = detectVendor(s)
		return s, nil
	}
	return Summary{}, ErrUnrecognised
}

// fragmentQuery returns the fragment when it looks like form parameters
// (implicit / hybrid / response_mode=fragment), else "".
func fragmentQuery(u *url.URL) string {
	f := u.EscapedFragment()
	if strings.Contains(f, "=") {
		return f
	}
	return ""
}

// mergeParams parses query then fragment; for a key present in both the
// query value wins, since response_mode=query is the code-flow default.
func mergeParams(query, fragment string) url.Values {
	out := url.Values{}
	for _, raw := range []string{query, fragment} {
		vals, _ := url.ParseQuery(raw) // keep what parsed; a stray % should not hide the error
		for k, v := range vals {
			if _, ok := out[k]; !ok {
				out[k] = v
			}
		}
	}
	return out
}

func fromParams(v url.Values, source string) (Summary, error) {
	if !v.Has("error") && !v.Has("code") {
		return Summary{}, ErrUnrecognised
	}
	code := v.Get("code")
	s := Summary{
		Source:           source,
		Error:            v.Get("error"),
		ErrorDescription: scrub(v.Get("error_description")),
		ErrorURI:         v.Get("error_uri"),
		State:            v.Get("state"),
		HasCode:          code != "",
		CodeRedacted:     redact.Value("code", code),
		Params:           sortedKeys(v),
	}
	s.VendorCode = vendorCode(s.ErrorDescription)
	return s, nil
}

func parseJSON(a string) (Summary, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(a), &m); err != nil {
		return Summary{}, ErrUnrecognised
	}
	e, _ := m["error"].(string)
	if e == "" {
		// A token success body ({"access_token":...}) or an unrelated
		// object: neither is an error to explain.
		return Summary{}, ErrUnrecognised
	}
	desc, _ := m["error_description"].(string)
	uri, _ := m["error_uri"].(string)
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := Summary{Source: SourceErrorBody, Error: e, ErrorDescription: scrub(desc), ErrorURI: uri, Params: keys}
	s.VendorCode = vendorCode(s.ErrorDescription)
	s.Vendor = detectVendor(s)
	return s, nil
}

// emailRE finds addresses in vendor descriptions: Entra's AADSTS50105 text
// names the signed-in user's UPN, which is PII under the redaction policy.
var emailRE = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// scrub masks identity-bearing substrings of a free-text description.
func scrub(desc string) string {
	return emailRE.ReplaceAllStringFunc(desc, func(m string) string { return redact.Value("email", m) })
}

func sortedKeys(v url.Values) []string {
	out := make([]string, 0, len(v))
	for k := range v {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
