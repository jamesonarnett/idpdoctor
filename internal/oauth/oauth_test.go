// SPDX-License-Identifier: Apache-2.0

package oauth_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/fixture"
	"github.com/jamesonarnett/idpdoctor/internal/oauth"
)

func checkOf(r *finding.Report, name string) finding.Check {
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	return finding.Check{}
}

func evidenceAt(r *finding.Report, code finding.Code, path string) *finding.Evidence {
	for _, f := range r.Findings {
		if f.Code != code {
			continue
		}
		for i := range f.Evidence {
			if f.Evidence[i].Path == path {
				return &f.Evidence[i]
			}
		}
	}
	return nil
}

func assertKnownPaths(t *testing.T, res *oauth.Result, exp expected.Expected) {
	t.Helper()
	known := map[string]bool{}
	for _, p := range oauth.KnownPaths(res.Summary, exp) {
		known[p] = true
	}
	for _, f := range res.Report.Findings {
		for _, e := range f.Evidence {
			if !known[e.Path] {
				t.Errorf("%s cites %s which KnownPaths omits", f.Code, e.Path)
			}
		}
	}
}

func TestParseShapes(t *testing.T) {
	cases := []struct {
		name, in      string
		source, error string
		hasCode       bool
		host, path    string
		params        string
	}{
		{"url with query error", "https://app.example.com/callback?error=access_denied&error_description=User+cancelled&state=xyz",
			oauth.SourceRedirectURL, "access_denied", false, "app.example.com", "/callback", "error,error_description,state"},
		{"url with fragment", "https://app.example.com/cb#code=abc&state=s1&id_token=eyJ.x.y",
			oauth.SourceRedirectURL, "", true, "app.example.com", "/cb", "code,id_token,state"},
		{"custom scheme", "com.example.app:/oauth2redirect?code=abc&state=s",
			oauth.SourceRedirectURL, "", true, "", "/oauth2redirect", "code,state"},
		{"bare query", "error=invalid_request&error_description=AADSTS50011%3A+The+redirect+URI",
			oauth.SourceRedirectURL, "invalid_request", false, "", "", "error,error_description"},
		{"bare query with leading ?", "?error=login_required",
			oauth.SourceRedirectURL, "login_required", false, "", "", "error"},
		{"json body", `{"error":"invalid_grant","error_description":"AADSTS70008: expired","error_codes":[70008]}`,
			oauth.SourceErrorBody, "invalid_grant", false, "", "", "error,error_codes,error_description"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := oauth.Parse(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if s.Source != tc.source || s.Error != tc.error || s.HasCode != tc.hasCode || s.RedirectHost != tc.host || s.RedirectPath != tc.path {
				t.Errorf("summary = %+v", s)
			}
			if got := strings.Join(s.Params, ","); got != tc.params {
				t.Errorf("params = %s, want %s", got, tc.params)
			}
			if tc.hasCode && (s.CodeRedacted == "" || strings.Contains(s.CodeRedacted, "abc")) {
				t.Errorf("code not redacted: %q", s.CodeRedacted)
			}
		})
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, in := range []string{
		"", "hello world", "https://app.example.com/callback", "https://app.example.com/callback?foo=bar",
		`{"access_token":"x","token_type":"Bearer"}`, `{"error":`, "a = b", "<html>Sign in</html>",
	} {
		if _, err := oauth.Parse(in); !errors.Is(err, oauth.ErrUnrecognised) {
			t.Errorf("Parse(%q) err = %v", in, err)
		}
		if _, err := oauth.Explain(in, expected.Expected{}); !errors.Is(err, oauth.ErrUnrecognised) {
			t.Errorf("Explain(%q) err = %v", in, err)
		}
	}
}

func TestVendorDetection(t *testing.T) {
	cases := map[string]string{
		"error=invalid_request&error_description=AADSTS50011%3A+bad":               oauth.VendorEntra,
		"https://example.us.auth0.com/authorize?error=access_denied":               oauth.VendorAuth0,
		"error=invalid_request&error_description=Callback+URL+mismatch":            oauth.VendorAuth0,
		"https://dev-1.okta.com/oauth2/v1/authorize?error=access_denied":           oauth.VendorOkta,
		"error=access_denied&error_description=E0000004+Authentication+failed":     oauth.VendorOkta,
		"https://accounts.google.com/o/oauth2/auth?error=app_not_enabled_for_user": oauth.VendorGoogle,
		"https://app.example.com/cb?error=server_error":                            oauth.VendorGeneric,
	}
	for in, want := range cases {
		s, err := oauth.Parse(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if s.Vendor != want {
			t.Errorf("%s: vendor = %s, want %s", in, s.Vendor, want)
		}
	}
	s, _ := oauth.Parse("error=invalid_grant&error_description=AADSTS70008%3A+The+code+expired")
	if s.VendorCode != "AADSTS70008" {
		t.Errorf("vendor code = %q", s.VendorCode)
	}
}

func TestErrorClassification(t *testing.T) {
	cases := []struct {
		in   string
		want finding.Code
	}{
		{"error=redirect_uri_mismatch", finding.OAuthRedirectURIMismatch},
		{"error=invalid_request&error_description=AADSTS50011%3A+The+redirect+URI", finding.OAuthRedirectURIMismatch},
		{"error=invalid_request&error_description=Redirect+URI+not+allowed", finding.OAuthRedirectURIMismatch},
		{"error=invalid_request&error_description=The+redirect_uri+is+invalid", finding.OAuthRedirectURIMismatch},
		{`{"error":"invalid_grant","error_description":"Failed to verify code verifier"}`, finding.OAuthPKCEVerifierMismatch},
		{`{"error":"invalid_grant","error_description":"AADSTS501481: The Code_Verifier does not match"}`, finding.OAuthPKCEVerifierMismatch},
		{`{"error":"invalid_grant"}`, finding.OAuthInvalidGrantCode},
		{`{"error":"invalid_grant","error_description":"AADSTS54005: OAuth2 Authorization code was already redeemed"}`, finding.OAuthInvalidGrantCode},
		{`{"error":"invalid_client","error_description":"AADSTS7000222: The provided client secret keys are expired"}`, finding.OAuthClientConfigRejected},
		{"error=unsupported_response_type", finding.OAuthClientConfigRejected},
		{`{"error":"unsupported_grant_type"}`, finding.OAuthClientConfigRejected},
		{"error=interaction_required&error_description=AADSTS50076%3A+MFA", finding.IdPPolicyRefusal},
		{"error=access_denied&error_description=AADSTS53003%3A+Conditional+Access", finding.IdPPolicyRefusal},
		{"error=account_selection_required", finding.IdPPolicyRefusal},
		{"error=app_not_enabled_for_user", finding.IdPPolicyRefusal},
		{"error=access_denied&error_description=user_not_active", finding.IdPPolicyRefusal},
	}
	for _, tc := range cases {
		res, err := oauth.Explain(tc.in, expected.Expected{})
		if err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if evidenceAt(res.Report, tc.want, oauth.PathError) == nil {
			t.Errorf("%s: want %s, got %+v", tc.in, tc.want, res.Report.Findings)
		}
		if len(res.Report.Findings) != 1 {
			t.Errorf("%s: %d findings, want exactly 1", tc.in, len(res.Report.Findings))
		}
	}
	// Policy refusals carry reduced confidence; unknown errors warn, never invent a code.
	res, _ := oauth.Explain("error=consent_required", expected.Expected{})
	if res.Report.Findings[0].Confidence != 0.8 {
		t.Errorf("policy confidence = %v", res.Report.Findings[0].Confidence)
	}
	res, _ = oauth.Explain("error=server_error", expected.Expected{})
	if len(res.Report.Findings) != 0 || checkOf(res.Report, "error_class").Status != finding.CheckWarn {
		t.Errorf("server_error: %+v %+v", res.Report.Findings, res.Report.Checks)
	}
}

func TestHealthySuccessRedirect(t *testing.T) {
	p := fixture.DefaultOAuthParams()
	art, exp, labels, err := fixture.MintOAuth(p)
	if err != nil || len(labels) != 0 {
		t.Fatal(err, labels)
	}
	res, err := oauth.Explain(art, exp)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Report.OK() || len(res.Report.Findings) != 0 {
		t.Fatalf("healthy redirect: %+v", res.Report.Findings)
	}
	for _, c := range res.Report.Checks {
		if c.Status != finding.CheckPass {
			t.Errorf("check %s = %s (%s)", c.Name, c.Status, c.Detail)
		}
	}
	s := res.Summary
	if !s.HasCode || s.CodeRedacted == "" || strings.Contains(s.CodeRedacted, p.Code) || !strings.HasPrefix(s.CodeRedacted, "[REDACTED:code:") {
		t.Errorf("code = %q", s.CodeRedacted)
	}
	if s.State != p.State || s.Error != "" || s.Vendor != oauth.VendorGeneric {
		t.Errorf("summary = %+v", s)
	}
}

func TestSkipsNameWhatToSupply(t *testing.T) {
	art, _, _, err := fixture.MintOAuth(fixture.DefaultOAuthParams())
	if err != nil {
		t.Fatal(err)
	}
	res, err := oauth.Explain(art, expected.Expected{})
	if err != nil {
		t.Fatal(err)
	}
	for name, needs := range map[string]string{"redirect_uri": "registered_redirect_uris", "pkce": "code_verifier", "pkce_posture": "client_type"} {
		if c := checkOf(res.Report, name); c.Status != finding.CheckSkip || c.Needs != needs {
			t.Errorf("%s = %+v, want skip needs %s", name, c, needs)
		}
	}
	if got := len(res.Report.Checks); got != 5 {
		t.Errorf("%d checks, want 5", got)
	}
}

func TestEveryOAuthMutatorIsCaught(t *testing.T) {
	muts := fixture.OAuthMutators()
	if len(muts) < 13 {
		t.Fatalf("only %d oauth mutators", len(muts))
	}
	for _, m := range muts {
		t.Run(m.Name, func(t *testing.T) {
			p := fixture.DefaultOAuthParams()
			art, exp, labels, err := fixture.MintOAuth(p, m)
			if err != nil {
				t.Fatal(err)
			}
			if len(labels) != 1 || labels[0].Code != m.Code {
				t.Fatalf("labels = %+v", labels)
			}
			res, err := oauth.Explain(art, exp)
			if err != nil {
				t.Fatalf("explain %q: %v", art, err)
			}
			if evidenceAt(res.Report, labels[0].Code, labels[0].Path) == nil {
				t.Errorf("no %s at %s: %+v", labels[0].Code, labels[0].Path, res.Report.Findings)
			}
			spec, _ := finding.Lookup(m.Code)
			if spec.Lane == finding.LanePosture && !res.Report.OK() {
				t.Errorf("posture-only mutator broke the flow: %+v", res.Report.Findings)
			}
			if spec.Lane == finding.LaneFault && res.Report.OK() {
				t.Error("fault mutator left the report OK")
			}
			// The mutated params say which vendor the artifact reveals.
			mp := p
			m.Apply(&mp)
			if res.Summary.Vendor != mp.Vendor {
				t.Errorf("vendor = %s, want %s", res.Summary.Vendor, mp.Vendor)
			}
			assertKnownPaths(t, res, exp)
		})
	}
}

func TestRedirectURINearMissNotes(t *testing.T) {
	reg := "https://app.example.com/callback"
	cases := []struct {
		sent, registered, note string
	}{
		{reg + "/", reg, "trailing slash"},
		{"http://app.example.com/callback", reg, "scheme"},
		{"https://app.example.com/Callback", reg, "case"},
		{"https://app.example.com:8443/callback", reg, "port"},
		{"http://localhost:3000/callback", "http://127.0.0.1:3000/callback", "localhost vs 127.0.0.1"},
		{"http://127.0.0.1:5173/cb", "http://127.0.0.1:3000/cb", "RFC 8252"},
		{"https://app.example.com/callback?x=1", reg, "query string"},
		{"https://evil.example.net/steal", reg, "no registered URI is a near miss"},
	}
	for _, tc := range cases {
		exp := expected.Expected{RedirectURI: tc.sent, RegisteredRedirectURIs: []string{"https://other.example.com/x", tc.registered}}
		res, err := oauth.Explain("https://app.example.com/callback?code=abc", exp)
		if err != nil {
			t.Fatal(err)
		}
		ev := evidenceAt(res.Report, finding.OAuthRedirectURIMismatch, oauth.PathRequestRedirectURI)
		if ev == nil {
			t.Fatalf("%s: not flagged", tc.sent)
		}
		if !strings.Contains(ev.Note, tc.note) {
			t.Errorf("%s vs %s: note %q, want it to mention %q", tc.sent, tc.registered, ev.Note, tc.note)
		}
		if tc.note != "no registered URI is a near miss" && ev.Expected != tc.registered {
			t.Errorf("%s: expected = %q, want the near-miss %q", tc.sent, ev.Expected, tc.registered)
		}
	}
	res, _ := oauth.Explain("https://app.example.com/callback?code=abc", expected.Expected{RedirectURI: reg, RegisteredRedirectURIs: []string{reg}})
	if checkOf(res.Report, "redirect_uri").Status != finding.CheckPass {
		t.Error("exact match not passed")
	}
}

func TestPKCE(t *testing.T) {
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// RFC 7636 Appendix B test vector.
	if got := oauth.S256(v); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("S256 = %s", got)
	}
	if fixture.S256(v) != oauth.S256(v) {
		t.Fatal("fixture.S256 disagrees with oauth.S256")
	}
	cases := []struct {
		name                string
		verifier, challenge string
		method              string
		status              finding.CheckStatus
		note                string
	}{
		{"s256 ok", v, oauth.S256(v), "S256", finding.CheckPass, ""},
		{"plain ok", v, v, "plain", finding.CheckPass, ""},
		{"absent method defaults to plain", v, v, "", finding.CheckPass, ""},
		{"s256 mismatch", v, oauth.S256(v + "x"), "S256", finding.CheckFail, "BASE64URL(SHA256"},
		{"raw verifier sent as S256 challenge", v, v, "S256", finding.CheckFail, "method mismatch"},
		{"S256 challenge with plain method", v, oauth.S256(v), "plain", finding.CheckFail, "method mismatch"},
		{"too short", "short", oauth.S256("short"), "S256", finding.CheckFail, "RFC 7636 4.1"},
		{"bad alphabet", strings.Repeat("a", 42) + "!", oauth.S256(strings.Repeat("a", 42) + "!"), "S256", finding.CheckFail, "RFC 7636 4.1"},
		{"unknown method", v, v, "S512", finding.CheckFail, "only S256 and plain"},
		{"challenge only", "", oauth.S256(v), "S256", finding.CheckSkip, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exp := expected.Expected{CodeVerifier: tc.verifier, CodeChallenge: tc.challenge, CodeChallengeMethod: tc.method}
			res, err := oauth.Explain("https://app.example.com/cb?code=abc", exp)
			if err != nil {
				t.Fatal(err)
			}
			if c := checkOf(res.Report, "pkce"); c.Status != tc.status {
				t.Fatalf("pkce = %+v", c)
			}
			if tc.note == "" {
				return
			}
			found := false
			for _, f := range res.Report.Findings {
				for _, e := range f.Evidence {
					found = found || (f.Code == finding.OAuthPKCEVerifierMismatch && strings.Contains(e.Note, tc.note))
				}
			}
			if !found {
				t.Errorf("no PKCE finding noting %q: %+v", tc.note, res.Report.Findings)
			}
			b, _ := json.Marshal(res)
			if tc.verifier != "" && len(tc.verifier) > 8 && strings.Contains(string(b), tc.verifier) {
				t.Error("verifier leaked")
			}
		})
	}
}

func TestPKCEPostureAndClientConfig(t *testing.T) {
	art := "https://app.example.com/cb?code=abc"
	cases := []struct {
		name string
		exp  expected.Expected
		code finding.Code
		path string
	}{
		{"public plain", expected.Expected{ClientType: "public", CodeVerifier: strings.Repeat("v", 43), CodeChallenge: strings.Repeat("v", 43), CodeChallengeMethod: "plain"},
			finding.PosturePKCEPlainOrAbsent, oauth.PathRequestCodeChallengeMethod},
		{"public absent, code inferred", expected.Expected{ClientType: "public"}, finding.PosturePKCEPlainOrAbsent, oauth.PathRequestCodeChallenge},
		{"public client_credentials", expected.Expected{ClientType: "public", GrantType: "client_credentials", ResponseType: "token"},
			finding.OAuthClientConfigRejected, oauth.PathRequestGrantType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := oauth.Explain(art, tc.exp)
			if err != nil {
				t.Fatal(err)
			}
			if evidenceAt(res.Report, tc.code, tc.path) == nil {
				t.Errorf("no %s at %s: %+v", tc.code, tc.path, res.Report.Findings)
			}
			assertKnownPaths(t, res, tc.exp)
		})
	}
	// Not a code flow and confidential clients do not trip the posture lane.
	for _, exp := range []expected.Expected{{ClientType: "public", ResponseType: "id_token"}, {ClientType: "confidential", ResponseType: "code"}} {
		res, _ := oauth.Explain(art, exp)
		if len(res.Report.Findings) != 0 {
			t.Errorf("%+v: unexpected %+v", exp, res.Report.Findings)
		}
	}
}

// TestNothingSecretLeaks marshals the Summary and Report for the healthy
// redirect and every mutator and asserts no bearer secret or user email
// survives into output.
func TestNothingSecretLeaks(t *testing.T) {
	base := fixture.DefaultOAuthParams()
	runs := []struct {
		name string
		muts []fixture.OAuthMutator
	}{{name: "healthy"}}
	for _, m := range fixture.OAuthMutators() {
		runs = append(runs, struct {
			name string
			muts []fixture.OAuthMutator
		}{m.Name, []fixture.OAuthMutator{m}})
	}
	for _, run := range runs {
		t.Run(run.name, func(t *testing.T) {
			art, exp, _, err := fixture.MintOAuth(base, run.muts...)
			if err != nil {
				t.Fatal(err)
			}
			res, err := oauth.Explain(art, exp)
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			out := string(b)
			secrets := []string{base.Code, base.CodeVerifier, base.CodeChallenge, exp.CodeVerifier, exp.CodeChallenge, "alice@example.com", "verifier-secret"}
			for _, s := range secrets {
				if s != "" && strings.Contains(out, s) {
					t.Errorf("output contains secret %q:\n%s", s, out)
				}
			}
		})
	}
}
