// SPDX-License-Identifier: Apache-2.0

package jwt_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gojwt "github.com/golang-jwt/jwt/v5"

	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/fixture"
	"github.com/jamesonarnett/idpdoctor/internal/jwt"
)

func keys(t *testing.T) *fixture.Keys {
	t.Helper()
	k, err := fixture.TestKeys()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jwks(k *fixture.Keys, p fixture.JWTParams) string {
	return fixture.JWKS(fixture.RSAJWK(p.KID, &k.Key.PublicKey))
}

func run(t *testing.T, token string, exp expected.Expected, ks jwt.Keys, client *http.Client) *jwt.Result {
	t.Helper()
	d, err := jwt.Decode(token, fixture.FixedNow)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	res, err := jwt.Validate(context.Background(), d, exp, jwt.Options{Keys: ks, Client: client}, fixture.FixedNow)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	return res
}

func hasCode(r *finding.Report, c finding.Code) bool {
	for _, f := range r.Findings {
		if f.Code == c {
			return true
		}
	}
	return false
}

func status(r *finding.Report, name string) finding.CheckStatus {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return "missing"
}

func TestHealthyToken(t *testing.T) {
	k := keys(t)
	p := fixture.DefaultJWTParams()
	tok, _, err := fixture.MintJWT(p, k.Key)
	if err != nil {
		t.Fatal(err)
	}
	exp := expected.Expected{Issuer: p.Issuer, ClientID: p.Audience, Nonce: p.Nonce}
	for name, ks := range map[string]jwt.Keys{
		"jwks_json": {JWKSJSON: jwks(k, p)},
		"pem":       {PEM: k.CertPEM()},
	} {
		t.Run(name, func(t *testing.T) {
			res := run(t, tok, exp, ks, nil)
			if !res.Report.OK() || len(res.Report.Findings) != 0 {
				t.Fatalf("healthy token has findings: %+v", res.Report.Findings)
			}
			for _, c := range res.Report.Checks {
				if c.Status != finding.CheckPass && c.Name != "at_hash" {
					t.Errorf("%s = %s (%s)", c.Name, c.Status, c.Detail)
				}
			}
			if res.KindGuess != "id_token" || res.ExpInSeconds != 3600 {
				t.Errorf("kind=%s exp_in=%d", res.KindGuess, res.ExpInSeconds)
			}
		})
	}
}

func TestJWKSOverHTTP(t *testing.T) {
	k := keys(t)
	p := fixture.DefaultJWTParams()
	tok, _, _ := fixture.MintJWT(p, k.Key)
	exp := expected.Expected{Issuer: p.Issuer, ClientID: p.Audience}

	tests := []struct {
		name     string
		body     string
		code     int
		wantOK   bool
		wantCode finding.Code
	}{
		{"200", jwks(k, p), 200, true, ""},
		{"500", "boom", 500, false, finding.JWTKidNotFoundInJWKS},
		{"garbage", "<html>", 200, false, finding.JWTKidNotFoundInJWKS},
		{"other kid only", fixture.JWKS(fixture.RSAJWK("other", &k.Key.PublicKey)), 200, false, finding.JWTKidNotFoundInJWKS},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(fixture.JWKSHandler(tc.body, tc.code))
			defer srv.Close()
			res := run(t, tok, exp, jwt.Keys{JWKSURL: srv.URL}, srv.Client())
			if res.Report.OK() != tc.wantOK {
				t.Fatalf("ok = %v, findings %+v", res.Report.OK(), res.Report.Findings)
			}
			if tc.wantCode != "" && !hasCode(res.Report, tc.wantCode) {
				t.Errorf("want %s, got %+v", tc.wantCode, res.Report.Findings)
			}
		})
	}
}

// TestMutatorsAreCaught: every JWT mutator yields its labelled code and path.
func TestMutatorsAreCaught(t *testing.T) {
	k := keys(t)
	p := fixture.DefaultJWTParams()
	exp := expected.Expected{Issuer: p.Issuer, ClientID: p.Audience, Nonce: p.Nonce}
	for _, m := range fixture.JWTMutators() {
		t.Run(m.Name, func(t *testing.T) {
			tok, labels, eff, err := fixture.MintJWTFull(p, k.Key, m)
			if err != nil {
				t.Fatal(err)
			}
			label := labels[0]
			exp.AccessToken = eff.AccessToken
			res := run(t, tok, exp, jwt.Keys{JWKSJSON: jwks(k, p)}, nil)
			if !hasCode(res.Report, label.Code) {
				t.Fatalf("want %s, got %+v", label.Code, res.Report.Findings)
			}
			found := false
			for _, f := range res.Report.Findings {
				for _, e := range f.Evidence {
					if f.Code == label.Code && e.Path == label.Path {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("no evidence on %s", label.Path)
			}
			if res.Report.OK() {
				t.Error("mutated token reported OK")
			}
		})
	}
}

func TestSkipsWithoutExpected(t *testing.T) {
	k := keys(t)
	tok, _, _ := fixture.MintJWT(fixture.DefaultJWTParams(), k.Key)
	res := run(t, tok, expected.Expected{}, jwt.Keys{}, nil)
	if !res.Report.OK() {
		t.Fatalf("findings: %+v", res.Report.Findings)
	}
	for _, name := range []string{"iss", "aud", "nonce", "kid_found", "signature"} {
		if status(res.Report, name) != finding.CheckSkip {
			t.Errorf("%s should skip", name)
		}
	}
	want := map[string]bool{"issuer": true, "client_id": true, "nonce": true, "jwks_url": true}
	for _, n := range res.Report.Needs {
		delete(want, n)
	}
	if len(want) != 0 {
		t.Errorf("needs missing %v (got %v)", want, res.Report.Needs)
	}
}

func TestDecodeRedactsAndRejectsMalformed(t *testing.T) {
	k := keys(t)
	p := fixture.DefaultJWTParams()
	tok, _, _ := fixture.MintJWT(p, k.Key)
	d, err := jwt.Decode("Bearer "+tok, fixture.FixedNow)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(d)
	out := string(b)
	for _, leak := range []string{p.Subject, p.Email} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q", leak)
		}
	}
	for _, keep := range []string{p.Issuer, p.Audience, p.KID, `"nonce":"` + p.Nonce} {
		if !strings.Contains(out, keep) {
			t.Errorf("over-redacted: %q", keep)
		}
	}
	if d.Claims["sub"] != p.Subject {
		t.Error("in-memory claims must stay intact")
	}
	if _, err := jwt.Decode("not.a.jwt", fixture.FixedNow); err == nil {
		t.Error("malformed must error")
	}
	if _, err := jwt.Decode("", fixture.FixedNow); err == nil {
		t.Error("empty must error")
	}
}

func TestMultiAudWithAzpPasses(t *testing.T) {
	k := keys(t)
	p := fixture.DefaultJWTParams()
	m := fixture.JWTMutator{Name: "x", Code: finding.JWTAudOrAzpMismatch, Apply: func(c gojwt.MapClaims, p *fixture.JWTParams) fixture.Label {
		c["aud"] = []string{p.Audience, "api://second"}
		c["azp"] = p.Audience
		return fixture.Label{}
	}}
	tok, _, _ := fixture.MintJWT(p, k.Key, m)
	res := run(t, tok, expected.Expected{ClientID: p.Audience}, jwt.Keys{}, nil)
	if status(res.Report, "aud") != finding.CheckPass || status(res.Report, "azp") != finding.CheckPass {
		t.Errorf("aud/azp = %s/%s", status(res.Report, "aud"), status(res.Report, "azp"))
	}
}
