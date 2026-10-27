// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/fixture"
	"github.com/jamesonarnett/idpdoctor/internal/oidc"
)

func mint(t *testing.T, muts ...fixture.DiscoveryMutator) ([]byte, fixture.DiscoveryParams, []fixture.Label) {
	t.Helper()
	_, p := fixture.DefaultDiscovery()
	doc, labels, err := fixture.MintDiscovery(p, muts...)
	if err != nil {
		t.Fatal(err)
	}
	return doc, p, labels
}

func checkStatus(r *finding.Report, name string) finding.CheckStatus {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return ""
}

func hasEvidence(r *finding.Report, code finding.Code, path string) bool {
	for _, f := range r.Findings {
		if f.Code != code {
			continue
		}
		for _, e := range f.Evidence {
			if e.Path == path {
				return true
			}
		}
	}
	return false
}

// assertKnownPaths is the eval harness's hallucination contract: every path
// the validator itself cites must be citable.
func assertKnownPaths(t *testing.T, res *oidc.Result) {
	t.Helper()
	known := map[string]bool{}
	for _, p := range oidc.KnownPaths(res.Summary) {
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

func TestHealthyDiscoveryPasses(t *testing.T) {
	doc, p, _ := mint(t)
	res, err := oidc.Check(doc, oidc.Options{ExpectedIssuer: p.Issuer})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Report.Findings) != 0 {
		t.Fatalf("healthy doc produced findings: %+v", res.Report.Findings)
	}
	want := map[string]finding.CheckStatus{
		"required_fields": finding.CheckPass, "issuer_match": finding.CheckPass, "https_only": finding.CheckPass,
		"rs256_present": finding.CheckPass, "endpoint_hosts": finding.CheckPass, "token_endpoint": finding.CheckPass,
		"content_type": finding.CheckSkip,
	}
	for name, st := range want {
		if got := checkStatus(res.Report, name); got != st {
			t.Errorf("check %s = %q, want %q", name, got, st)
		}
	}
	if len(res.Report.Checks) != len(want) {
		t.Errorf("got %d checks, want %d", len(res.Report.Checks), len(want))
	}
	s := res.Summary
	if s.Issuer != p.Issuer || s.Endpoints["jwks_uri"] == "" || s.Endpoints["token_endpoint"] == "" || len(s.Keys) == 0 {
		t.Errorf("summary = %+v", s)
	}
	if _, ok := s.Endpoints["claims_supported"]; ok {
		t.Error("non-endpoint key in Endpoints")
	}
	if res.Report.ArtifactKind != oidc.ArtifactKind || res.Report.Redaction != "default" {
		t.Errorf("report header = %q %q", res.Report.ArtifactKind, res.Report.Redaction)
	}
}

func TestIssuerMatchSkipsWithoutExpectations(t *testing.T) {
	doc, _, _ := mint(t)
	res, err := oidc.Check(doc, oidc.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if checkStatus(res.Report, "issuer_match") != finding.CheckSkip || len(res.Report.Needs) != 1 || res.Report.Needs[0] != "issuer" {
		t.Errorf("checks %+v needs %v", res.Report.Checks, res.Report.Needs)
	}
}

func TestEveryDiscoveryMutatorIsCaught(t *testing.T) {
	muts := fixture.DiscoveryMutators()
	if len(muts) < 7 {
		t.Fatalf("only %d discovery mutators", len(muts))
	}
	for _, m := range muts {
		t.Run(m.Name, func(t *testing.T) {
			doc, p, labels := mint(t, m)
			if len(labels) != 1 || labels[0].Code != m.Code {
				t.Fatalf("labels = %+v", labels)
			}
			res, err := oidc.Check(doc, oidc.Options{ExpectedIssuer: p.Issuer})
			if err != nil {
				t.Fatal(err)
			}
			if !hasEvidence(res.Report, labels[0].Code, labels[0].Path) {
				t.Errorf("no %s finding at %s: %+v", labels[0].Code, labels[0].Path, res.Report.Findings)
			}
			if res.Report.OK() {
				t.Error("report OK despite an error-severity fault")
			}
			assertKnownPaths(t, res)
		})
	}
}

func TestDiscoveryEdgeCases(t *testing.T) {
	base, _ := fixture.DefaultDiscovery()
	cases := []struct {
		name   string
		edit   func(map[string]any)
		check  string
		status finding.CheckStatus
	}{
		{"loopback http is a warning", func(d map[string]any) {
			d["issuer"] = "http://localhost:8080/realms/dev"
			for k, v := range d {
				if s, ok := v.(string); ok && strings.HasPrefix(s, "https://login.example.com") {
					d[k] = strings.Replace(s, "https://login.example.com", "http://localhost:8080", 1)
				}
			}
		}, "https_only", finding.CheckWarn},
		{"sibling subdomain is a warning", func(d map[string]any) {
			d["jwks_uri"] = "https://keys.example.com/tenant-1/keys"
		}, "endpoint_hosts", finding.CheckWarn},
		{"implicit-only needs no token endpoint", func(d map[string]any) {
			d["response_types_supported"] = []any{"id_token", "id_token token"}
			delete(d, "token_endpoint")
		}, "token_endpoint", finding.CheckPass},
		{"empty array counts as missing", func(d map[string]any) {
			d["subject_types_supported"] = []any{}
		}, "required_fields", finding.CheckFail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := map[string]any{}
			for k, v := range base {
				d[k] = v
			}
			tc.edit(d)
			doc := mustJSON(t, d)
			res, err := oidc.Check(doc, oidc.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if got := checkStatus(res.Report, tc.check); got != tc.status {
				t.Errorf("%s = %q, want %q (%+v)", tc.check, got, tc.status, res.Report.Checks)
			}
			assertKnownPaths(t, res)
		})
	}
}

func TestIssuerMismatchAgainstFetchedFrom(t *testing.T) {
	doc, p, _ := mint(t)
	cases := []struct {
		name string
		from string
		ok   bool
	}{
		{"same prefix", p.Issuer + "/.well-known/openid-configuration", true},
		{"other tenant", "https://login.example.com/tenant-2/v2.0/.well-known/openid-configuration", false},
		{"v1 endpoint", "https://login.example.com/tenant-1/.well-known/openid-configuration", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := oidc.Check(doc, oidc.Options{FetchedFrom: tc.from})
			if err != nil {
				t.Fatal(err)
			}
			caught := hasEvidence(res.Report, finding.OIDCIssuerMismatch, oidc.PathDiscoveryIssuer)
			if caught == tc.ok {
				t.Errorf("mismatch finding = %v, want %v", caught, !tc.ok)
			}
			// FetchedFrom alone (no HTTP metadata) must not trip content_type.
			if checkStatus(res.Report, "content_type") != finding.CheckSkip {
				t.Error("content_type ran without fetch metadata")
			}
		})
	}
	// Discovery 4.1: a trailing-slash issuer is fetched without doubling the slash.
	d, _ := fixture.DefaultDiscovery()
	d["issuer"] = p.Issuer + "/"
	res, err := oidc.Check(mustJSON(t, d), oidc.Options{FetchedFrom: p.Issuer + "/.well-known/openid-configuration"})
	if err != nil {
		t.Fatal(err)
	}
	if checkStatus(res.Report, "issuer_match") != finding.CheckPass {
		t.Errorf("trailing-slash issuer flagged against its own fetch URL: %+v", res.Report.Findings)
	}
}

func TestFetch(t *testing.T) {
	doc, p, _ := mint(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/ok/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(doc)
	})
	mux.HandleFunc("/html/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>Sign in</body></html>"))
	})
	mux.HandleFunc("/htmljson/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(doc)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cases := []struct {
		name       string
		issuer     string
		wantStatus int
		wantFail   bool
	}{
		{"200 json", srv.URL + "/ok", 200, false},
		{"already has well-known path", srv.URL + "/ok/.well-known/openid-configuration", 200, false},
		{"404", srv.URL + "/missing", 404, true},
		{"html body", srv.URL + "/html", 200, true},
		{"json body served as text/html", srv.URL + "/htmljson", 200, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, opts, err := oidc.Fetch(context.Background(), srv.Client(), tc.issuer)
			if err != nil {
				t.Fatal(err)
			}
			if opts.FetchStatus != tc.wantStatus || !strings.HasSuffix(opts.FetchedFrom, "/.well-known/openid-configuration") ||
				strings.Count(opts.FetchedFrom, ".well-known") != 1 {
				t.Fatalf("opts = %+v", opts)
			}
			opts.ExpectedIssuer = p.Issuer
			res, err := oidc.Check(body, opts)
			if err != nil {
				t.Fatalf("check: %v", err)
			}
			failed := checkStatus(res.Report, "content_type") == finding.CheckFail
			if failed != tc.wantFail {
				t.Errorf("content_type fail = %v, want %v: %+v", failed, tc.wantFail, res.Report.Checks)
			}
			if tc.wantFail && !hasEvidence(res.Report, finding.OIDCDiscoveryDocInvalid, oidc.PathDiscovery) {
				t.Errorf("no finding at /discovery: %+v", res.Report.Findings)
			}
			if res.Summary.FetchStatus != tc.wantStatus {
				t.Errorf("summary fetch status = %d", res.Summary.FetchStatus)
			}
			assertKnownPaths(t, res)
		})
	}

	// The fixture's own issuer and the test server URL differ, so 4.3 fires.
	body, opts, err := oidc.Fetch(context.Background(), srv.Client(), srv.URL+"/ok")
	if err != nil {
		t.Fatal(err)
	}
	res, _ := oidc.Check(body, opts)
	if !hasEvidence(res.Report, finding.OIDCIssuerMismatch, oidc.PathDiscoveryIssuer) {
		t.Error("issuer != fetch URL prefix not reported")
	}

	srv.Close()
	if _, _, err := oidc.Fetch(context.Background(), srv.Client(), srv.URL+"/ok"); !errors.Is(err, oidc.ErrFetch) {
		t.Errorf("closed server err = %v", err)
	}
}

func TestParseRejectsNonObjects(t *testing.T) {
	for _, in := range []string{"", "not json", "[1,2]", "null", `"str"`} {
		if _, err := oidc.Parse([]byte(in)); !errors.Is(err, oidc.ErrNotJSON) {
			t.Errorf("Parse(%q) err = %v", in, err)
		}
		if _, err := oidc.Check([]byte(in), oidc.Options{}); !errors.Is(err, oidc.ErrNotJSON) {
			t.Errorf("Check(%q) err = %v", in, err)
		}
	}
}

func TestDiscoveryURL(t *testing.T) {
	cases := map[string]string{
		"https://op.example.com":                                  "https://op.example.com/.well-known/openid-configuration",
		"https://op.example.com/t/":                               "https://op.example.com/t/.well-known/openid-configuration",
		"https://op.example.com/t/v2.0":                           "https://op.example.com/t/v2.0/.well-known/openid-configuration",
		"https://op.example.com/.well-known/openid-configuration": "https://op.example.com/.well-known/openid-configuration",
	}
	for in, want := range cases {
		if got := oidc.DiscoveryURL(in); got != want {
			t.Errorf("DiscoveryURL(%q) = %q, want %q", in, got, want)
		}
	}
}
