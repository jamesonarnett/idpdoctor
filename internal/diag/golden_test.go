// SPDX-License-Identifier: Apache-2.0

package diag_test

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/fixture"
	"github.com/jamesonarnett/idpdoctor/internal/jwt"
)

// -update regenerates every case directory under testdata/ from the fixture
// engine and rewrites the golden files. Review the git diff afterwards: a
// changed expected.json is a behaviour change.
var update = flag.Bool("update", false, "regenerate testdata cases and golden files")

const testdataRoot = "../../testdata"

// samlCase is one directory under testdata/saml. Dialect and Mutator feed
// the fixture; Tweak adjusts the Expected the SP "has configured" for
// cases where the whole point is a mismatch between the two.
type samlCase struct {
	Name    string
	Dialect string
	Mutator string
	Tweak   func(e *expected.Expected, m *fixture.Minted)
}

func samlCases() []samlCase {
	var cases []samlCase
	for _, d := range []string{"generic", "okta", "entra", "auth0"} {
		cases = append(cases, samlCase{Name: "healthy_" + d, Dialect: d})
	}
	cases = append(cases, samlCase{Name: "healthy_no_expected", Tweak: func(e *expected.Expected, m *fixture.Minted) { *e = expected.Expected{} }})
	for _, m := range fixture.SAMLMutators() {
		c := samlCase{Name: m.Name, Dialect: "generic", Mutator: m.Name}
		switch m.Name {
		case "posture_embedded_key":
			c.Tweak = func(e *expected.Expected, _ *fixture.Minted) { e.IdPCertPEM = "" }
		case "posture_expired_cert", "cert_expired", "cert_weak_key":
			c.Tweak = func(e *expected.Expected, m *fixture.Minted) { e.IdPCertPEM = m.Keys.CertPEM() }
		case "posture_unsigned_assertion":
			c.Tweak = func(e *expected.Expected, _ *fixture.Minted) { e.RequireSignedAssertion = nil }
		}
		cases = append(cases, c)
	}
	return cases
}

type jwtCase struct {
	Name    string
	Mutator string
	NoKeys  bool
}

func jwtCases() []jwtCase {
	cases := []jwtCase{{Name: "healthy"}, {Name: "healthy_no_keys", NoKeys: true}}
	for _, m := range fixture.JWTMutators() {
		cases = append(cases, jwtCase{Name: m.Name, Mutator: m.Name})
	}
	return cases
}

type discoveryCase struct {
	Name    string
	Mutator string
}

func discoveryCases() []discoveryCase {
	cases := []discoveryCase{{Name: "healthy"}}
	for _, m := range fixture.DiscoveryMutators() {
		cases = append(cases, discoveryCase{Name: m.Name, Mutator: m.Name})
	}
	return cases
}

type oauthCase struct {
	Name    string
	Mutator string
}

func oauthCases() []oauthCase {
	cases := []oauthCase{{Name: "healthy"}}
	for _, m := range fixture.OAuthMutators() {
		cases = append(cases, oauthCase{Name: m.Name, Mutator: m.Name})
	}
	return cases
}

// golden is the stable projection of a Report: codes, lanes, paths and
// check statuses. Volatile values (fingerprints of freshly generated certs,
// prose) are deliberately excluded so -update is a no-op unless behaviour
// changed.
type golden struct {
	OK       bool              `json:"ok"`
	TopCause string            `json:"top_cause"`
	Findings []goldenFinding   `json:"findings"`
	Checks   map[string]string `json:"checks"`
	Needs    []string          `json:"needs"`
}

type goldenFinding struct {
	Code     string   `json:"code"`
	Lane     string   `json:"lane"`
	Severity string   `json:"severity"`
	Paths    []string `json:"paths"`
}

func project(res *diag.Result) golden {
	g := golden{OK: res.Report.OK(), Checks: map[string]string{}, Needs: res.Report.Needs}
	if res.TopCause != nil {
		g.TopCause = string(res.TopCause.Code)
	}
	for _, f := range res.Report.Findings {
		gf := goldenFinding{Code: string(f.Code), Lane: string(f.Lane), Severity: string(f.Severity)}
		for _, e := range f.Evidence {
			gf.Paths = append(gf.Paths, e.Path)
		}
		g.Findings = append(g.Findings, gf)
	}
	for _, c := range res.Report.Checks {
		g.Checks[c.Name] = string(c.Status)
	}
	if g.Findings == nil {
		g.Findings = []goldenFinding{}
	}
	return g
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run `go test ./internal/diag -update`)", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func TestGoldenSAML(t *testing.T) {
	k, err := fixture.TestKeys()
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	for _, c := range samlCases() {
		t.Run(c.Name, func(t *testing.T) {
			dir := filepath.Join(testdataRoot, "saml", c.Name)
			if *update {
				p := fixture.DefaultParams()
				if c.Dialect != "" {
					p.Dialect = c.Dialect
				}
				var muts []fixture.Mutator
				if c.Mutator != "" {
					m, ok := fixture.SAMLMutator(c.Mutator)
					if !ok {
						t.Fatalf("no mutator %s", c.Mutator)
					}
					muts = append(muts, m)
				}
				minted, err := fixture.MintSAML(p, k, muts...)
				if err != nil {
					t.Fatal(err)
				}
				exp := expected.Expected{
					SPEntityID: p.SPEntityID, ACSURL: p.ACSURL, IdPEntityID: p.IdPEntityID, IdPCertPEM: k.CertPEM(),
					RequestID: p.RequestID, NameIDFormat: p.NameIDFormat, RequiredAttributes: []string{"email", "firstName"},
					RequireSignedAssertion: &yes, Now: fixture.FixedNow.Format("2006-01-02T15:04:05Z"),
				}
				if c.Tweak != nil {
					c.Tweak(&exp, minted)
				}
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "response.xml"), minted.XML, 0o644); err != nil {
					t.Fatal(err)
				}
				writeJSON(t, filepath.Join(dir, "params.json"), exp)
				writeJSON(t, filepath.Join(dir, "label.json"), minted.Labels)
			}

			xml, err := os.ReadFile(filepath.Join(dir, "response.xml"))
			if err != nil {
				t.Fatalf("%v (run with -update)", err)
			}
			var exp expected.Expected
			readJSON(t, filepath.Join(dir, "params.json"), &exp)
			res, err := diag.Run(context.Background(), diag.Input{Artifact: string(xml), Expected: exp, Now: fixture.FixedNow})
			if err != nil {
				t.Fatal(err)
			}
			got := project(res)
			summary, err := json.MarshalIndent(res.SAML, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if *update {
				writeJSON(t, filepath.Join(dir, "expected.json"), got)
				if err := os.WriteFile(filepath.Join(dir, "summary.json"), append(summary, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			var want golden
			readJSON(t, filepath.Join(dir, "expected.json"), &want)
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("expected.json mismatch (-want +got):\n%s", diff)
			}
			wantSummary, err := os.ReadFile(filepath.Join(dir, "summary.json"))
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(strings.TrimSpace(string(wantSummary)), string(summary)); diff != "" {
				t.Errorf("summary.json mismatch (-want +got):\n%s", diff)
			}
			// The label promised a code; the pipeline must deliver it.
			var labels []fixture.Label
			readJSON(t, filepath.Join(dir, "label.json"), &labels)
			for _, l := range labels {
				if !hasCode(res.Report, l.Code) {
					t.Errorf("label %s not found in %v", l.Code, codes(res.Report))
				}
			}
			assertNoLeak(t, res, string(summary))
		})
	}
}

func TestGoldenJWT(t *testing.T) {
	k, err := fixture.TestKeys()
	if err != nil {
		t.Fatal(err)
	}
	p := fixture.DefaultJWTParams()
	jwks := fixture.JWKS(fixture.RSAJWK(p.KID, &k.Key.PublicKey))
	for _, c := range jwtCases() {
		t.Run(c.Name, func(t *testing.T) {
			dir := filepath.Join(testdataRoot, "jwt", c.Name)
			if *update {
				var muts []fixture.JWTMutator
				if c.Mutator != "" {
					m, ok := fixture.JWTMutatorByName(c.Mutator)
					if !ok {
						t.Fatalf("no mutator %s", c.Mutator)
					}
					muts = append(muts, m)
				}
				tok, labels, eff, err := fixture.MintJWTFull(p, k.Key, muts...)
				if err != nil {
					t.Fatal(err)
				}
				exp := expected.Expected{Issuer: p.Issuer, ClientID: p.Audience, Nonce: p.Nonce, AccessToken: eff.AccessToken, Now: fixture.FixedNow.Format("2006-01-02T15:04:05Z")}
				params := map[string]any{"expected": exp}
				if !c.NoKeys {
					params["keys"] = jwt.Keys{JWKSJSON: jwks}
				}
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "token.txt"), []byte(tok+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				writeJSON(t, filepath.Join(dir, "params.json"), params)
				writeJSON(t, filepath.Join(dir, "label.json"), labels)
			}
			tok, err := os.ReadFile(filepath.Join(dir, "token.txt"))
			if err != nil {
				t.Fatalf("%v (run with -update)", err)
			}
			var params struct {
				Expected expected.Expected `json:"expected"`
				Keys     jwt.Keys          `json:"keys"`
			}
			readJSON(t, filepath.Join(dir, "params.json"), &params)
			res, err := diag.Run(context.Background(), diag.Input{Artifact: string(tok), Expected: params.Expected, Keys: params.Keys, Now: fixture.FixedNow})
			if err != nil {
				t.Fatal(err)
			}
			got := project(res)
			if *update {
				writeJSON(t, filepath.Join(dir, "expected.json"), got)
			}
			var want golden
			readJSON(t, filepath.Join(dir, "expected.json"), &want)
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("expected.json mismatch (-want +got):\n%s", diff)
			}
			var labels []fixture.Label
			readJSON(t, filepath.Join(dir, "label.json"), &labels)
			for _, l := range labels {
				if !hasCode(res.Report, l.Code) {
					t.Errorf("label %s not found in %v", l.Code, codes(res.Report))
				}
			}
			out, _ := json.Marshal(res.JWT)
			assertNoLeak(t, res, string(out))
		})
	}
}

// TestGoldenDiscovery and TestGoldenOAuth follow the SAML/JWT harness for
// the v1 kinds: the artifact and params are regenerated with -update, the
// projection must match, and the labelled code must be found.
func TestGoldenDiscovery(t *testing.T) {
	_, dp := fixture.DefaultDiscovery()
	for _, c := range discoveryCases() {
		t.Run(c.Name, func(t *testing.T) {
			dir := filepath.Join(testdataRoot, "oidc", c.Name)
			if *update {
				var muts []fixture.DiscoveryMutator
				if c.Mutator != "" {
					m, ok := fixture.DiscoveryMutatorByName(c.Mutator)
					if !ok {
						t.Fatalf("no mutator %s", c.Mutator)
					}
					muts = append(muts, m)
				}
				doc, labels, err := fixture.MintDiscovery(dp, muts...)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "document.json"), append(doc, '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
				writeJSON(t, filepath.Join(dir, "params.json"), expected.Expected{Issuer: dp.Issuer})
				writeJSON(t, filepath.Join(dir, "label.json"), labels)
			}
			runGolden(t, dir, "document.json")
		})
	}
}

func TestGoldenOAuth(t *testing.T) {
	for _, c := range oauthCases() {
		t.Run(c.Name, func(t *testing.T) {
			dir := filepath.Join(testdataRoot, "oauth", c.Name)
			if *update {
				var muts []fixture.OAuthMutator
				if c.Mutator != "" {
					m, ok := fixture.OAuthMutatorByName(c.Mutator)
					if !ok {
						t.Fatalf("no mutator %s", c.Mutator)
					}
					muts = append(muts, m)
				}
				art, exp, labels, err := fixture.MintOAuth(fixture.DefaultOAuthParams(), muts...)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "artifact.txt"), []byte(art+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				writeJSON(t, filepath.Join(dir, "params.json"), exp)
				writeJSON(t, filepath.Join(dir, "label.json"), labels)
			}
			runGolden(t, dir, "artifact.txt")
		})
	}
}

// runGolden is the shared read-run-compare half for kinds whose params.json
// is a bare Expected.
func runGolden(t *testing.T, dir, artifactFile string) {
	t.Helper()
	art, err := os.ReadFile(filepath.Join(dir, artifactFile))
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	var exp expected.Expected
	readJSON(t, filepath.Join(dir, "params.json"), &exp)
	res, err := diag.Run(context.Background(), diag.Input{Artifact: string(art), Expected: exp, Now: fixture.FixedNow})
	if err != nil {
		t.Fatal(err)
	}
	got := project(res)
	if *update {
		writeJSON(t, filepath.Join(dir, "expected.json"), got)
	}
	var want golden
	readJSON(t, filepath.Join(dir, "expected.json"), &want)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("expected.json mismatch (-want +got):\n%s", diff)
	}
	var labels []fixture.Label
	readJSON(t, filepath.Join(dir, "label.json"), &labels)
	for _, l := range labels {
		if !hasCode(res.Report, l.Code) {
			t.Errorf("label %s not found in %v", l.Code, codes(res.Report))
		}
	}
	// Every path a validator cited must be one an explainer may cite.
	known := map[string]bool{}
	for _, p := range diag.KnownPaths(res) {
		known[p] = true
	}
	for _, f := range res.Report.Findings {
		for _, e := range f.Evidence {
			if !known[e.Path] {
				t.Errorf("evidence path %s missing from KnownPaths", e.Path)
			}
		}
	}
	assertNoLeak(t, res, diag.RedactedText(res, 1<<20))
}

// TestNoStrayCaseDirs: every directory under testdata must be in the case
// list, so a renamed mutator cannot leave a stale case behind.
func TestNoStrayCaseDirs(t *testing.T) {
	want := map[string]bool{}
	for _, c := range samlCases() {
		want["saml/"+c.Name] = true
	}
	for _, c := range jwtCases() {
		want["jwt/"+c.Name] = true
	}
	for _, c := range discoveryCases() {
		want["oidc/"+c.Name] = true
	}
	for _, c := range oauthCases() {
		want["oauth/"+c.Name] = true
	}
	for _, proto := range []string{"saml", "jwt", "oidc", "oauth"} {
		entries, err := os.ReadDir(filepath.Join(testdataRoot, proto))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() && !want[proto+"/"+e.Name()] {
				t.Errorf("stray case directory testdata/%s/%s", proto, e.Name())
			}
		}
	}
}

// fixtureSecrets are the identity values every fixture carries. None may
// appear in any output of the pipeline.
var fixtureSecrets = []string{"alice@example.com", "Alice", "Admins", "Everyone", "Mallory",
	"user-00000000-1111-2222-3333-444444444444", "access-token-secret",
	fixture.DefaultOAuthParams().Code, fixture.DefaultOAuthParams().CodeVerifier}

func assertNoLeak(t *testing.T, res *diag.Result, extra string) {
	t.Helper()
	report, _ := json.Marshal(res.Report)
	text := diag.Text(res.Report, res.TopCause)
	for _, out := range []string{string(report), text, extra} {
		for _, s := range fixtureSecrets {
			if strings.Contains(out, s) {
				t.Errorf("output leaks %q", s)
			}
		}
	}
}

func hasCode(r *finding.Report, c finding.Code) bool {
	for _, f := range r.Findings {
		if f.Code == c {
			return true
		}
	}
	return false
}

func codes(r *finding.Report) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, string(f.Code))
	}
	sort.Strings(out)
	return out
}

func TestTextRendersTopCauseAndNeeds(t *testing.T) {
	k, _ := fixture.TestKeys()
	m, _ := fixture.SAMLMutator("audience_mismatch")
	minted, _ := fixture.MintSAML(fixture.DefaultParams(), k, m)
	res, err := diag.Run(context.Background(), diag.Input{Artifact: string(minted.XML), Expected: expected.Expected{SPEntityID: minted.Params.SPEntityID}, Now: fixture.FixedNow})
	if err != nil {
		t.Fatal(err)
	}
	txt := diag.Text(res.Report, res.TopCause)
	for _, want := range []string{"Top cause: SAML_AUDIENCE_MISMATCH", "fix:", "Supply to unskip checks:", "acs_url"} {
		if !strings.Contains(txt, want) {
			t.Errorf("text missing %q:\n%s", want, txt)
		}
	}
	if _, err := diag.Run(context.Background(), diag.Input{Artifact: "hello"}); err == nil {
		t.Error("unknown kind must error")
	}
}
