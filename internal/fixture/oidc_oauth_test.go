// SPDX-License-Identifier: Apache-2.0

// External test package: it imports oidc and oauth, which fixture itself
// must never do (their tests import fixture).
package fixture_test

import (
	"encoding/json"
	"testing"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/fixture"
	"github.com/jamesonarnett/idpdoctor/internal/oauth"
	"github.com/jamesonarnett/idpdoctor/internal/oidc"
)

func evidenceAt(r *finding.Report, code finding.Code, path string) bool {
	for _, f := range r.Findings {
		for _, e := range f.Evidence {
			if f.Code == code && e.Path == path {
				return true
			}
		}
	}
	return false
}

func TestNewMutatorsAreWellFormed(t *testing.T) {
	type entry struct {
		name string
		code finding.Code
	}
	var all []entry
	for _, m := range fixture.DiscoveryMutators() {
		all = append(all, entry{m.Name, m.Code})
		if got, ok := fixture.DiscoveryMutatorByName(m.Name); !ok || got.Name != m.Name {
			t.Errorf("DiscoveryMutatorByName(%s) failed", m.Name)
		}
	}
	for _, m := range fixture.OAuthMutators() {
		all = append(all, entry{m.Name, m.Code})
		if got, ok := fixture.OAuthMutatorByName(m.Name); !ok || got.Name != m.Name {
			t.Errorf("OAuthMutatorByName(%s) failed", m.Name)
		}
	}
	seen := map[string]bool{}
	for _, e := range all {
		if e.name == "" || e.code == "" {
			t.Errorf("mutator with empty name or code: %+v", e)
		}
		if _, ok := finding.Lookup(e.code); !ok {
			t.Errorf("mutator %s -> code %s not in finding.Catalog", e.name, e.code)
		}
		if seen[e.name] {
			t.Errorf("duplicate mutator name %s", e.name)
		}
		seen[e.name] = true
	}
}

// TestCatalogMutatorsResolve is the cross-registry version of
// TestEveryCatalogMutatorExists: a catalog Mutator name may live in any of
// the four registries.
func TestCatalogMutatorsResolve(t *testing.T) {
	for _, s := range finding.Catalog {
		if s.Mutator == "" {
			continue
		}
		_, a := fixture.SAMLMutator(s.Mutator)
		_, b := fixture.JWTMutatorByName(s.Mutator)
		d, c := fixture.DiscoveryMutatorByName(s.Mutator)
		o, e := fixture.OAuthMutatorByName(s.Mutator)
		if !a && !b && !c && !e {
			t.Errorf("%s names mutator %q which does not exist", s.Code, s.Mutator)
		}
		if (c && d.Code != s.Code) || (e && o.Code != s.Code) {
			t.Errorf("%s names mutator %q which produces a different code", s.Code, s.Mutator)
		}
	}
}

// TestMintDiscoveryRoundTrip is the eval generator's contract: mint, check,
// find the labelled code at the labelled path.
func TestMintDiscoveryRoundTrip(t *testing.T) {
	doc0, p := fixture.DefaultDiscovery()
	if doc0["issuer"] != fixture.DefaultJWTParams().Issuer || p.Issuer != fixture.DefaultJWTParams().Issuer {
		t.Fatalf("discovery issuer %v does not agree with the JWT fixture", doc0["issuer"])
	}
	healthy, labels, err := fixture.MintDiscovery(p)
	if err != nil || len(labels) != 0 {
		t.Fatal(err, labels)
	}
	res, err := oidc.Check(healthy, oidc.Options{ExpectedIssuer: p.Issuer})
	if err != nil || len(res.Report.Findings) != 0 {
		t.Fatalf("healthy discovery: %v %+v", err, res)
	}
	for _, m := range fixture.DiscoveryMutators() {
		t.Run(m.Name, func(t *testing.T) {
			doc, labels, err := fixture.MintDiscovery(p, m)
			if err != nil {
				t.Fatal(err)
			}
			if !json.Valid(doc) {
				t.Fatal("not JSON")
			}
			res, err := oidc.Check(doc, oidc.Options{ExpectedIssuer: p.Issuer})
			if err != nil {
				t.Fatal(err)
			}
			l := labels[0]
			if l.Code != m.Code || !evidenceAt(res.Report, l.Code, l.Path) {
				t.Errorf("label %+v not found in %+v", l, res.Report.Findings)
			}
		})
	}
}

func TestMintOAuthRoundTrip(t *testing.T) {
	p := fixture.DefaultOAuthParams()
	if p.CodeChallenge != oauth.S256(p.CodeVerifier) || fixture.S256(p.CodeVerifier) != oauth.S256(p.CodeVerifier) {
		t.Fatal("fixture S256 disagrees with oauth.S256")
	}
	if n := len(p.CodeVerifier); n < 43 || n > 128 {
		t.Fatalf("default verifier length %d", n)
	}
	art, exp, labels, err := fixture.MintOAuth(p)
	if err != nil || len(labels) != 0 {
		t.Fatal(err, labels)
	}
	if want := p.RedirectURI + "?code=" + p.Code + "&state=" + p.State; art != want {
		t.Errorf("healthy artifact = %q, want %q", art, want)
	}
	res, err := oauth.Explain(art, exp)
	if err != nil || !res.Report.OK() || len(res.Report.Findings) != 0 {
		t.Fatalf("healthy oauth: %v %+v", err, res.Report.Findings)
	}
	for _, m := range fixture.OAuthMutators() {
		t.Run(m.Name, func(t *testing.T) {
			art, exp, labels, err := fixture.MintOAuth(p, m)
			if err != nil {
				t.Fatal(err)
			}
			res, err := oauth.Explain(art, exp)
			if err != nil {
				t.Fatalf("explain %q: %v", art, err)
			}
			l := labels[0]
			if l.Code != m.Code || !evidenceAt(res.Report, l.Code, l.Path) {
				t.Errorf("label %+v not found in %+v", l, res.Report.Findings)
			}
		})
	}
}

// TestMintDoesNotAliasParams guards the eval generator, which reuses one
// params value across many mints.
func TestMintDoesNotAliasParams(t *testing.T) {
	p := fixture.DefaultOAuthParams()
	m, _ := fixture.OAuthMutatorByName("oauth_invalid_scope")
	_, _, _, _ = fixture.MintOAuth(p, m)
	if len(p.Scopes) != 3 {
		t.Errorf("mutator leaked into caller params: %v", p.Scopes)
	}
}
