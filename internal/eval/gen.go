// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/fixture"
	"github.com/jamesonarnett/idpdoctor/internal/jwt"
)

// GenOptions drives the generator (BUILD_PLAN 6.1).
type GenOptions struct {
	Seed     uint64
	PerClass int // fault cases per catalog class that has a mutator
	// Controls is the number of healthy controls, spread over SAML
	// dialects, JWT, discovery and OAuth; a third carry a misleading symptom.
	Controls int
	// PerPosture is the number of validating artifacts per posture code;
	// 0 means max(1, PerClass/2).
	PerPosture int
	// Templates is the symptom_templates directory (every *.json file in
	// it is a map code -> []string); "" means vendor strings only.
	Templates string
	Out       string
}

// Dialects the SAML fixtures rotate through.
var dialects = []string{"generic", "okta", "entra", "auth0"}

// Gen writes the dataset and returns the cases. Everything is derived from
// the seed via a PCG stream per decision so adding a class does not
// reshuffle unrelated cases.
func Gen(o GenOptions) ([]*Case, error) {
	if o.PerClass <= 0 {
		o.PerClass = 1
	}
	if o.PerPosture <= 0 {
		o.PerPosture = max(1, o.PerClass/2)
	}
	tmpl, err := LoadTemplates(o.Templates)
	if err != nil {
		return nil, err
	}
	keys, err := fixture.TestKeys()
	if err != nil {
		return nil, err
	}
	g := &generator{o: o, tmpl: tmpl, keys: keys}
	if err := os.MkdirAll(filepath.Join(o.Out, "cases"), 0o755); err != nil {
		return nil, err
	}
	var cases []*Case
	for _, spec := range finding.Catalog {
		if spec.Mutator == "" {
			continue
		}
		n := o.PerClass
		if spec.Lane == finding.LanePosture {
			n = o.PerPosture
		}
		for i := 0; i < n; i++ {
			c, err := g.faultCase(spec, i)
			if err != nil {
				return nil, fmt.Errorf("gen %s #%d: %w", spec.Code, i, err)
			}
			cases = append(cases, c)
		}
	}
	for i := 0; i < o.Controls; i++ {
		c, err := g.control(i)
		if err != nil {
			return nil, fmt.Errorf("gen control #%d: %w", i, err)
		}
		cases = append(cases, c)
	}
	for _, c := range cases {
		if err := c.Write(o.Out); err != nil {
			return nil, err
		}
	}
	manifest := map[string]any{"seed": o.Seed, "per_class": o.PerClass, "per_posture": o.PerPosture, "controls": o.Controls, "cases": len(cases), "templates": o.Templates}
	b, _ := json.MarshalIndent(manifest, "", "  ")
	return cases, os.WriteFile(filepath.Join(o.Out, "manifest.json"), append(b, '\n'), 0o644)
}

type generator struct {
	o    GenOptions
	tmpl Templates
	keys *fixture.Keys
}

// jwks is the OP's published key set for the JWT fixtures.
func (g *generator) jwks() jwt.Keys {
	return jwt.Keys{JWKSJSON: fixture.JWKS(fixture.RSAJWK(fixture.DefaultJWTParams().KID, &g.keys.Key.PublicKey))}
}

// truth runs the deterministic pipeline on a case with its current
// (full) expected values and returns the top cause code or HEALTHY.
func (g *generator) truth(c *Case) string {
	res, err := diag.Run(context.Background(), diag.Input{Artifact: c.Artifact, Expected: c.Expected, Keys: c.Keys, Now: fixture.FixedNow})
	if err != nil {
		return "ERROR: " + err.Error()
	}
	if res.TopCause == nil {
		return "HEALTHY"
	}
	return string(res.TopCause.Code)
}

// rng returns a stream seeded from the global seed and a label, so each
// decision is independent of generation order.
func (g *generator) rng(label string, i int) *rand.Rand {
	var h uint64 = 1469598103934665603
	for _, b := range []byte(label) {
		h = (h ^ uint64(b)) * 1099511628211
	}
	return rand.New(rand.NewPCG(g.o.Seed, h+uint64(i)))
}

// mutatorsFor lists every mutator (across registries) that produces code;
// the catalog names one, the registries may hold several variants.
func mutatorsFor(code finding.Code) (saml []fixture.Mutator, jwt []fixture.JWTMutator, disc []fixture.DiscoveryMutator, oa []fixture.OAuthMutator) {
	for _, m := range fixture.SAMLMutators() {
		if m.Code == code {
			saml = append(saml, m)
		}
	}
	for _, m := range fixture.JWTMutators() {
		if m.Code == code {
			jwt = append(jwt, m)
		}
	}
	for _, m := range fixture.DiscoveryMutators() {
		if m.Code == code {
			disc = append(disc, m)
		}
	}
	for _, m := range fixture.OAuthMutators() {
		if m.Code == code {
			oa = append(oa, m)
		}
	}
	return
}

// faultCase mints case i of a class, rotating mutator variant, dialect,
// symptom template and expected completeness.
func (g *generator) faultCase(spec finding.Spec, i int) (*Case, error) {
	r := g.rng(string(spec.Code), i)
	saml, jwt, disc, oa := mutatorsFor(spec.Code)
	variants := len(saml) + len(jwt) + len(disc) + len(oa)
	if variants == 0 {
		return nil, fmt.Errorf("no mutator registered for %s", spec.Code)
	}
	var c *Case
	var label fixture.Label
	var err error
	// Rotate through the variants; a variant whose deterministic verdict is
	// not the class (cert_expired validates with a warning, by design) is
	// skipped so the label is always the pipeline's own truth.
	for attempt := 0; attempt < variants; attempt++ {
		c, label, err = g.mint(spec, i, (i+attempt)%variants, saml, jwt, disc, oa)
		if err != nil {
			return nil, err
		}
		if spec.Lane == finding.LanePosture || g.truth(c) == string(spec.Code) {
			break
		}
		c = nil
	}
	if c == nil {
		return nil, fmt.Errorf("no variant of %s diagnoses as itself under full expected", spec.Code)
	}
	c.Label = Label{Code: string(spec.Code), PostureCodes: []string{}, EvidencePath: label.Path, FixKeys: fixKeys(spec), Needs: label.Needs}
	if spec.Lane == finding.LanePosture {
		// A validating artifact with an unsafe property: the root cause is
		// HEALTHY and the posture code must be reported alongside.
		c.Label.Code = "HEALTHY"
		c.Label.PostureCodes = []string{string(spec.Code)}
	}
	c.Expected = withhold(c.Expected, c.Meta.Completeness, label.Needs)
	c.Symptom, c.Meta.SymptomFrom = g.tmpl.pick(r, string(spec.Code))
	c.Meta.ID = fmt.Sprintf("%s-%02d", strings.ToLower(string(spec.Code)), i)
	return c, nil
}

// mint builds variant v of class i without labelling it.
func (g *generator) mint(spec finding.Spec, i, v int, saml []fixture.Mutator, jwt []fixture.JWTMutator, disc []fixture.DiscoveryMutator, oa []fixture.OAuthMutator) (*Case, fixture.Label, error) {
	c := &Case{Meta: Meta{Seed: g.o.Seed, Index: i, Completeness: completeness(i)}}
	var label fixture.Label
	var err error
	switch {
	case v < len(saml):
		m := saml[v]
		p := fixture.DefaultParams()
		// Rotate dialects by index (offset by the seed) rather than drawing
		// at random: every class sees every dialect, and no two cases of a
		// class collide on content.
		p.Dialect = dialects[(i+int(g.o.Seed))%len(dialects)]
		c.Meta.Dialect, c.Meta.Kind, c.Meta.Mutator = p.Dialect, "saml_response", m.Name
		var minted *fixture.Minted
		minted, err = fixture.MintSAML(p, g.keys, m)
		if err != nil {
			return nil, label, err
		}
		c.Artifact = string(minted.XML)
		c.Expected = samlExpected(p, g.keys, m.Name, minted)
		label = minted.Labels[0]
	case v < len(saml)+len(jwt):
		m := jwt[v-len(saml)]
		p := fixture.DefaultJWTParams()
		c.Meta.Kind, c.Meta.Mutator = "jwt", m.Name
		var tok string
		var labels []fixture.Label
		var eff fixture.JWTParams
		tok, labels, eff, err = fixture.MintJWTFull(p, g.keys.Key, m)
		if err != nil {
			return nil, label, err
		}
		c.Artifact = tok
		c.Expected = jwtExpected(p, eff)
		c.Keys = g.jwks()
		label = labels[0]
	case v < len(saml)+len(jwt)+len(disc):
		m := disc[v-len(saml)-len(jwt)]
		_, dp := fixture.DefaultDiscovery()
		c.Meta.Kind, c.Meta.Mutator = "oidc_discovery", m.Name
		var doc []byte
		var labels []fixture.Label
		doc, labels, err = fixture.MintDiscovery(dp, m)
		if err != nil {
			return nil, label, err
		}
		c.Artifact = string(doc)
		c.Expected = expected.Expected{Issuer: dp.Issuer}
		label = labels[0]
	default:
		m := oa[v-len(saml)-len(jwt)-len(disc)]
		c.Meta.Kind, c.Meta.Mutator = "oauth_redirect", m.Name
		var labels []fixture.Label
		c.Artifact, c.Expected, labels, err = fixture.MintOAuth(fixture.DefaultOAuthParams(), m)
		if err != nil {
			return nil, label, err
		}
		label = labels[0]
	}
	return c, label, nil
}

// control mints healthy artifact i, rotating over kinds and dialects. A
// third carry a misleading symptom ("SSO is broken") so the false-positive
// rate is measured under pressure.
func (g *generator) control(i int) (*Case, error) {
	r := g.rng("control", i)
	c := &Case{Meta: Meta{Seed: g.o.Seed, Index: i, Completeness: "full"}}
	kinds := []string{"saml_response", "saml_response", "jwt", "oidc_discovery", "oauth_redirect"}
	kind := kinds[i%len(kinds)]
	c.Meta.Kind = kind
	switch kind {
	case "saml_response":
		p := fixture.DefaultParams()
		// Two SAML slots per cycle, so index by i (not the cycle) to keep
		// consecutive SAML controls on different dialects.
		p.Dialect = dialects[i%len(dialects)]
		c.Meta.Dialect = p.Dialect
		minted, err := fixture.MintSAML(p, g.keys)
		if err != nil {
			return nil, err
		}
		c.Artifact = string(minted.XML)
		c.Expected = samlExpected(p, g.keys, "", minted)
	case "jwt":
		p := fixture.DefaultJWTParams()
		tok, _, eff, err := fixture.MintJWTFull(p, g.keys.Key)
		if err != nil {
			return nil, err
		}
		c.Artifact = tok
		c.Expected = jwtExpected(p, eff)
		c.Keys = g.jwks()
	case "oidc_discovery":
		_, dp := fixture.DefaultDiscovery()
		doc, _, err := fixture.MintDiscovery(dp)
		if err != nil {
			return nil, err
		}
		c.Artifact = string(doc)
		c.Expected = expected.Expected{Issuer: dp.Issuer}
	default:
		art, exp, _, err := fixture.MintOAuth(fixture.DefaultOAuthParams())
		if err != nil {
			return nil, err
		}
		c.Artifact, c.Expected = art, exp
	}
	c.Label = Label{Code: "HEALTHY", PostureCodes: []string{}, FixKeys: []string{"no change needed", "the artifact validates"}}
	if i%3 == 2 {
		c.Symptom = misleading[r.IntN(len(misleading))]
		c.Meta.SymptomFrom, c.Meta.Misleading = "misleading", true
	}
	c.Meta.ID = fmt.Sprintf("healthy-%s-%02d", strings.ReplaceAll(kind, "_", ""), i)
	return c, nil
}

// misleading symptoms for controls: true complaints about a healthy artifact.
var misleading = []string{
	"Users say SSO is broken since this morning, nothing changed on our side.",
	"Login loops back to the IdP; here is the response we captured.",
	"Getting a generic 'Authentication failed' from our SP library.",
	"One user cannot log in; everyone else is fine. Captured their response.",
}

// completeness rotates full / partial / none so abstention is measured:
// most cases are full, one in four withholds an unrelated field, one in
// eight withholds the field the class needs.
func completeness(i int) string {
	switch {
	case i%8 == 7:
		return "none"
	case i%4 == 3:
		return "partial"
	}
	return "full"
}

// withhold removes expected fields per the completeness level. "none"
// removes exactly the fields the class needs, which makes the deterministic
// pipeline skip the decisive check; the right answer is then to ask.
func withhold(e expected.Expected, level string, needs []string) expected.Expected {
	switch level {
	case "none":
		for _, n := range needs {
			clearField(&e, n)
		}
	case "partial":
		// Drop request_id / nonce: real tickets rarely include them and no
		// class in the dataset depends on them unless it is in needs.
		for _, n := range []string{"request_id", "nonce"} {
			if !contains(needs, n) {
				clearField(&e, n)
			}
		}
	}
	return e
}

func clearField(e *expected.Expected, name string) {
	switch name {
	case "sp_entity_id":
		e.SPEntityID = ""
	case "acs_url":
		e.ACSURL = ""
	case "idp_entity_id":
		e.IdPEntityID = ""
	case "idp_cert_pem":
		e.IdPCertPEM = ""
	case "request_id":
		e.RequestID = ""
	case "name_id_format":
		e.NameIDFormat = ""
	case "required_attributes":
		e.RequiredAttributes = nil
	case "require_signed_assertion":
		e.RequireSignedAssertion = nil
	case "issuer":
		e.Issuer = ""
	case "client_id":
		e.ClientID = ""
	case "nonce":
		e.Nonce = ""
	case "access_token":
		e.AccessToken = ""
	case "registered_redirect_uris":
		e.RegisteredRedirectURIs = nil
	case "code_verifier":
		e.CodeVerifier = ""
	case "client_type":
		e.ClientType = ""
	}
}

// samlExpected is the SP configuration that matches the healthy params,
// adjusted for the mutators whose point is the SP side (mirrors the golden
// harness Tweak rules).
func samlExpected(p fixture.Params, keys *fixture.Keys, mutator string, minted *fixture.Minted) expected.Expected {
	yes := true
	e := expected.Expected{
		SPEntityID: p.SPEntityID, ACSURL: p.ACSURL, IdPEntityID: p.IdPEntityID, IdPCertPEM: keys.CertPEM(),
		RequestID: p.RequestID, NameIDFormat: p.NameIDFormat, RequiredAttributes: []string{"email", "firstName"},
		RequireSignedAssertion: &yes, Now: fixture.FixedNow.Format("2006-01-02T15:04:05Z"),
	}
	switch mutator {
	case "posture_embedded_key":
		e.IdPCertPEM = ""
	case "posture_expired_cert", "cert_expired", "cert_weak_key":
		e.IdPCertPEM = minted.Keys.CertPEM()
	case "posture_unsigned_assertion", "posture_encrypted_unsigned":
		e.RequireSignedAssertion = nil
	}
	return e
}

func jwtExpected(p, eff fixture.JWTParams) expected.Expected {
	return expected.Expected{Issuer: p.Issuer, ClientID: p.Audience, Nonce: p.Nonce, AccessToken: eff.AccessToken, Now: fixture.FixedNow.Format("2006-01-02T15:04:05Z")}
}

// fixKeys derives the judge's fix concepts from the catalog fix text: the
// first clause's content words. Hand labels can refine them later.
func fixKeys(spec finding.Spec) []string {
	first := spec.Fix
	if i := strings.IndexAny(first, ";."); i > 0 {
		first = first[:i]
	}
	var keys []string
	for _, w := range strings.Fields(strings.ToLower(first)) {
		w = strings.TrimSuffix(strings.Trim(w, "(),'\""), "'s")
		if len(w) > 4 && !stopword[w] {
			keys = append(keys, w)
		}
		if len(keys) == 4 {
			break
		}
	}
	return keys
}

var stopword = map[string]bool{"exactly": true, "including": true, "should": true, "their": true, "before": true, "whether": true, "against": true, "rather": true}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// Templates maps a code to candidate symptom strings.
type Templates map[string][]string

// LoadTemplates merges every *.json file in dir (each a map code ->
// []string). Missing dir is an empty set, so `eval gen` works before any
// template exists.
func LoadTemplates(dir string) (Templates, error) {
	t := Templates{}
	if dir == "" {
		return t, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return t, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var m map[string][]string
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		for code, list := range m {
			for _, s := range list {
				t[code] = append(t[code], e.Name()+": "+s)
			}
		}
	}
	for code := range t {
		sort.Strings(t[code])
	}
	return t, nil
}

// pick returns a symptom for code, or "" about 30% of the time (tickets
// often arrive with no error text). The source file is reported in meta.
func (t Templates) pick(r *rand.Rand, code string) (symptom, from string) {
	list := t[code]
	if len(list) == 0 || r.IntN(10) < 3 {
		return "", ""
	}
	entry := list[r.IntN(len(list))]
	from, symptom, _ = strings.Cut(entry, ": ")
	return symptom, from
}
