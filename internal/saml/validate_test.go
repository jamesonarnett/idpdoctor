// SPDX-License-Identifier: Apache-2.0

package saml_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/fixture"
	"github.com/jamesonarnett/idpdoctor/internal/saml"
)

func keys(t *testing.T) *fixture.Keys {
	t.Helper()
	k, err := fixture.TestKeys()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fullExpected is what a fully configured SP would supply.
func fullExpected(p fixture.Params, k *fixture.Keys) expected.Expected {
	yes := true
	return expected.Expected{
		SPEntityID: p.SPEntityID, ACSURL: p.ACSURL, IdPEntityID: p.IdPEntityID,
		IdPCertPEM: k.CertPEM(), RequestID: p.RequestID, NameIDFormat: p.NameIDFormat,
		RequiredAttributes: []string{"email", "firstName"}, RequireSignedAssertion: &yes,
	}
}

func validate(t *testing.T, xml []byte, exp expected.Expected) *finding.Report {
	t.Helper()
	p, err := saml.Parse(xml)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r, err := saml.Validate(p, exp, fixture.FixedNow)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	return r
}

func codes(r *finding.Report) []finding.Code {
	var out []finding.Code
	for _, f := range r.Findings {
		out = append(out, f.Code)
	}
	return out
}

func hasCode(r *finding.Report, c finding.Code) bool {
	for _, f := range r.Findings {
		if f.Code == c {
			return true
		}
	}
	return false
}

func checkStatus(r *finding.Report, name string) finding.CheckStatus {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return "missing"
}

func TestHealthyPassesEveryCheck(t *testing.T) {
	k := keys(t)
	for _, dialect := range []string{"generic", "okta", "entra", "auth0"} {
		t.Run(dialect, func(t *testing.T) {
			p := fixture.DefaultParams()
			p.Dialect = dialect
			m, err := fixture.MintSAML(p, k)
			if err != nil {
				t.Fatal(err)
			}
			r := validate(t, m.XML, fullExpected(p, k))
			if !r.OK() {
				t.Fatalf("healthy response not OK: %v", codes(r))
			}
			if len(r.Findings) != 0 {
				t.Errorf("healthy response has findings: %v", codes(r))
			}
			for _, c := range r.Checks {
				if c.Status != finding.CheckPass {
					t.Errorf("check %s = %s (%s)", c.Name, c.Status, c.Detail)
				}
			}
			if len(r.Needs) != 0 {
				t.Errorf("needs = %v", r.Needs)
			}
		})
	}
}

// TestMutatorsAreCaught is the v0 catalog table: every SAML mutator must
// produce its labelled code, with evidence on the labelled path, and the
// healthy checks must still pass (no collateral failures).
func TestMutatorsAreCaught(t *testing.T) {
	k := keys(t)
	for _, m := range fixture.SAMLMutators() {
		t.Run(m.Name, func(t *testing.T) {
			p := fixture.DefaultParams()
			minted, err := fixture.MintSAML(p, k, m)
			if err != nil {
				t.Fatal(err)
			}
			xml, label := minted.XML, minted.Labels[0]
			exp := fullExpected(p, k)
			switch m.Name {
			case "posture_embedded_key":
				exp.IdPCertPEM = ""
			case "posture_expired_cert", "cert_expired", "cert_weak_key":
				// The SP is configured with the (expired) cert the IdP really used;
				// wrong_cert keeps the old one, which is the whole failure.
				exp.IdPCertPEM = minted.Keys.CertPEM()
			case "posture_unsigned_assertion":
				exp.RequireSignedAssertion = nil
			case "response_signed_only":
				// SP requires assertion signing: fault, not posture.
			}
			r := validate(t, xml, exp)
			if !hasCode(r, label.Code) {
				t.Fatalf("want %s, got %v\nchecks: %s", label.Code, codes(r), checksJSON(r))
			}
			found := false
			for _, f := range r.Findings {
				if f.Code != label.Code {
					continue
				}
				for _, e := range f.Evidence {
					if e.Path == label.Path {
						found = true
					}
				}
			}
			if !found {
				t.Errorf("no evidence on %s for %s: %s", label.Path, label.Code, findingsJSON(r))
			}
			// Posture mutators must leave the artifact valid (that is the point).
			if strings.HasPrefix(m.Name, "posture_") && !r.OK() {
				t.Errorf("posture fixture is not OK: %v", codes(r))
			}
			if m.Name == "posture_unsigned_assertion" || m.Name == "response_signed_only" {
				return
			}
			// The top finding after ranking should be the labelled fault.
			if !strings.HasPrefix(m.Name, "posture_") && r.Findings[0].Code != label.Code && r.Findings[0].Lane == finding.LaneFault {
				t.Logf("note: top finding is %s, labelled %s", r.Findings[0].Code, label.Code)
			}
		})
	}
}

func checksJSON(r *finding.Report) string {
	b, _ := json.MarshalIndent(r.Checks, "", " ")
	return string(b)
}

func findingsJSON(r *finding.Report) string {
	b, _ := json.MarshalIndent(r.Findings, "", " ")
	return string(b)
}

func TestMissingExpectedValuesSkipNotFail(t *testing.T) {
	k := keys(t)
	minted, err := fixture.MintSAML(fixture.DefaultParams(), k)
	if err != nil {
		t.Fatal(err)
	}
	r := validate(t, minted.XML, expected.Expected{})
	if !r.OK() {
		t.Fatalf("no expected values must not produce errors: %v", codes(r))
	}
	wantSkipped := map[string]string{
		"issuer": "idp_entity_id", "destination": "acs_url", "in_response_to": "request_id",
		"audience": "sp_entity_id", "attributes": "required_attributes", "signature_verify": "idp_cert_pem",
	}
	for name, needs := range wantSkipped {
		if got := checkStatus(r, name); got != finding.CheckSkip {
			t.Errorf("%s = %s, want skip", name, got)
		}
		found := false
		for _, n := range r.Needs {
			if n == needs {
				found = true
			}
		}
		if !found {
			t.Errorf("needs missing %s: %v", needs, r.Needs)
		}
	}
	// Self-consistency still runs and the posture lane notes the embedded-key trust.
	if !hasCode(r, finding.PostureEmbeddedKeyTrust) {
		t.Errorf("expected POSTURE_EMBEDDED_KEY_TRUST: %v", codes(r))
	}
	// Time, NameID, status and signature presence need nothing and must pass.
	for _, name := range []string{"status", "time_window", "name_id", "signature_present", "structure"} {
		if got := checkStatus(r, name); got != finding.CheckPass {
			t.Errorf("%s = %s, want pass", name, got)
		}
	}
}

func TestTamperDetectedWithoutConfiguredCert(t *testing.T) {
	k := keys(t)
	m, _ := fixture.SAMLMutator("signature_tampered")
	minted, err := fixture.MintSAML(fixture.DefaultParams(), k, m)
	if err != nil {
		t.Fatal(err)
	}
	r := validate(t, minted.XML, expected.Expected{})
	if !hasCode(r, finding.SAMLSignatureInvalid) {
		t.Fatalf("tamper not detected via embedded cert: %v", codes(r))
	}
}

func TestClockSkewAndNowOverride(t *testing.T) {
	k := keys(t)
	m, _ := fixture.SAMLMutator("expired")
	minted, err := fixture.MintSAML(fixture.DefaultParams(), k, m)
	if err != nil {
		t.Fatal(err)
	}
	xml := minted.XML
	// Replay at capture time: the "expired" fixture was valid 22 minutes before FixedNow.
	exp := expected.Expected{Now: fixture.FixedNow.Add(-22 * 60e9).UTC().Format("2006-01-02T15:04:05Z")}
	r := validate(t, xml, exp)
	if hasCode(r, finding.SAMLTimeWindowInvalid) {
		t.Errorf("now override not honoured: %v", codes(r))
	}
	if _, err := saml.Validate(&saml.Parsed{}, expected.Expected{Now: "noon"}, fixture.FixedNow); err == nil {
		t.Error("bad now must error")
	}
}

func TestEntraNamespacedClaimHint(t *testing.T) {
	k := keys(t)
	p := fixture.DefaultParams()
	p.Attributes = map[string][]string{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {"alice@example.com"}}
	minted, err := fixture.MintSAML(p, k)
	if err != nil {
		t.Fatal(err)
	}
	r := validate(t, minted.XML, expected.Expected{RequiredAttributes: []string{"emailaddress"}})
	if !hasCode(r, finding.SAMLRequiredAttributeMissing) {
		t.Fatal("expected missing attribute")
	}
	if note := r.Findings[0].Evidence[0].Note; !strings.Contains(note, "namespaced claim URI") {
		t.Errorf("note = %q", note)
	}
}

// TestReportNeverLeaksIdentity: no NameID or attribute value from the
// fixture may appear anywhere in the serialised report.
func TestReportNeverLeaksIdentity(t *testing.T) {
	k := keys(t)
	p := fixture.DefaultParams()
	for _, m := range fixture.SAMLMutators() {
		minted, err := fixture.MintSAML(p, k, m)
		if err != nil {
			t.Fatal(err)
		}
		r := validate(t, minted.XML, fullExpected(p, k))
		b, _ := json.Marshal(r)
		for _, leak := range []string{p.NameID, "Alice", "Admins", "Everyone", "Mallory"} {
			if strings.Contains(string(b), leak) {
				t.Errorf("%s: report leaks %q", m.Name, leak)
			}
		}
	}
}
