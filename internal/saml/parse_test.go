// SPDX-License-Identifier: Apache-2.0

package saml

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// TestParseDialects is the namespace sharp edge from BUILD_PLAN 2.6: the
// same logical fields must come out of three vendors' prefix conventions.
func TestParseDialects(t *testing.T) {
	tests := []struct {
		name, issuer, audience, emailAttr string
	}{
		{"okta", "http://www.okta.com/exk1", "https://sp.example.com/saml/metadata", "email"},
		{"entra", "https://sts.windows.net/11111111-2222-3333-4444-555555555555/", "https://sp.example.com/saml/metadata", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(readDialect(t, tc.name))
			if err != nil {
				t.Fatal(err)
			}
			s := p.Summary
			if s.Issuer != tc.issuer {
				t.Errorf("issuer = %q", s.Issuer)
			}
			if s.Status.Code != StatusSuccess {
				t.Errorf("status = %q", s.Status.Code)
			}
			if s.Destination != "https://sp.example.com/saml/acs" || s.InResponseTo != "_req1" {
				t.Errorf("destination/inResponseTo = %q / %q", s.Destination, s.InResponseTo)
			}
			a := s.Assertion
			if a == nil {
				t.Fatal("no assertion parsed")
			}
			if a.Issuer != tc.issuer {
				t.Errorf("assertion issuer = %q", a.Issuer)
			}
			if a.Subject.NameID != "alice@example.com" || !a.Subject.NameIDPresent {
				t.Errorf("nameid = %+v", a.Subject)
			}
			if len(a.Conditions.Audiences) != 1 || a.Conditions.Audiences[0] != tc.audience {
				t.Errorf("audiences = %v", a.Conditions.Audiences)
			}
			if a.SubjectConfirmation.Recipient != "https://sp.example.com/saml/acs" || a.SubjectConfirmation.InResponseTo != "_req1" {
				t.Errorf("subject confirmation = %+v", a.SubjectConfirmation)
			}
			if got := a.Attributes[tc.emailAttr]; len(got) != 1 || got[0] != "alice@example.com" {
				t.Errorf("email attribute = %v (all: %v)", got, a.Attributes)
			}
			if a.AuthnContextClassRef == "" {
				t.Error("authn context missing")
			}
			if s.AssertionCount != 1 || s.Encrypted || len(s.Signatures) != 0 {
				t.Errorf("count/encrypted/signatures = %d/%v/%d", s.AssertionCount, s.Encrypted, len(s.Signatures))
			}
		})
	}
}

func TestParseStatusResponder(t *testing.T) {
	p, err := Parse(readDialect(t, "auth0"))
	if err != nil {
		t.Fatal(err)
	}
	s := p.Summary
	if !strings.HasSuffix(s.Status.Code, ":Responder") || !strings.HasSuffix(s.Status.SubCode, ":RequestDenied") || s.Status.Message != "Access denied by policy" {
		t.Errorf("status = %+v", s.Status)
	}
	if s.Assertion != nil || s.AssertionCount != 0 {
		t.Error("error responses carry no assertion")
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse([]byte("<a><b></a>")); !errors.Is(err, ErrXMLParse) {
		t.Errorf("malformed: %v", err)
	}
	if _, err := Parse([]byte(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>`)); !errors.Is(err, ErrNotResponse) {
		t.Errorf("metadata root: %v", err)
	}
	// A Response in the wrong namespace is not a Response.
	if _, err := Parse([]byte(`<Response xmlns="urn:wrong"/>`)); !errors.Is(err, ErrNotResponse) {
		t.Errorf("wrong ns: %v", err)
	}
}

// TestSummaryJSONRedacts is the property the whole threat model rests on:
// serialising a Summary can never leak the NameID or an attribute value.
func TestSummaryJSONRedacts(t *testing.T) {
	p, err := Parse(readDialect(t, "okta"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p.Summary)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, leak := range []string{"alice@example.com", "Everyone", "Admins"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q", leak)
		}
	}
	for _, keep := range []string{"http://www.okta.com/exk1", `"groups"`, `"email"`, "emailAddress", "https://sp.example.com/saml/metadata"} {
		if !strings.Contains(out, keep) {
			t.Errorf("over-redacted: %q missing", keep)
		}
	}
	// In memory the value is intact for server-side comparison.
	if p.Summary.Assertion.Subject.NameID != "alice@example.com" {
		t.Error("marshal must not mutate the summary")
	}
	if !strings.Contains(p.PrettyXML(1<<20), "[REDACTED:nameid:") || strings.Contains(p.PrettyXML(1<<20), "alice") {
		t.Error("PrettyXML must be redacted")
	}
}

func TestParseStructuralFindings(t *testing.T) {
	base := string(readDialect(t, "okta"))
	withComment := strings.Replace(base, ">alice@example.com</saml2:NameID>", ">alice@example.com<!---->.evil</saml2:NameID>", 1)
	withDoctype := `<!DOCTYPE foo [<!ENTITY x "y">]>` + base
	twoAssertions := strings.Replace(base, "</saml2:Assertion>", "</saml2:Assertion>"+base[strings.Index(base, "<saml2:Assertion"):strings.Index(base, "</saml2:Assertion>")+len("</saml2:Assertion>")], 1)

	tests := []struct {
		name string
		xml  string
		want finding.Code
	}{
		{"comment in nameid", withComment, finding.PostureParserDifferentialExposure},
		{"doctype", withDoctype, finding.PostureParserDifferentialExposure},
		{"two assertions", twoAssertions, finding.SAMLStructureInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse([]byte(tc.xml))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, f := range p.Findings {
				if f.Code == tc.want {
					found = true
				}
			}
			if !found {
				t.Errorf("want %s in %+v", tc.want, p.Findings)
			}
		})
	}
}
