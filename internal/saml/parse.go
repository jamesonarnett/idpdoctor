// SPDX-License-Identifier: Apache-2.0

package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"

	"github.com/jamesonarnett/idpdoctor/internal/cert"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/redact"
)

// Parse errors.
var (
	ErrXMLParse    = errors.New("saml: xml parse failed")
	ErrNotResponse = errors.New("saml: root element is not a samlp:Response")
)

// Status is the Response status triple.
type Status struct {
	Code    string `json:"code"`
	SubCode string `json:"sub_code,omitempty"`
	Message string `json:"message,omitempty"`
}

// Subject carries the NameID. The value is real in memory (validators
// compare it server-side) and masked by Summary's JSON marshaller.
type Subject struct {
	NameID       string `json:"name_id"`
	NameIDFormat string `json:"name_id_format,omitempty"`
	// NameIDPresent distinguishes an empty NameID from a missing one once
	// the value has been redacted away.
	NameIDPresent bool `json:"name_id_present"`
}

// Conditions mirrors saml:Conditions.
type Conditions struct {
	NotBefore    string   `json:"not_before,omitempty"`
	NotOnOrAfter string   `json:"not_on_or_after,omitempty"`
	Audiences    []string `json:"audiences"`
}

// SubjectConfirmation mirrors the bearer SubjectConfirmationData.
type SubjectConfirmation struct {
	Method       string `json:"method,omitempty"`
	Recipient    string `json:"recipient,omitempty"`
	NotOnOrAfter string `json:"not_on_or_after,omitempty"`
	InResponseTo string `json:"in_response_to,omitempty"`
}

// Assertion is the parsed view of the (first) saml:Assertion.
type Assertion struct {
	ID                   string              `json:"id"`
	Issuer               string              `json:"issuer"`
	IssueInstant         string              `json:"issue_instant,omitempty"`
	Subject              Subject             `json:"subject"`
	Conditions           Conditions          `json:"conditions"`
	SubjectConfirmation  SubjectConfirmation `json:"subject_confirmation"`
	AuthnContextClassRef string              `json:"authn_context_class_ref,omitempty"`
	SessionIndex         string              `json:"session_index,omitempty"`
	SessionNotOnOrAfter  string              `json:"session_not_on_or_after,omitempty"`
	AuthnInstant         string              `json:"authn_instant,omitempty"`
	// Attributes maps attribute Name to its values. Names stay in clear;
	// values are masked on output.
	Attributes map[string][]string `json:"attributes"`
	// AttributeStatementPresent lets validators tell "no statement" from
	// "statement with no attributes".
	AttributeStatementPresent bool `json:"attribute_statement_present"`
}

// SignatureInfo describes one ds:Signature without exposing its value.
type SignatureInfo struct {
	On           string `json:"on"` // "response" | "assertion"
	SigAlg       string `json:"sig_alg,omitempty"`
	DigestAlg    string `json:"digest_alg,omitempty"`
	ReferenceURI string `json:"reference_uri,omitempty"`
	CertSHA256   string `json:"cert_sha256,omitempty"`
	CertSubject  string `json:"cert_subject,omitempty"`
	CertNotAfter string `json:"cert_not_after,omitempty"`
	// Cert is the embedded KeyInfo certificate, for posture checks; not
	// serialised (it is public, but it is large and the fingerprint suffices).
	Cert *x509.Certificate `json:"-"`
}

// Summary is the saml_decode output. It is the only SAML type that crosses
// the tool boundary, and its MarshalJSON redacts, so a caller cannot forget.
type Summary struct {
	ID             string          `json:"id"`
	Issuer         string          `json:"issuer"`
	Destination    string          `json:"destination,omitempty"`
	InResponseTo   string          `json:"in_response_to,omitempty"`
	IssueInstant   string          `json:"issue_instant,omitempty"`
	Version        string          `json:"version,omitempty"`
	Status         Status          `json:"status"`
	RelayState     string          `json:"relay_state,omitempty"`
	Assertion      *Assertion      `json:"assertion,omitempty"`
	AssertionCount int             `json:"assertion_count"`
	Encrypted      bool            `json:"encrypted"`
	Signatures     []SignatureInfo `json:"signatures"`
	// Dialect is a best-effort vendor guess from namespace prefixes and
	// attribute naming; informational only.
	Dialect string `json:"dialect,omitempty"`
}

// Parsed holds the tree alongside the Summary for validators that need the
// elements themselves (signature verification, structure checks).
type Parsed struct {
	Summary  Summary
	Doc      *etree.Document
	Response *etree.Element
	// Assertions are the direct saml:Assertion children; validators use
	// Assertions[0] and flag len > 1.
	Assertions []*etree.Element
	Raw        []byte
	// Findings are parse-level problems (DOCTYPE, comments in NameID,
	// multiple assertions) reported even when validation never runs.
	Findings []finding.Finding
}

// redactedSummary is the wire form. Declared as a distinct type so
// MarshalJSON on Summary cannot recurse.
type redactedSummary Summary

// MarshalJSON masks NameID and attribute values. Redaction is therefore a
// property of the type, not a step a caller might skip.
func (s Summary) MarshalJSON() ([]byte, error) {
	cp := redactedSummary(s)
	if s.Assertion != nil {
		a := *s.Assertion
		a.Subject.NameID = redact.Value("nameid", a.Subject.NameID)
		attrs := make(map[string][]string, len(a.Attributes))
		for name, vals := range a.Attributes {
			masked := make([]string, len(vals))
			for i, v := range vals {
				masked[i] = redact.Value("attr", v)
			}
			attrs[name] = masked
		}
		a.Attributes = attrs
		cp.Assertion = &a
	}
	return json.Marshal(cp)
}

// Parse builds a Parsed from Response XML. It never fails on semantic
// problems; only unparsable XML or a non-Response root is an error.
func Parse(xml []byte) (*Parsed, error) {
	doc := etree.NewDocument()
	doc.ReadSettings.MaxDepth = 64 // a Response is ~10 deep; anything near the cap is hostile
	if err := doc.ReadFromBytes(xml); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrXMLParse, err)
	}
	root := doc.Root()
	if root == nil {
		return nil, ErrXMLParse
	}
	if root.Tag != "Response" || root.NamespaceURI() != NSProtocol {
		return nil, fmt.Errorf("%w: got {%s}%s", ErrNotResponse, root.NamespaceURI(), root.Tag)
	}

	p := &Parsed{Doc: doc, Response: root, Raw: xml, Findings: []finding.Finding{}}
	s := &p.Summary
	s.ID = attr(root, "ID")
	s.Version = attr(root, "Version")
	s.Destination = attr(root, "Destination")
	s.InResponseTo = attr(root, "InResponseTo")
	s.IssueInstant = attr(root, "IssueInstant")
	s.Issuer = text(child(root, NSAssertion, "Issuer"))
	s.Signatures = []SignatureInfo{}

	if st := child(root, NSProtocol, "Status"); st != nil {
		code := child(st, NSProtocol, "StatusCode")
		s.Status.Code = attr(code, "Value")
		s.Status.SubCode = attr(child(code, NSProtocol, "StatusCode"), "Value")
		s.Status.Message = text(child(st, NSProtocol, "StatusMessage"))
	}

	p.Assertions = children(root, NSAssertion, "Assertion")
	s.AssertionCount = len(p.Assertions)
	s.Encrypted = child(root, NSAssertion, "EncryptedAssertion") != nil
	if len(p.Assertions) > 0 {
		s.Assertion = parseAssertion(p.Assertions[0], p)
	}

	if sig := child(root, NSDSig, "Signature"); sig != nil {
		s.Signatures = append(s.Signatures, signatureInfo(sig, "response"))
	}
	for _, a := range p.Assertions {
		if sig := child(a, NSDSig, "Signature"); sig != nil {
			s.Signatures = append(s.Signatures, signatureInfo(sig, "assertion"))
		}
	}
	s.Dialect = guessDialect(root, s)

	p.structuralFindings()
	return p, nil
}

func parseAssertion(a *etree.Element, p *Parsed) *Assertion {
	out := &Assertion{
		ID:           attr(a, "ID"),
		Issuer:       text(child(a, NSAssertion, "Issuer")),
		IssueInstant: attr(a, "IssueInstant"),
		Attributes:   map[string][]string{},
		Conditions:   Conditions{Audiences: []string{}},
	}
	if subj := child(a, NSAssertion, "Subject"); subj != nil {
		if nid := child(subj, NSAssertion, "NameID"); nid != nil {
			out.Subject.NameIDPresent = true
			out.Subject.NameID = text(nid)
			out.Subject.NameIDFormat = attr(nid, "Format")
			if hasComment(nid) {
				p.Findings = append(p.Findings, finding.New(finding.PostureParserDifferentialExposure, finding.Evidence{
					Path: PathNameID, Note: "XML comment inside NameID; parsers disagree on the resulting value",
				}))
			}
		}
		if scd := path(subj, NSAssertion, "SubjectConfirmation", NSAssertion, "SubjectConfirmationData"); scd != nil {
			out.SubjectConfirmation = SubjectConfirmation{
				Method:       attr(child(subj, NSAssertion, "SubjectConfirmation"), "Method"),
				Recipient:    attr(scd, "Recipient"),
				NotOnOrAfter: attr(scd, "NotOnOrAfter"),
				InResponseTo: attr(scd, "InResponseTo"),
			}
		} else if sc := child(subj, NSAssertion, "SubjectConfirmation"); sc != nil {
			out.SubjectConfirmation.Method = attr(sc, "Method")
		}
	}
	if cond := child(a, NSAssertion, "Conditions"); cond != nil {
		out.Conditions.NotBefore = attr(cond, "NotBefore")
		out.Conditions.NotOnOrAfter = attr(cond, "NotOnOrAfter")
		for _, ar := range children(cond, NSAssertion, "AudienceRestriction") {
			for _, aud := range children(ar, NSAssertion, "Audience") {
				out.Conditions.Audiences = append(out.Conditions.Audiences, text(aud))
			}
		}
	}
	if as := child(a, NSAssertion, "AuthnStatement"); as != nil {
		out.SessionIndex = attr(as, "SessionIndex")
		out.SessionNotOnOrAfter = attr(as, "SessionNotOnOrAfter")
		out.AuthnInstant = attr(as, "AuthnInstant")
		out.AuthnContextClassRef = text(path(as, NSAssertion, "AuthnContext", NSAssertion, "AuthnContextClassRef"))
	}
	if st := child(a, NSAssertion, "AttributeStatement"); st != nil {
		out.AttributeStatementPresent = true
		for _, at := range children(st, NSAssertion, "Attribute") {
			name := attr(at, "Name")
			vals := []string{}
			for _, v := range children(at, NSAssertion, "AttributeValue") {
				vals = append(vals, text(v))
				if hasComment(v) {
					p.Findings = append(p.Findings, finding.New(finding.PostureParserDifferentialExposure, finding.Evidence{
						Path: PathAttribute(name), Note: "XML comment inside AttributeValue",
					}))
				}
			}
			out.Attributes[name] = vals
		}
	}
	return out
}

// signatureInfo reads the public parts of a ds:Signature. The signature
// value itself is never copied out.
func signatureInfo(sig *etree.Element, on string) SignatureInfo {
	info := SignatureInfo{On: on}
	if si := child(sig, NSDSig, "SignedInfo"); si != nil {
		info.SigAlg = attr(child(si, NSDSig, "SignatureMethod"), "Algorithm")
		if ref := child(si, NSDSig, "Reference"); ref != nil {
			info.ReferenceURI = attr(ref, "URI")
			info.DigestAlg = attr(child(ref, NSDSig, "DigestMethod"), "Algorithm")
		}
	}
	if x := path(sig, NSDSig, "KeyInfo", NSDSig, "X509Data", NSDSig, "X509Certificate"); x != nil {
		if c, err := cert.Parse(text(x)); err == nil {
			info.Cert = c
			info.CertSHA256 = cert.FingerprintSHA256(c)
			info.CertSubject = c.Subject.String()
			info.CertNotAfter = c.NotAfter.UTC().Format(time.RFC3339)
		}
	}
	return info
}

// structuralFindings records parse-level problems that are findings in
// their own right regardless of expected values.
func (p *Parsed) structuralFindings() {
	raw := bytes.ToUpper(p.Raw[:min(len(p.Raw), 4096)])
	if bytes.Contains(raw, []byte("<!DOCTYPE")) || bytes.Contains(raw, []byte("<!ENTITY")) {
		p.Findings = append(p.Findings, finding.New(finding.PostureParserDifferentialExposure, finding.Evidence{
			Path: PathResponse, Note: "DOCTYPE or ENTITY declaration present; SAML responses must not carry them",
		}))
	}
	if len(p.Assertions) > 1 {
		p.Findings = append(p.Findings, finding.New(finding.SAMLStructureInvalid, finding.Evidence{
			Path: PathAssertion, Actual: fmt.Sprintf("%d assertions", len(p.Assertions)), Expected: "1",
			Note: "multiple assertions; an SP must consume only the signed one (CVE-2022-41912 class)",
		}))
	}
}

// guessDialect is a heuristic label for test realism and the text summary.
func guessDialect(root *etree.Element, s *Summary) string {
	iss := strings.ToLower(s.Issuer)
	switch {
	case strings.Contains(iss, "okta.com"):
		return "okta"
	case strings.Contains(iss, "sts.windows.net") || strings.Contains(iss, "login.microsoftonline.com"):
		return "entra"
	case strings.Contains(iss, "accounts.google.com"):
		return "google"
	case strings.Contains(iss, "auth0.com"):
		return "auth0"
	}
	if root.Space == "" {
		return "default-namespace"
	}
	return ""
}

// PrettyXML returns the document indented and redacted, truncated to max
// bytes. The tree is copied first so the Parsed stays usable.
func (p *Parsed) PrettyXML(max int) string {
	doc := p.Doc.Copy()
	redact.XML(doc.Root())
	doc.Indent(2)
	s, err := doc.WriteToString()
	if err != nil {
		return ""
	}
	return redact.Truncate(s, max)
}
