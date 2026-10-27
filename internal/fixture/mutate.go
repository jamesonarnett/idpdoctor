// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"sort"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/saml"
)

// Phase says whether a mutator runs before signing (semantic classes: the
// signature stays valid, the content is wrong) or after (tamper classes:
// the signature must break). This is gosaml2's signResponseWithTimes
// pattern generalised.
type Phase int

const (
	PhasePreSign Phase = iota
	PhasePostSign
)

// Label is what a mutator promises the validators will find: the code and
// the evidence path, so the evidence metric is checkable.
type Label struct {
	Code finding.Code `json:"code"`
	Path string       `json:"path"`
	Note string       `json:"note,omitempty"`
	// Needs lists expected-values the validator must be given to catch
	// this class (e.g. sp_entity_id); documentation for the eval generator.
	Needs []string `json:"needs,omitempty"`
}

// Mutator produces one failure class from a healthy Response.
type Mutator struct {
	Name  string
	Code  finding.Code
	Phase Phase
	Apply func(doc *etree.Document, p *Params) Label
}

// samlMutators is keyed by the Mutator name in finding.Catalog.
var samlMutators = map[string]Mutator{}

func register(m Mutator) { samlMutators[m.Name] = m }

// SAMLMutator looks a mutator up by catalog name.
func SAMLMutator(name string) (Mutator, bool) {
	m, ok := samlMutators[name]
	return m, ok
}

// SAMLMutators returns every SAML mutator in name order.
func SAMLMutators() []Mutator {
	out := make([]Mutator, 0, len(samlMutators))
	for _, m := range samlMutators {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// first finds the first descendant with the namespace and tag.
func first(root *etree.Element, ns, tag string) *etree.Element {
	if root.Tag == tag && root.NamespaceURI() == ns {
		return root
	}
	for _, c := range root.ChildElements() {
		if f := first(c, ns, tag); f != nil {
			return f
		}
	}
	return nil
}

// all finds every descendant with the namespace and tag.
func all(root *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	if root.Tag == tag && root.NamespaceURI() == ns {
		out = append(out, root)
	}
	for _, c := range root.ChildElements() {
		out = append(out, all(c, ns, tag)...)
	}
	return out
}

func setAttr(el *etree.Element, key, val string) {
	if el != nil {
		el.RemoveAttr(key)
		el.CreateAttr(key, val)
	}
}

func init() {
	register(Mutator{Name: "audience_mismatch", Code: finding.SAMLAudienceMismatch, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			// The classic: a trailing slash the IdP admin typed.
			first(doc.Root(), saml.NSAssertion, "Audience").SetText(p.SPEntityID + "/")
			return Label{Code: finding.SAMLAudienceMismatch, Path: saml.PathAudience, Needs: []string{"sp_entity_id"}}
		}})

	register(Mutator{Name: "destination_mismatch", Code: finding.SAMLDestinationOrRecipientMismatch, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			// Staging ACS configured on the IdP, prod SP receiving it.
			setAttr(doc.Root(), "Destination", "https://sp-staging.example.com/saml/acs")
			return Label{Code: finding.SAMLDestinationOrRecipientMismatch, Path: saml.PathResponseDestination, Needs: []string{"acs_url"}}
		}})

	register(Mutator{Name: "recipient_mismatch", Code: finding.SAMLDestinationOrRecipientMismatch, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			setAttr(first(doc.Root(), saml.NSAssertion, "SubjectConfirmationData"), "Recipient", "http://sp.example.com/saml/acs")
			return Label{Code: finding.SAMLDestinationOrRecipientMismatch, Path: saml.PathRecipient, Needs: []string{"acs_url"}}
		}})

	register(Mutator{Name: "expired", Code: finding.SAMLTimeWindowInvalid, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			// Captured 20 minutes ago and replayed now: the usual "it worked in the morning" ticket.
			cond := first(doc.Root(), saml.NSAssertion, "Conditions")
			setAttr(cond, "NotBefore", ts(p.Now.Add(-25*time.Minute)))
			setAttr(cond, "NotOnOrAfter", ts(p.Now.Add(-20*time.Minute)))
			setAttr(first(doc.Root(), saml.NSAssertion, "SubjectConfirmationData"), "NotOnOrAfter", ts(p.Now.Add(-20*time.Minute)))
			return Label{Code: finding.SAMLTimeWindowInvalid, Path: saml.PathConditionsNotOnOrAfter}
		}})

	register(Mutator{Name: "not_yet_valid", Code: finding.SAMLTimeWindowInvalid, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			// IdP clock 10 minutes ahead: beyond any sane skew.
			cond := first(doc.Root(), saml.NSAssertion, "Conditions")
			setAttr(cond, "NotBefore", ts(p.Now.Add(10*time.Minute)))
			setAttr(cond, "NotOnOrAfter", ts(p.Now.Add(15*time.Minute)))
			return Label{Code: finding.SAMLTimeWindowInvalid, Path: saml.PathConditionsNotBefore}
		}})

	register(Mutator{Name: "issuer_mismatch", Code: finding.SAMLIssuerMismatch, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			for _, iss := range all(doc.Root(), saml.NSAssertion, "Issuer") {
				iss.SetText(p.IdPEntityID + "/")
			}
			return Label{Code: finding.SAMLIssuerMismatch, Path: saml.PathResponseIssuer, Needs: []string{"idp_entity_id"}}
		}})

	register(Mutator{Name: "in_response_to_mismatch", Code: finding.SAMLInResponseToMismatch, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			setAttr(doc.Root(), "InResponseTo", "_req_stale_from_another_tab")
			setAttr(first(doc.Root(), saml.NSAssertion, "SubjectConfirmationData"), "InResponseTo", "_req_stale_from_another_tab")
			return Label{Code: finding.SAMLInResponseToMismatch, Path: saml.PathResponseInResponseTo, Needs: []string{"request_id"}}
		}})

	register(Mutator{Name: "unsolicited", Code: finding.SAMLInResponseToMismatch, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			doc.Root().RemoveAttr("InResponseTo")
			first(doc.Root(), saml.NSAssertion, "SubjectConfirmationData").RemoveAttr("InResponseTo")
			return Label{Code: finding.SAMLInResponseToMismatch, Path: saml.PathResponseInResponseTo, Needs: []string{"request_id"},
				Note: "IdP-initiated response arriving at an SP that expects SP-initiated"}
		}})

	register(Mutator{Name: "nameid_missing", Code: finding.SAMLNameIDMissingOrFormatMismatch, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			nid := first(doc.Root(), saml.NSAssertion, "NameID")
			nid.Parent().RemoveChild(nid)
			return Label{Code: finding.SAMLNameIDMissingOrFormatMismatch, Path: saml.PathNameID}
		}})

	register(Mutator{Name: "nameid_format_mismatch", Code: finding.SAMLNameIDMissingOrFormatMismatch, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			setAttr(first(doc.Root(), saml.NSAssertion, "NameID"), "Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient")
			return Label{Code: finding.SAMLNameIDMissingOrFormatMismatch, Path: saml.PathNameIDFormat, Needs: []string{"name_id_format"}}
		}})

	register(Mutator{Name: "attribute_missing", Code: finding.SAMLRequiredAttributeMissing, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			for _, at := range all(doc.Root(), saml.NSAssertion, "Attribute") {
				if at.SelectAttrValue("Name", "") == "email" {
					at.Parent().RemoveChild(at)
				}
			}
			return Label{Code: finding.SAMLRequiredAttributeMissing, Path: saml.PathAttribute("email"), Needs: []string{"required_attributes"}}
		}})

	register(Mutator{Name: "status_responder", Code: finding.SAMLStatusNotSuccess, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			root := doc.Root()
			code := first(root, saml.NSProtocol, "StatusCode")
			setAttr(code, "Value", "urn:oasis:names:tc:SAML:2.0:status:Responder")
			sub := code.CreateElement(code.Space + ":StatusCode")
			if code.Space == "" {
				sub.Tag = "StatusCode"
			}
			sub.CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:RequestDenied")
			msg := code.Parent().CreateElement(code.Space + ":StatusMessage")
			msg.SetText("The user is not assigned to this application.")
			// Error responses carry no assertion and are not signed.
			if a := first(root, saml.NSAssertion, "Assertion"); a != nil {
				root.RemoveChild(a)
			}
			p.Sign = "none"
			return Label{Code: finding.SAMLStatusNotSuccess, Path: saml.PathStatusCode}
		}})

	register(Mutator{Name: "unsigned", Code: finding.SAMLNotSignedOrWrongElementSigned, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			p.Sign = "none"
			return Label{Code: finding.SAMLNotSignedOrWrongElementSigned, Path: saml.PathAssertionSignature}
		}})

	register(Mutator{Name: "response_signed_only", Code: finding.SAMLNotSignedOrWrongElementSigned, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			// SP requires a signed assertion; IdP signs only the Response.
			p.Sign = "response"
			return Label{Code: finding.SAMLNotSignedOrWrongElementSigned, Path: saml.PathAssertionSignature, Needs: []string{"require_signed_assertion"}}
		}})

	register(Mutator{Name: "signature_tampered", Code: finding.SAMLSignatureInvalid, Phase: PhasePostSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			// Change one signed byte after signing: the digest no longer matches.
			for _, v := range all(doc.Root(), saml.NSAssertion, "AttributeValue") {
				if v.Text() == "Alice" {
					v.SetText("Mallory")
				}
			}
			return Label{Code: finding.SAMLSignatureInvalid, Path: saml.PathAssertionSignature, Needs: []string{"idp_cert_pem"}}
		}})

	register(Mutator{Name: "wrong_cert", Code: finding.SAMLSignatureInvalid, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			// Signed by a key the SP has never seen (IdP rotated, SP did not).
			p.Keys = mustKeys("rotated idp", p.Now.Add(-24*time.Hour), p.Now.Add(24*time.Hour), 2048)
			return Label{Code: finding.SAMLSignatureInvalid, Path: saml.PathKeyInfoCertificate, Needs: []string{"idp_cert_pem"}}
		}})

	register(Mutator{Name: "cert_expired", Code: finding.CertExpiredOrWeak, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			p.Keys = mustKeys("expired idp", p.Now.Add(-48*time.Hour), p.Now.Add(-24*time.Hour), 2048)
			return Label{Code: finding.CertExpiredOrWeak, Path: saml.PathKeyInfoCertificate}
		}})

	register(Mutator{Name: "posture_unsigned_assertion", Code: finding.PostureUnsignedAssertionAccepted, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			p.Sign = "response"
			return Label{Code: finding.PostureUnsignedAssertionAccepted, Path: saml.PathAssertionSignature}
		}})

	register(Mutator{Name: "posture_embedded_key", Code: finding.PostureEmbeddedKeyTrust, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			// Healthy artifact; the unsafe property is on the SP side (no
			// idp_cert_pem configured), so the label says what to omit.
			return Label{Code: finding.PostureEmbeddedKeyTrust, Path: saml.PathKeyInfoCertificate, Note: "validate without idp_cert_pem"}
		}})

	register(Mutator{Name: "posture_expired_cert", Code: finding.PostureExpiredCertAccepted, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			p.Keys = mustKeys("expired idp", p.Now.Add(-48*time.Hour), p.Now.Add(-24*time.Hour), 2048)
			return Label{Code: finding.PostureExpiredCertAccepted, Path: saml.PathKeyInfoCertificate, Note: "validate with this expired cert as idp_cert_pem"}
		}})

	register(Mutator{Name: "posture_comment_in_nameid", Code: finding.PostureParserDifferentialExposure, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			// Exclusive c14n drops comments, so the signature still verifies:
			// exactly the condition under which parser differentials bite.
			nid := first(doc.Root(), saml.NSAssertion, "NameID")
			nid.SetText("alice@example.com")
			nid.AddChild(etree.NewComment(""))
			nid.AddChild(etree.NewText(".evil.example"))
			return Label{Code: finding.PostureParserDifferentialExposure, Path: saml.PathNameID}
		}})

	register(Mutator{Name: "posture_sha1", Code: finding.PostureWeakAlgorithm, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			p.SigAlg = dsig.RSASHA1SignatureMethod
			return Label{Code: finding.PostureWeakAlgorithm, Path: saml.PathSignatureMethod}
		}})

	register(Mutator{Name: "posture_long_window", Code: finding.PostureValidityWindowTooLong, Phase: PhasePreSign,
		Apply: func(doc *etree.Document, p *Params) Label {
			cond := first(doc.Root(), saml.NSAssertion, "Conditions")
			setAttr(cond, "NotBefore", ts(p.Now.Add(-time.Hour)))
			setAttr(cond, "NotOnOrAfter", ts(p.Now.Add(time.Hour)))
			setAttr(first(doc.Root(), saml.NSAssertion, "SubjectConfirmationData"), "NotOnOrAfter", ts(p.Now.Add(time.Hour)))
			return Label{Code: finding.PostureValidityWindowTooLong, Path: saml.PathConditionsNotOnOrAfter}
		}})
}

func mustKeys(cn string, nb, na time.Time, bits int) *Keys {
	k, err := GenerateKeys(cn, nb, na, bits)
	if err != nil {
		panic("fixture: generate keys: " + err.Error())
	}
	return k
}
