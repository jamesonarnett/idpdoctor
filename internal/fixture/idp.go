// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"crypto"
	"fmt"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/jamesonarnett/idpdoctor/internal/saml"
)

// FixedNow is the clock every committed fixture is minted against. Tests
// pass it as the validator's Now so time-window checks are deterministic.
var FixedNow = time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

// Params describes a healthy Response. It is also what params.json holds
// in testdata, minus the Go-only fields.
type Params struct {
	SPEntityID  string `json:"sp_entity_id"`
	ACSURL      string `json:"acs_url"`
	IdPEntityID string `json:"idp_entity_id"`
	RequestID   string `json:"request_id"`
	// Now is RFC 3339 in JSON so params.json stays human-editable.
	Now time.Time `json:"now"`

	NameID       string              `json:"name_id"`
	NameIDFormat string              `json:"name_id_format"`
	Attributes   map[string][]string `json:"attributes"`

	// Dialect selects namespace prefix conventions: okta (saml2p:/saml2:),
	// entra (samlp: + default namespace on assertion), auth0 (samlp:/saml:),
	// generic (samlp:/saml:). It changes nothing semantic, which is the point.
	Dialect string `json:"dialect"`
	// Sign is "response", "assertion", "both" or "none".
	Sign string `json:"sign"`
	// SigAlg defaults to RSA-SHA256; the posture_sha1 mutator sets SHA-1.
	SigAlg string `json:"sig_alg,omitempty"`
	// Validity is the assertion window length; default 5 minutes centred on Now.
	Validity time.Duration `json:"-"`
	// Unsolicited omits InResponseTo (IdP-initiated SSO).
	Unsolicited bool `json:"unsolicited,omitempty"`
	// Keys overrides the signing identity; mutators set it for the
	// wrong-cert and expired-cert classes. Nil means "use the keys passed
	// to MintSAML".
	Keys *Keys `json:"-"`
}

// DefaultParams is the healthy baseline every mutator starts from.
func DefaultParams() Params {
	return Params{
		SPEntityID:   "https://sp.example.com/saml/metadata",
		ACSURL:       "https://sp.example.com/saml/acs",
		IdPEntityID:  "https://idp.example.com/saml",
		RequestID:    "_req_1234567890abcdef",
		Now:          FixedNow,
		NameID:       "alice@example.com",
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		Attributes: map[string][]string{
			"email":     {"alice@example.com"},
			"firstName": {"Alice"},
			"groups":    {"Everyone", "Admins"},
		},
		Dialect:  "generic",
		Sign:     "assertion",
		Validity: 5 * time.Minute,
	}
}

// prefixes are the per-dialect namespace spellings.
type prefixes struct {
	proto, assertion string // prefix; "" means default namespace
}

func dialectPrefixes(d string) prefixes {
	switch d {
	case "okta":
		return prefixes{"saml2p", "saml2"}
	case "entra":
		return prefixes{"samlp", ""}
	default: // auth0, generic
		return prefixes{"samlp", "saml"}
	}
}

func ts(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// BuildResponse constructs an unsigned Response tree. Mutators run on it
// before signing (semantic classes) or after (tamper classes).
func BuildResponse(p Params) *etree.Document {
	px := dialectPrefixes(p.Dialect)
	if p.Validity == 0 {
		p.Validity = 5 * time.Minute
	}
	notBefore := p.Now.Add(-p.Validity / 2)
	notOnOrAfter := p.Now.Add(p.Validity / 2)

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)

	resp := doc.CreateElement(qn(px.proto, "Response"))
	resp.CreateAttr(xmlns(px.proto), saml.NSProtocol)
	if px.assertion != "" {
		resp.CreateAttr(xmlns(px.assertion), saml.NSAssertion)
	}
	resp.CreateAttr("ID", "_resp_"+idSuffix(p, "r"))
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", ts(p.Now))
	resp.CreateAttr("Destination", p.ACSURL)
	if !p.Unsolicited {
		resp.CreateAttr("InResponseTo", p.RequestID)
	}

	issuer := resp.CreateElement(qn(px.assertion, "Issuer"))
	if px.assertion == "" {
		issuer.CreateAttr("xmlns", saml.NSAssertion)
	}
	issuer.SetText(p.IdPEntityID)

	status := resp.CreateElement(qn(px.proto, "Status"))
	status.CreateElement(qn(px.proto, "StatusCode")).CreateAttr("Value", saml.StatusSuccess)

	a := resp.CreateElement(qn(px.assertion, "Assertion"))
	// Declare the namespace on the Assertion itself, as Okta and Entra do:
	// the assertion must canonicalise standalone when it is signed.
	a.CreateAttr(xmlns(px.assertion), saml.NSAssertion)
	a.CreateAttr("ID", "_assert_"+idSuffix(p, "a"))
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", ts(p.Now))
	a.CreateElement(qn(px.assertion, "Issuer")).SetText(p.IdPEntityID)

	subj := a.CreateElement(qn(px.assertion, "Subject"))
	nid := subj.CreateElement(qn(px.assertion, "NameID"))
	nid.CreateAttr("Format", p.NameIDFormat)
	nid.SetText(p.NameID)
	sc := subj.CreateElement(qn(px.assertion, "SubjectConfirmation"))
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement(qn(px.assertion, "SubjectConfirmationData"))
	if !p.Unsolicited {
		scd.CreateAttr("InResponseTo", p.RequestID)
	}
	scd.CreateAttr("NotOnOrAfter", ts(notOnOrAfter))
	scd.CreateAttr("Recipient", p.ACSURL)

	cond := a.CreateElement(qn(px.assertion, "Conditions"))
	cond.CreateAttr("NotBefore", ts(notBefore))
	cond.CreateAttr("NotOnOrAfter", ts(notOnOrAfter))
	cond.CreateElement(qn(px.assertion, "AudienceRestriction")).
		CreateElement(qn(px.assertion, "Audience")).SetText(p.SPEntityID)

	authn := a.CreateElement(qn(px.assertion, "AuthnStatement"))
	authn.CreateAttr("AuthnInstant", ts(p.Now.Add(-time.Minute)))
	authn.CreateAttr("SessionIndex", "_sess_"+idSuffix(p, "s"))
	authn.CreateAttr("SessionNotOnOrAfter", ts(p.Now.Add(8*time.Hour)))
	authn.CreateElement(qn(px.assertion, "AuthnContext")).
		CreateElement(qn(px.assertion, "AuthnContextClassRef")).
		SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")

	if len(p.Attributes) > 0 {
		st := a.CreateElement(qn(px.assertion, "AttributeStatement"))
		for _, name := range sortedKeys(p.Attributes) {
			at := st.CreateElement(qn(px.assertion, "Attribute"))
			at.CreateAttr("Name", name)
			at.CreateAttr("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
			for _, v := range p.Attributes[name] {
				at.CreateElement(qn(px.assertion, "AttributeValue")).SetText(v)
			}
		}
	}
	return doc
}

// Sign adds enveloped signatures per p.Sign using keys. The Signature is
// moved to sit right after Issuer, where real IdPs put it.
func Sign(doc *etree.Document, p Params, keys *Keys) error {
	if p.Sign == "none" || p.Sign == "" {
		return nil
	}
	ctx, err := dsig.NewSigningContext(keys.Key, [][]byte{keys.CertDER})
	if err != nil {
		return err
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	ctx.Hash = crypto.SHA256
	if p.SigAlg != "" {
		if err := ctx.SetSignatureMethod(p.SigAlg); err != nil {
			return err
		}
	}

	root := doc.Root()
	if p.Sign == "assertion" || p.Sign == "both" {
		for _, a := range findChildren(root, saml.NSAssertion, "Assertion") {
			if err := attachSignature(ctx, a); err != nil {
				return fmt.Errorf("sign assertion: %w", err)
			}
		}
	}
	if p.Sign == "response" || p.Sign == "both" {
		if err := attachSignature(ctx, root); err != nil {
			return fmt.Errorf("sign response: %w", err)
		}
	}
	return nil
}

// attachSignature signs a copy of el and grafts only the resulting
// ds:Signature into el at index 1 (right after Issuer, where real IdPs put
// it). Signing a copy matters: goxmldsig's exclusive canonicaliser rewrites
// the element it is given in place, which would strip the very comment
// nodes the parser-differential fixture relies on. The verifier
// canonicalises the same way, so the signature still verifies.
func attachSignature(ctx *dsig.SigningContext, el *etree.Element) error {
	signed, err := ctx.SignEnveloped(el.Copy())
	if err != nil {
		return err
	}
	n := len(signed.Child)
	sig, ok := signed.Child[n-1].(*etree.Element)
	if !ok || sig.Tag != "Signature" {
		return fmt.Errorf("SignEnveloped did not append a Signature")
	}
	el.InsertChildAt(1, sig.Copy())
	return nil
}

// Minted is MintSAML's result: the bytes plus everything a test needs to
// build the matching Expected (the keys actually used, the final params).
type Minted struct {
	XML    []byte
	Labels []Label
	Params Params
	Keys   *Keys
}

// MintSAML builds, mutates and signs a Response in one call. Mutators with
// PhasePreSign run before signing; PhasePostSign ones after. Mutators may
// change Params (signing mode, keys), so the effective Params come back.
func MintSAML(p Params, keys *Keys, muts ...Mutator) (*Minted, error) {
	doc := BuildResponse(p)
	labels := []Label{}
	for _, m := range muts {
		if m.Phase == PhasePreSign {
			labels = append(labels, m.Apply(doc, &p))
		}
	}
	if p.Keys != nil {
		keys = p.Keys
	}
	if err := Sign(doc, p, keys); err != nil {
		return nil, err
	}
	for _, m := range muts {
		if m.Phase == PhasePostSign {
			labels = append(labels, m.Apply(doc, &p))
		}
	}
	out, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}
	return &Minted{XML: out, Labels: labels, Params: p, Keys: keys}, nil
}

func qn(prefix, local string) string {
	if prefix == "" {
		return local
	}
	return prefix + ":" + local
}

func xmlns(prefix string) string {
	if prefix == "" {
		return "xmlns"
	}
	return "xmlns:" + prefix
}

// idSuffix derives stable IDs from the request ID so fixtures are
// reproducible without a random source.
func idSuffix(p Params, tag string) string {
	return fmt.Sprintf("%s%x", tag, len(p.RequestID)*7919+len(p.NameID))
}

func findChildren(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			out = append(out, c)
		}
	}
	return out
}
