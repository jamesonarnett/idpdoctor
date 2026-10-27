// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/redact"
	"github.com/jamesonarnett/idpdoctor/internal/saml"
)

// KnownPaths lists every evidence path an explainer may legitimately cite
// for this result: the paths the validators actually produced plus the
// structural paths that exist in the parsed artifact. The eval harness
// counts a cited path outside this set as a hallucinated citation
// (BUILD_PLAN 6.2, R2), so the set errs towards generosity on structure
// and never includes a value.
func KnownPaths(res *Result) []string {
	set := map[string]bool{}
	for _, f := range res.Report.Findings {
		for _, e := range f.Evidence {
			set[e.Path] = true
		}
	}
	switch {
	case res.SAML != nil:
		samlPaths(res.SAML, set)
	case res.JWT != nil:
		for k := range res.JWT.Header {
			set["/header/"+k] = true
		}
		for k := range res.JWT.Claims {
			set["/claims/"+k] = true
		}
		for _, p := range []string{"/header", "/claims", "/signature", "/keys/jwks_json", "/keys/jwks_url", "/keys/pem"} {
			set[p] = true
		}
	case res.Cert != nil:
		for _, p := range []string{"/Certificate", "/Certificate/NotAfter", "/Certificate/NotBefore", "/Certificate/PublicKey", "/Certificate/SignatureAlgorithm", "/Certificate/Subject", "/Certificate/Issuer"} {
			set[p] = true
		}
	}
	for _, p := range res.extraPaths {
		set[p] = true
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// samlPaths adds the structural SAML paths. Signature-relative constants
// are prefixed for both the Response and the Assertion signature.
func samlPaths(s *saml.Summary, set map[string]bool) {
	for _, p := range []string{
		saml.PathResponse, saml.PathResponseID, saml.PathResponseDestination, saml.PathResponseInResponseTo,
		saml.PathResponseIssuer, saml.PathStatusCode, saml.PathStatusSubCode, saml.PathStatusMessage,
		saml.PathResponseSignature, saml.PathAssertion, saml.PathAssertionIssuer, saml.PathAssertionSignature,
		saml.PathNameID, saml.PathNameIDFormat, saml.PathSubjectConfirmationData, saml.PathRecipient,
		saml.PathSCDNotOnOrAfter, saml.PathSCDInResponseTo, saml.PathConditions, saml.PathConditionsNotBefore,
		saml.PathConditionsNotOnOrAfter, saml.PathAudience, saml.PathAttributeStatement,
		saml.PathSessionNotOnOrAfter, saml.PathRelayState, "/Response/@Version", "/Response/@IssueInstant",
		"/Response/Assertion/@ID", "/Response/Assertion/@IssueInstant", "/Response/Assertion/AuthnStatement",
		"/Response/Assertion/AuthnStatement/AuthnContext/AuthnContextClassRef", "/expected/idp_cert_pem",
	} {
		set[p] = true
	}
	for _, prefix := range []string{"/Response", "/Response/Assertion", ""} {
		for _, p := range []string{saml.PathSignatureMethod, saml.PathDigestMethod, saml.PathKeyInfoCertificate,
			saml.PathKeyInfoCertificate + "/NotAfter", saml.PathKeyInfoCertificate + "/NotBefore",
			saml.PathKeyInfoCertificate + "/PublicKey", saml.PathKeyInfoCertificate + "/SignatureAlgorithm"} {
			set[prefix+p] = true
		}
	}
	if s.Assertion != nil {
		for name := range s.Assertion.Attributes {
			set[saml.PathAttribute(name)] = true
		}
	}
}

// indexSuffix matches XPath-style positional predicates ("[1]") that a
// model may append; they carry no information for our flat paths.
var indexSuffix = regexp.MustCompile(`\[\d+\]`)

// NormalizePath canonicalises a cited path before it is compared with
// KnownPaths: trims whitespace, drops positional predicates, collapses
// doubled slashes and a trailing slash.
func NormalizePath(p string) string {
	p = strings.TrimSpace(p)
	p = indexSuffix.ReplaceAllString(p, "")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p
}

// RedactedText is what the tools-off explain mode and the redacted bundle
// show: the artifact's structure with every identity-bearing value masked.
// It is the only form of the artifact that may enter a model transcript.
func RedactedText(res *Result, max int) string {
	switch {
	case res.SAMLParsed != nil:
		return res.SAMLParsed.PrettyXML(max)
	case res.JWT != nil:
		// Claims.MarshalJSON redacts; the header is public metadata.
		b, err := json.MarshalIndent(map[string]any{"header": res.JWT.Header, "claims": res.JWT.Claims, "kind_guess": res.JWT.KindGuess}, "", "  ")
		if err != nil {
			return ""
		}
		return redact.Truncate(string(b), max)
	case res.Cert != nil:
		b, err := json.MarshalIndent(res.Cert, "", "  ")
		if err != nil {
			return ""
		}
		return redact.Truncate(string(b), max)
	}
	return redact.Truncate(res.extraText, max)
}
