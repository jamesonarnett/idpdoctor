// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/oauth"
	"github.com/jamesonarnett/idpdoctor/internal/oidc"
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

// CheckPaths maps a validator check name (the Check.Name values a tool
// prints, e.g. "audience") to the one evidence path it is about, for this
// result only. Models sometimes cite the check name instead of a path; the
// explain layer uses this map to normalise such a citation, and it only
// maps a name when the target is unambiguous:
//
//   - the name has exactly one candidate path that is in KnownPaths, or
//   - several candidates are known but exactly one of them appears in the
//     findings' evidence for this result.
//
// Anything else (an unknown name, two plausible targets) is left out, so
// the citation stays hallucinated. The candidate table mirrors the check
// names in internal/saml, internal/jwt, internal/oidc and internal/oauth.
func CheckPaths(res *Result) map[string]string {
	known := map[string]bool{}
	for _, p := range KnownPaths(res) {
		known[p] = true
	}
	cited := map[string]bool{}
	for _, f := range res.Report.Findings {
		for _, e := range f.Evidence {
			cited[e.Path] = true
		}
	}
	out := map[string]string{}
	for name, candidates := range checkCandidates(res) {
		var inKnown, inCited []string
		for _, c := range candidates {
			if !known[c] {
				continue
			}
			inKnown = append(inKnown, c)
			if cited[c] {
				inCited = append(inCited, c)
			}
		}
		switch {
		case len(inKnown) == 1:
			out[name] = inKnown[0]
		case len(inCited) == 1:
			out[name] = inCited[0]
		}
	}
	return out
}

// checkCandidates lists, per artifact kind, the paths a check name may
// stand for. Order carries no meaning; ambiguity is resolved by evidence.
func checkCandidates(res *Result) map[string][]string {
	switch {
	case res.SAML != nil:
		certPaths := func(prefix string) []string {
			base := prefix + saml.PathKeyInfoCertificate
			return []string{base, base + "/NotAfter", base + "/NotBefore", base + "/PublicKey", base + "/SignatureAlgorithm"}
		}
		return map[string][]string{
			"status":              {saml.PathStatusCode, saml.PathStatusSubCode, saml.PathStatusMessage},
			"issuer":              {saml.PathResponseIssuer, saml.PathAssertionIssuer},
			"destination":         {saml.PathResponseDestination},
			"in_response_to":      {saml.PathResponseInResponseTo, saml.PathSCDInResponseTo},
			"signature_present":   {saml.PathResponseSignature, saml.PathAssertionSignature},
			"signature_placement": {saml.PathResponseSignature, saml.PathAssertionSignature},
			"signature_verify":    {saml.PathResponseSignature, saml.PathAssertionSignature, "/Response" + saml.PathSignatureMethod, "/Response/Assertion" + saml.PathSignatureMethod},
			"cert_validity":       append(certPaths("/Response"), certPaths("/Response/Assertion")...),
			"audience":            {saml.PathAudience},
			"recipient":           {saml.PathRecipient},
			"time_window":         {saml.PathConditionsNotBefore, saml.PathConditionsNotOnOrAfter, saml.PathSCDNotOnOrAfter, saml.PathSessionNotOnOrAfter},
			"name_id":             {saml.PathNameID, saml.PathNameIDFormat},
			"attributes":          {saml.PathAttributeStatement},
			"structure":           {saml.PathResponse, saml.PathAssertion},
		}
	case res.JWT != nil:
		return map[string][]string{
			"alg_allowed": {"/header/alg"},
			"kid_found":   {"/header/kid"},
			"signature":   {"/signature"},
			"iss":         {"/claims/iss"},
			"aud":         {"/claims/aud"},
			"azp":         {"/claims/azp"},
			"exp":         {"/claims/exp"},
			"nbf":         {"/claims/nbf"},
			"iat":         {"/claims/iat"},
			"nonce":       {"/claims/nonce"},
			"at_hash":     {"/claims/at_hash"},
		}
	case res.Cert != nil:
		return map[string][]string{
			"cert_validity": {"/Certificate/NotAfter", "/Certificate/NotBefore", "/Certificate/PublicKey", "/Certificate/SignatureAlgorithm"},
		}
	case res.OIDC != nil:
		var fields []string
		for _, p := range res.extraPaths {
			if p != oidc.PathDiscovery {
				fields = append(fields, p)
			}
		}
		return map[string][]string{
			"required_fields": fields,
			"issuer_match":    {oidc.PathDiscoveryIssuer},
			"https_only":      fields,
			"endpoint_hosts":  fields,
			"token_endpoint":  {oidc.PathDiscoveryField("token_endpoint")},
			"content_type":    {oidc.PathDiscovery},
		}
	case res.OAuth != nil:
		pkce := []string{oauth.PathRequestCodeVerifier, oauth.PathRequestCodeChallenge, oauth.PathRequestCodeChallengeMethod}
		return map[string][]string{
			"error_class":   {oauth.PathError},
			"redirect_uri":  {oauth.PathRequestRedirectURI, oauth.PathRequestRegisteredRedirectURIs},
			"pkce":          pkce,
			"pkce_posture":  pkce,
			"client_config": {oauth.PathRequestClientType},
		}
	}
	return nil
}
