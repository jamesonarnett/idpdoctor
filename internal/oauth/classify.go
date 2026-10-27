// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"regexp"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// Vendor values for Summary.Vendor.
const (
	VendorEntra   = "entra"
	VendorAuth0   = "auth0"
	VendorOkta    = "okta"
	VendorGoogle  = "google"
	VendorGeneric = "generic"
)

// vendorCodeRE captures the vendor's own error number: Entra AADSTS codes
// and Okta's E0000xxx API error codes.
var vendorCodeRE = regexp.MustCompile(`\b(AADSTS\d+|E0000\d{3})\b`)

func vendorCode(desc string) string { return vendorCodeRE.FindString(desc) }

// vendorRules is checked in order against the lower-cased error,
// description, error_uri and redirect host; the first match wins. An AADSTS
// code is definitive, so Entra comes first.
var vendorRules = []struct {
	vendor string
	re     *regexp.Regexp
}{
	{VendorEntra, regexp.MustCompile(`\baadsts\d+|login\.microsoftonline\.com|login\.microsoft\.com`)},
	{VendorAuth0, regexp.MustCompile(`auth0|callback url mismatch`)},
	{VendorOkta, regexp.MustCompile(`okta|\be0000\d{3}\b`)},
	{VendorGoogle, regexp.MustCompile(`accounts\.google\.com|googleapis\.com|app_not_enabled_for_user`)},
}

func detectVendor(s Summary) string {
	hay := strings.ToLower(strings.Join([]string{s.Error, s.ErrorDescription, s.ErrorURI, s.RedirectHost}, " "))
	for _, r := range vendorRules {
		if r.re.MatchString(hay) {
			return r.vendor
		}
	}
	return VendorGeneric
}

// rule maps error signals to one catalog code. Classification walks the
// table three times, most specific signal first: a vendor code (AADSTS),
// then a description phrase, then the bare RFC 6749 error value. That
// ordering is what lets "invalid_grant + Failed to verify code verifier"
// land on PKCE instead of the generic invalid_grant class.
type rule struct {
	code finding.Code
	// errors are RFC 6749 / OIDC Core / vendor error parameter values.
	errors []string
	// vendorCodes are AADSTS numbers (without the prefix).
	vendorCodes []string
	// phrases are lower-case substrings of error_description.
	phrases []string
	// phraseOnlyFor restricts phrases to these error values ("" means the
	// error parameter was absent); empty means any error.
	phraseOnlyFor []string
	confidence    float64
}

// policyConfidence: the artifact proves the IdP refused, but which policy
// (assignment, consent, MFA, tenant) needs tenant context.
const policyConfidence = 0.8

var rules = []rule{
	{
		code:        finding.OAuthRedirectURIMismatch,
		errors:      []string{"redirect_uri_mismatch"},
		vendorCodes: []string{"50011"},
		phrases:     []string{"callback url mismatch", "redirect uri not allowed", "redirect_uri_mismatch"},
		confidence:  1.0,
	},
	{
		// invalid_request that talks about the redirect is the same class;
		// restricted so a consent page mentioning "redirect" does not match.
		code:          finding.OAuthRedirectURIMismatch,
		phrases:       []string{"redirect"},
		phraseOnlyFor: []string{"invalid_request"},
		confidence:    1.0,
	},
	{
		code:        finding.OAuthPKCEVerifierMismatch,
		vendorCodes: []string{"501481"},
		phrases:     []string{"code_verifier", "code verifier", "pkce", "proof key", "code_challenge", "code challenge"},
		confidence:  1.0,
	},
	{
		code:          finding.OAuthInvalidGrantCode,
		errors:        []string{"invalid_grant"},
		vendorCodes:   []string{"70000", "70008", "50173", "54005"},
		phrases:       []string{"expired", "already redeemed", "already been redeemed", "already used", "reused", "has been used"},
		phraseOnlyFor: []string{"invalid_grant", ""},
		confidence:    1.0,
	},
	{
		code:        finding.OAuthClientConfigRejected,
		errors:      []string{"invalid_client", "invalid_scope", "unauthorized_client", "unsupported_response_type", "unsupported_grant_type"},
		vendorCodes: []string{"7000215", "7000222", "700025", "70011", "700054"},
		confidence:  1.0,
	},
	{
		code: finding.IdPPolicyRefusal,
		errors: []string{"access_denied", "login_required", "consent_required", "interaction_required",
			"account_selection_required", "app_not_enabled_for_user", "user_not_active"},
		vendorCodes: []string{"50105", "65001", "90094", "50076", "53003", "700016", "500011", "50194"},
		phrases:     []string{"app_not_enabled_for_user", "user_not_active"},
		confidence:  policyConfidence,
	},
}

// classify returns the matching rule and which signal matched, or ok=false
// for an error the table does not know (server_error, a bare invalid_request).
func classify(s Summary) (r rule, matchedBy string, ok bool) {
	num := strings.TrimPrefix(s.VendorCode, "AADSTS")
	if strings.HasPrefix(s.VendorCode, "AADSTS") {
		for _, r := range rules {
			if contains(r.vendorCodes, num) {
				return r, "vendor code " + s.VendorCode, true
			}
		}
	}
	desc := strings.ToLower(s.ErrorDescription)
	for _, r := range rules {
		if len(r.phraseOnlyFor) > 0 && !contains(r.phraseOnlyFor, s.Error) {
			continue
		}
		for _, p := range r.phrases {
			if strings.Contains(desc, p) {
				return r, "description mentions \"" + p + "\"", true
			}
		}
	}
	for _, r := range rules {
		if contains(r.errors, s.Error) {
			return r, "error=" + s.Error, true
		}
	}
	return rule{}, "", false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
