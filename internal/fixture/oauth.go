// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// Artifact forms an OAuthParams can render as.
const (
	// FormRedirect is the browser landing on redirect_uri (or ErrorPageURL).
	FormRedirect = ""
	// FormQuery is a bare query string, what a developer copies from an IdP
	// error page that refused to redirect to an unregistered URI.
	FormQuery = "query"
	// FormJSON is a token-endpoint error body.
	FormJSON = "json"
)

// OAuthParams describes the request a client sent and what came back. The
// Error*/Form fields are set by mutators; a zero Error means success.
type OAuthParams struct {
	RedirectURI            string
	RegisteredRedirectURIs []string
	State                  string
	Code                   string
	CodeVerifier           string
	CodeChallenge          string
	CodeChallengeMethod    string
	ClientType             string
	ResponseType           string
	GrantType              string
	Scopes                 []string
	// Vendor is the vendor oauth.Parse should detect from the artifact.
	Vendor string

	Error            string
	ErrorDescription string
	// Form selects the artifact shape (FormRedirect, FormQuery, FormJSON).
	Form string
	// ErrorPageURL, when set with FormRedirect, is where the error lands
	// instead of RedirectURI (an IdP-hosted error page such as Auth0's).
	ErrorPageURL string
}

// Secrets in the healthy baseline. Tests assert none of them ever appears
// in a Summary or Report.
const (
	fixtureCode     = "AUTHCODE-secret-0000"
	fixtureVerifier = "verifier-secret-0123456789abcdefghijklmnopqrstuvwxyz"
)

// S256 duplicates oauth.S256 (RFC 7636 4.2) so fixture stays free of
// validator imports; fixture's external test asserts the two agree.
func S256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// DefaultOAuthParams is a healthy public SPA client using S256 PKCE.
func DefaultOAuthParams() OAuthParams {
	return OAuthParams{
		RedirectURI:            "https://app.example.com/callback",
		RegisteredRedirectURIs: []string{"https://app.example.com/callback"},
		State:                  "st-7Hq2Lx9P",
		Code:                   fixtureCode,
		CodeVerifier:           fixtureVerifier,
		CodeChallenge:          S256(fixtureVerifier),
		CodeChallengeMethod:    "S256",
		ClientType:             "public",
		ResponseType:           "code",
		GrantType:              "authorization_code",
		Scopes:                 []string{"openid", "profile", "email"},
		Vendor:                 "generic",
	}
}

// Expected returns the request context a caller would supply for p.
func (p OAuthParams) Expected() expected.Expected {
	jp := DefaultJWTParams()
	return expected.Expected{
		Issuer:                 jp.Issuer,
		ClientID:               jp.Audience,
		RedirectURI:            p.RedirectURI,
		RegisteredRedirectURIs: append([]string(nil), p.RegisteredRedirectURIs...),
		CodeVerifier:           p.CodeVerifier,
		CodeChallenge:          p.CodeChallenge,
		CodeChallengeMethod:    p.CodeChallengeMethod,
		Scopes:                 append([]string(nil), p.Scopes...),
		ResponseType:           p.ResponseType,
		GrantType:              p.GrantType,
		ClientType:             p.ClientType,
	}
}

// OAuthMutator edits the params into one failure (or posture) class.
type OAuthMutator struct {
	Name  string
	Code  finding.Code
	Apply func(p *OAuthParams) Label
}

var oauthMutators = map[string]OAuthMutator{}

func registerOAuth(m OAuthMutator) { oauthMutators[m.Name] = m }

// OAuthMutatorByName looks up an OAuth mutator.
func OAuthMutatorByName(name string) (OAuthMutator, bool) {
	m, ok := oauthMutators[name]
	return m, ok
}

// OAuthMutators returns every OAuth mutator in name order.
func OAuthMutators() []OAuthMutator {
	out := make([]OAuthMutator, 0, len(oauthMutators))
	for _, m := range oauthMutators {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ErrNoRedirectURI reports params that cannot render a redirect artifact.
var ErrNoRedirectURI = errors.New("fixture: redirect artifact needs RedirectURI or ErrorPageURL")

// MintOAuth applies mutators and renders the artifact plus the Expected a
// caller would pass. With no mutator it is a healthy success redirect
// "<redirect_uri>?code=<code>&state=<state>".
func MintOAuth(p OAuthParams, muts ...OAuthMutator) (string, expected.Expected, []Label, error) {
	var labels []Label
	for _, m := range muts {
		labels = append(labels, m.Apply(&p))
	}
	exp := p.Expected()
	if p.Error == "" {
		if p.RedirectURI == "" {
			return "", exp, labels, ErrNoRedirectURI
		}
		q := url.Values{"code": {p.Code}, "state": {p.State}}
		return p.RedirectURI + "?" + q.Encode(), exp, labels, nil
	}
	switch p.Form {
	case FormJSON:
		b, err := json.Marshal(map[string]string{"error": p.Error, "error_description": p.ErrorDescription})
		return string(b), exp, labels, err
	case FormQuery:
		return errorQuery(p).Encode(), exp, labels, nil
	}
	target := p.ErrorPageURL
	if target == "" {
		target = p.RedirectURI
	}
	if target == "" {
		return "", exp, labels, ErrNoRedirectURI
	}
	return target + "?" + errorQuery(p).Encode(), exp, labels, nil
}

func errorQuery(p OAuthParams) url.Values {
	q := url.Values{"error": {p.Error}}
	if p.ErrorDescription != "" {
		q.Set("error_description", p.ErrorDescription)
	}
	if p.State != "" {
		q.Set("state", p.State)
	}
	return q
}

// Evidence paths the OAuth mutators label; they mirror the oauth package's
// Path constants (see discoveryPath for why they are literals here).
const (
	oauthPathError           = "/redirect/error"
	oauthPathRedirectURI     = "/request/redirect_uri"
	oauthPathCodeVerifier    = "/request/code_verifier"
	oauthPathCodeChallenge   = "/request/code_challenge"
	oauthPathChallengeMethod = "/request/code_challenge_method"
	entraTrailer             = " Trace ID: 0f3c2a1e-0000-4000-8000-000000000001 Correlation ID: 7d9e4b2c-0000-4000-8000-000000000002 Timestamp: 2026-01-15 12:00:00Z"
	otherVerifier            = "verifier-secret-ZZZZ456789abcdefghijklmnopqrstuvwxyz"
	plainChallenge           = "verifier-secret-plain-0123456789abcdefghijklmnop"
	auth0ErrorPage           = "https://example-tenant.us.auth0.com/authorize"
	fixtureUserEmail         = "alice@example.com"
)

// errorLabel is the label for classes caught from the error parameter.
func errorLabel(code finding.Code, note string) Label {
	return Label{Code: code, Path: oauthPathError, Note: note}
}

func init() {
	registerOAuth(OAuthMutator{Name: "oauth_redirect_uri_mismatch", Code: finding.OAuthRedirectURIMismatch,
		Apply: func(p *OAuthParams) Label {
			// Trailing slash drift; Entra shows its error page instead of
			// redirecting, so the artifact is the copied query string.
			p.RedirectURI = p.RegisteredRedirectURIs[0] + "/"
			p.Vendor, p.Form, p.Error = "entra", FormQuery, "invalid_request"
			p.ErrorDescription = "AADSTS50011: The redirect URI '" + p.RedirectURI + "' specified in the request does not match the redirect URIs configured for the application 'client-abc123'. Make sure the redirect URI sent in the request matches one added to your application in the Azure portal." + entraTrailer
			return Label{Code: finding.OAuthRedirectURIMismatch, Path: oauthPathRedirectURI, Needs: []string{"registered_redirect_uris"}, Note: "trailing slash"}
		}})
	registerOAuth(OAuthMutator{Name: "oauth_redirect_uri_mismatch_auth0", Code: finding.OAuthRedirectURIMismatch,
		Apply: func(p *OAuthParams) Label {
			p.RedirectURI = strings.Replace(p.RegisteredRedirectURIs[0], "https://", "http://", 1)
			p.Vendor, p.Error, p.ErrorPageURL = "auth0", "invalid_request", auth0ErrorPage
			p.ErrorDescription = "Callback URL mismatch. " + p.RedirectURI + " is not in the list of allowed callback URLs"
			return Label{Code: finding.OAuthRedirectURIMismatch, Path: oauthPathRedirectURI, Needs: []string{"registered_redirect_uris"}, Note: "http vs https"}
		}})
	registerOAuth(OAuthMutator{Name: "oauth_pkce_verifier_mismatch", Code: finding.OAuthPKCEVerifierMismatch,
		Apply: func(p *OAuthParams) Label {
			// The verifier was regenerated between /authorize and /token
			// (e.g. stored in memory and lost on the redirect).
			p.CodeVerifier = otherVerifier
			// Auth0's wording, but the bare JSON body names no vendor, so
			// a parser can only call it generic.
			p.Vendor, p.Form, p.Error = "generic", FormJSON, "invalid_grant"
			p.ErrorDescription = "Failed to verify code verifier"
			return Label{Code: finding.OAuthPKCEVerifierMismatch, Path: oauthPathCodeVerifier, Needs: []string{"code_verifier"}}
		}})
	registerOAuth(OAuthMutator{Name: "oauth_pkce_plain_mismatch", Code: finding.OAuthPKCEVerifierMismatch,
		Apply: func(p *OAuthParams) Label {
			p.CodeChallengeMethod, p.CodeChallenge, p.CodeVerifier = "plain", plainChallenge, otherVerifier
			p.Vendor, p.Form, p.Error = "entra", FormJSON, "invalid_grant"
			p.ErrorDescription = "AADSTS501481: The Code_Verifier does not match the code_challenge supplied in the authorization request." + entraTrailer
			return Label{Code: finding.OAuthPKCEVerifierMismatch, Path: oauthPathCodeVerifier, Needs: []string{"code_verifier"}}
		}})
	registerOAuth(OAuthMutator{Name: "oauth_invalid_grant_expired", Code: finding.OAuthInvalidGrantCode,
		Apply: func(p *OAuthParams) Label {
			p.Vendor, p.Form, p.Error = "entra", FormJSON, "invalid_grant"
			p.ErrorDescription = "AADSTS70008: The provided authorization code or refresh token has expired due to inactivity. Send a new interactive authorization request for this user and resource." + entraTrailer
			return errorLabel(finding.OAuthInvalidGrantCode, "expired code")
		}})
	registerOAuth(OAuthMutator{Name: "oauth_invalid_grant_reused", Code: finding.OAuthInvalidGrantCode,
		Apply: func(p *OAuthParams) Label {
			p.Vendor, p.Form, p.Error = "generic", FormJSON, "invalid_grant"
			p.ErrorDescription = "The authorization code has already been redeemed."
			return errorLabel(finding.OAuthInvalidGrantCode, "double submission (React StrictMode effect firing twice)")
		}})
	registerOAuth(OAuthMutator{Name: "oauth_invalid_client", Code: finding.OAuthClientConfigRejected,
		Apply: func(p *OAuthParams) Label {
			p.ClientType = "confidential"
			p.Vendor, p.Form, p.Error = "entra", FormJSON, "invalid_client"
			p.ErrorDescription = "AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app 'client-abc123'." + entraTrailer
			return errorLabel(finding.OAuthClientConfigRejected, "invalid client secret")
		}})
	registerOAuth(OAuthMutator{Name: "oauth_invalid_scope", Code: finding.OAuthClientConfigRejected,
		Apply: func(p *OAuthParams) Label {
			// Copy first: p.Scopes may share a backing array with the caller.
			p.Scopes = append(append([]string(nil), p.Scopes...), "admin.write")
			p.Vendor, p.Error = "generic", "invalid_scope"
			p.ErrorDescription = "The requested scope is invalid, unknown, or malformed."
			return errorLabel(finding.OAuthClientConfigRejected, "unknown scope admin.write")
		}})
	registerOAuth(OAuthMutator{Name: "oauth_unauthorized_client", Code: finding.OAuthClientConfigRejected,
		Apply: func(p *OAuthParams) Label {
			p.ResponseType = "id_token"
			p.Vendor, p.Error = "entra", "unauthorized_client"
			p.ErrorDescription = "AADSTS700054: response_type 'id_token' is not enabled for the application." + entraTrailer
			return errorLabel(finding.OAuthClientConfigRejected, "implicit id_token not enabled")
		}})
	registerOAuth(OAuthMutator{Name: "oauth_policy_refusal", Code: finding.IdPPolicyRefusal,
		Apply: func(p *OAuthParams) Label {
			p.Vendor, p.Error = "entra", "access_denied"
			// Real AADSTS50105 text names the user's UPN; the oauth package
			// must mask it.
			p.ErrorDescription = "AADSTS50105: Your administrator has configured the application 'client-abc123' to block users unless they are specifically granted ('assigned') access to the application. The signed in user '" + fixtureUserEmail + "' is blocked because they are not a direct member of a group with access." + entraTrailer
			return errorLabel(finding.IdPPolicyRefusal, "user not assigned")
		}})
	registerOAuth(OAuthMutator{Name: "oauth_consent_required", Code: finding.IdPPolicyRefusal,
		Apply: func(p *OAuthParams) Label {
			p.Vendor, p.Error = "generic", "consent_required"
			p.ErrorDescription = "The user or administrator has not consented to use the application."
			return errorLabel(finding.IdPPolicyRefusal, "consent required")
		}})
	registerOAuth(OAuthMutator{Name: "oauth_pkce_plain_posture", Code: finding.PosturePKCEPlainOrAbsent,
		Apply: func(p *OAuthParams) Label {
			// Flow succeeds and PKCE verifies; only the method is weak.
			p.CodeChallengeMethod, p.CodeChallenge = "plain", p.CodeVerifier
			return Label{Code: finding.PosturePKCEPlainOrAbsent, Path: oauthPathChallengeMethod, Needs: []string{"client_type"}}
		}})
	registerOAuth(OAuthMutator{Name: "oauth_pkce_absent_posture", Code: finding.PosturePKCEPlainOrAbsent,
		Apply: func(p *OAuthParams) Label {
			p.CodeVerifier, p.CodeChallenge, p.CodeChallengeMethod = "", "", ""
			return Label{Code: finding.PosturePKCEPlainOrAbsent, Path: oauthPathCodeChallenge, Needs: []string{"client_type"}}
		}})
}
