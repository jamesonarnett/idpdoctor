// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"sort"

	"github.com/jamesonarnett/idpdoctor/internal/expected"
)

// Evidence paths. /redirect/* names a parameter of the artifact (redirect
// URL, bare query or token-endpoint JSON body alike); /request/* names a
// value the caller supplied about the request the client sent.
const (
	PathError            = "/redirect/error"
	PathErrorDescription = "/redirect/error_description"
	PathState            = "/redirect/state"
	PathCode             = "/redirect/code"

	PathRequestRedirectURI            = "/request/redirect_uri"
	PathRequestRegisteredRedirectURIs = "/request/registered_redirect_uris"
	PathRequestCodeVerifier           = "/request/code_verifier"
	PathRequestCodeChallenge          = "/request/code_challenge"
	PathRequestCodeChallengeMethod    = "/request/code_challenge_method"
	PathRequestClientType             = "/request/client_type"
	PathRequestGrantType              = "/request/grant_type"
	PathRequestResponseType           = "/request/response_type"
	PathRequestScopes                 = "/request/scopes"
)

// KnownPaths lists every path a citation may legitimately use: artifact
// parameters that are present, request values that were supplied, and, for
// a public client, the PKCE paths even when empty, because "no
// code_challenge was sent" is a claim about that path.
func KnownPaths(s Summary, exp expected.Expected) []string {
	set := map[string]bool{}
	add := func(cond bool, p string) {
		if cond {
			set[p] = true
		}
	}
	add(s.Error != "", PathError)
	add(s.ErrorDescription != "", PathErrorDescription)
	add(s.State != "", PathState)
	add(s.HasCode, PathCode)
	add(exp.RedirectURI != "", PathRequestRedirectURI)
	add(len(exp.RegisteredRedirectURIs) > 0, PathRequestRegisteredRedirectURIs)
	add(exp.CodeVerifier != "", PathRequestCodeVerifier)
	add(exp.CodeChallenge != "" || exp.ClientType == "public", PathRequestCodeChallenge)
	add(exp.CodeChallengeMethod != "" || exp.ClientType == "public", PathRequestCodeChallengeMethod)
	add(exp.ClientType != "", PathRequestClientType)
	add(exp.GrantType != "", PathRequestGrantType)
	add(exp.ResponseType != "", PathRequestResponseType)
	add(len(exp.Scopes) > 0, PathRequestScopes)
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
