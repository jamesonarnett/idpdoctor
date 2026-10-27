// SPDX-License-Identifier: Apache-2.0

// Package oidc validates an OpenID Provider discovery document
// (/.well-known/openid-configuration) against OIDC Discovery 1.0: REQUIRED
// fields, the RS256 floor, https and same-host endpoints, and the issuer
// rules of section 4.3. A discovery document holds no secrets, so nothing
// here is redacted; the Report still says "redaction": "default".
package oidc

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// ArtifactKind is the Report label for discovery documents.
const ArtifactKind = "oidc_discovery"

// ErrNotJSON reports a document that is not a JSON object.
var ErrNotJSON = errors.New("oidc: discovery document is not a JSON object")

// Summary is the parsed, citation-friendly view of a discovery document.
type Summary struct {
	Issuer string `json:"issuer"`
	// Endpoints holds every *_endpoint key plus jwks_uri that is present.
	Endpoints            map[string]string `json:"endpoints"`
	IDTokenAlgs          []string          `json:"id_token_signing_alg_values_supported"`
	ResponseTypes        []string          `json:"response_types_supported"`
	SubjectTypes         []string          `json:"subject_types_supported"`
	ScopesSupported      []string          `json:"scopes_supported"`
	CodeChallengeMethods []string          `json:"code_challenge_methods_supported"`
	FetchedFrom          string            `json:"fetched_from,omitempty"`
	FetchStatus          int               `json:"fetch_status,omitempty"`
	ContentType          string            `json:"content_type,omitempty"`
	// Keys is the sorted list of top-level key names present in the doc.
	Keys []string `json:"keys"`
}

// Options carries what the caller knows beyond the document itself.
type Options struct {
	// ExpectedIssuer is the issuer the SP is configured with.
	ExpectedIssuer string
	// FetchedFrom is the URL the document was fetched from, if any; it
	// enables the Discovery 4.3 "issuer == fetch URL prefix" check and the
	// content_type check.
	FetchedFrom string
	FetchStatus int
	ContentType string
}

// Result is the oidc_discovery output: the summary plus the report.
type Result struct {
	Summary Summary         `json:"summary"`
	Report  *finding.Report `json:"report"`
}

// Parse decodes a discovery document into its top-level object.
func Parse(doc []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil || m == nil {
		return nil, ErrNotJSON
	}
	return m, nil
}

// summarise builds the Summary from a parsed document (m may be nil when the
// fetched body was not JSON).
func summarise(m map[string]any, opts Options) Summary {
	s := Summary{
		Issuer:               str(m, "issuer"),
		Endpoints:            map[string]string{},
		IDTokenAlgs:          strs(m, "id_token_signing_alg_values_supported"),
		ResponseTypes:        strs(m, "response_types_supported"),
		SubjectTypes:         strs(m, "subject_types_supported"),
		ScopesSupported:      strs(m, "scopes_supported"),
		CodeChallengeMethods: strs(m, "code_challenge_methods_supported"),
		FetchedFrom:          opts.FetchedFrom,
		FetchStatus:          opts.FetchStatus,
		ContentType:          opts.ContentType,
		Keys:                 make([]string, 0, len(m)),
	}
	for k := range m {
		s.Keys = append(s.Keys, k)
		if isEndpointKey(k) {
			if v := str(m, k); v != "" {
				s.Endpoints[k] = v
			}
		}
	}
	sort.Strings(s.Keys)
	return s
}

// isEndpointKey says which keys are URLs the RP will actually call.
// Documentation URLs (op_policy_uri, service_documentation) are not.
func isEndpointKey(k string) bool {
	return k == "jwks_uri" || strings.HasSuffix(k, "_endpoint")
}

// str returns m[k] when it is a string.
func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// strs returns m[k] as a string slice, dropping non-string elements; never
// nil so JSON renders [] for "absent".
func strs(m map[string]any, k string) []string {
	out := []string{}
	arr, _ := m[k].([]any)
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
