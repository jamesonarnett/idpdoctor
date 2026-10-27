// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// DiscoveryParams describes a healthy OIDC discovery document. The issuer
// is the one DefaultJWTParams uses, so a minted id_token and a minted
// discovery document agree with each other.
type DiscoveryParams struct {
	Issuer string
	// Host serves every endpoint; it equals the issuer's host when healthy.
	Host string
	// TenantPath is the path prefix shared by the endpoints (Entra-style).
	TenantPath string
}

// Evidence paths the discovery mutators label. They mirror
// oidc.PathDiscoveryField; fixture must not import oidc (oidc's tests
// import fixture), and the round-trip test catches drift.
func discoveryPath(key string) string { return "/discovery/" + key }

func defaultDiscoveryParams() DiscoveryParams {
	return DiscoveryParams{Issuer: DefaultJWTParams().Issuer, Host: "login.example.com", TenantPath: "/tenant-1"}
}

// DefaultDiscovery returns a healthy Entra-shaped document and its params:
// every REQUIRED field, https, one host, RS256, code flow with S256 PKCE.
func DefaultDiscovery() (map[string]any, DiscoveryParams) {
	p := defaultDiscoveryParams()
	return discoveryDoc(p), p
}

// discoveryDoc builds the document for p. Arrays are []any so a mutator
// edits the same shape json.Unmarshal would produce.
func discoveryDoc(p DiscoveryParams) map[string]any {
	base := "https://" + p.Host + p.TenantPath
	return map[string]any{
		"issuer":                                p.Issuer,
		"authorization_endpoint":                base + "/oauth2/v2.0/authorize",
		"token_endpoint":                        base + "/oauth2/v2.0/token",
		"device_authorization_endpoint":         base + "/oauth2/v2.0/devicecode",
		"end_session_endpoint":                  base + "/oauth2/v2.0/logout",
		"userinfo_endpoint":                     "https://" + p.Host + "/oidc/userinfo",
		"jwks_uri":                              base + "/discovery/v2.0/keys",
		"response_types_supported":              []any{"code", "id_token", "code id_token"},
		"response_modes_supported":              []any{"query", "fragment", "form_post"},
		"subject_types_supported":               []any{"pairwise"},
		"id_token_signing_alg_values_supported": []any{"RS256"},
		"scopes_supported":                      []any{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []any{"client_secret_post", "private_key_jwt", "client_secret_basic"},
		"code_challenge_methods_supported":      []any{"S256", "plain"},
		"claims_supported":                      []any{"sub", "iss", "aud", "exp", "iat", "nonce", "email", "name"},
		"request_uri_parameter_supported":       false,
		"frontchannel_logout_supported":         true,
		"http_logout_supported":                 true,
	}
}

// DiscoveryMutator edits a healthy document into one failure class.
type DiscoveryMutator struct {
	Name  string
	Code  finding.Code
	Apply func(doc map[string]any, p *DiscoveryParams) Label
}

var discoveryMutators = map[string]DiscoveryMutator{}

func registerDiscovery(m DiscoveryMutator) { discoveryMutators[m.Name] = m }

// DiscoveryMutatorByName looks up a discovery mutator.
func DiscoveryMutatorByName(name string) (DiscoveryMutator, bool) {
	m, ok := discoveryMutators[name]
	return m, ok
}

// DiscoveryMutators returns every discovery mutator in name order.
func DiscoveryMutators() []DiscoveryMutator {
	out := make([]DiscoveryMutator, 0, len(discoveryMutators))
	for _, m := range discoveryMutators {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// MintDiscovery renders the document for p after applying mutators.
func MintDiscovery(p DiscoveryParams, muts ...DiscoveryMutator) ([]byte, []Label, error) {
	doc := discoveryDoc(p)
	var labels []Label
	for _, m := range muts {
		labels = append(labels, m.Apply(doc, &p))
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return b, labels, nil
}

func init() {
	invalid := finding.OIDCDiscoveryDocInvalid
	registerDiscovery(DiscoveryMutator{Name: "discovery_missing_jwks_uri", Code: invalid,
		Apply: func(doc map[string]any, p *DiscoveryParams) Label {
			delete(doc, "jwks_uri")
			return Label{Code: invalid, Path: discoveryPath("jwks_uri")}
		}})
	registerDiscovery(DiscoveryMutator{Name: "discovery_missing_subject_types", Code: invalid,
		Apply: func(doc map[string]any, p *DiscoveryParams) Label {
			delete(doc, "subject_types_supported")
			return Label{Code: invalid, Path: discoveryPath("subject_types_supported")}
		}})
	registerDiscovery(DiscoveryMutator{Name: "discovery_no_rs256", Code: invalid,
		Apply: func(doc map[string]any, p *DiscoveryParams) Label {
			// ES256-only: modern, but Discovery 3 makes RS256 the floor.
			doc["id_token_signing_alg_values_supported"] = []any{"ES256"}
			return Label{Code: invalid, Path: discoveryPath("id_token_signing_alg_values_supported")}
		}})
	registerDiscovery(DiscoveryMutator{Name: "discovery_http_endpoint", Code: invalid,
		Apply: func(doc map[string]any, p *DiscoveryParams) Label {
			doc["token_endpoint"] = strings.Replace(doc["token_endpoint"].(string), "https://", "http://", 1)
			return Label{Code: invalid, Path: discoveryPath("token_endpoint")}
		}})
	registerDiscovery(DiscoveryMutator{Name: "discovery_offhost_endpoint", Code: invalid,
		Apply: func(doc map[string]any, p *DiscoveryParams) Label {
			// Keys from a domain the issuer does not own: a tampered or
			// mis-proxied document.
			doc["jwks_uri"] = "https://keys.cdn-example.net" + p.TenantPath + "/discovery/v2.0/keys"
			return Label{Code: invalid, Path: discoveryPath("jwks_uri"), Note: "jwks_uri served from a different domain"}
		}})
	registerDiscovery(DiscoveryMutator{Name: "discovery_token_endpoint_missing", Code: invalid,
		Apply: func(doc map[string]any, p *DiscoveryParams) Label {
			delete(doc, "token_endpoint")
			return Label{Code: invalid, Path: discoveryPath("token_endpoint")}
		}})
	registerDiscovery(DiscoveryMutator{Name: "discovery_issuer_mismatch", Code: finding.OIDCIssuerMismatch,
		Apply: func(doc map[string]any, p *DiscoveryParams) Label {
			// p.Issuer stays the configured value; only the document drifts.
			doc["issuer"] = p.Issuer + "/"
			return Label{Code: finding.OIDCIssuerMismatch, Path: discoveryPath("issuer"), Needs: []string{"issuer"}, Note: "trailing slash"}
		}})
}
