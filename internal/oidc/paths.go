// SPDX-License-Identifier: Apache-2.0

package oidc

import "sort"

// Evidence paths name a top-level key of the discovery document, so an LLM
// can cite "/discovery/jwks_uri" and a harness can check that the key is
// one the document has (or one the spec requires it to have).
const (
	PathDiscovery       = "/discovery"
	PathDiscoveryIssuer = "/discovery/issuer"
)

// PathDiscoveryField is the evidence path for one top-level key.
func PathDiscoveryField(name string) string { return PathDiscovery + "/" + name }

// KnownPaths lists every path a citation may legitimately use for this
// document: the root, every key present, and the REQUIRED keys plus
// token_endpoint even when absent, because "jwks_uri is missing" is a
// claim about that path.
func KnownPaths(s Summary) []string {
	set := map[string]bool{PathDiscovery: true, PathDiscoveryIssuer: true}
	for _, k := range s.Keys {
		set[PathDiscoveryField(k)] = true
	}
	for _, k := range requiredFields {
		set[PathDiscoveryField(k)] = true
	}
	set[PathDiscoveryField("token_endpoint")] = true
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
