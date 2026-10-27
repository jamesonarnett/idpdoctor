// SPDX-License-Identifier: Apache-2.0

// Package diag is the deterministic pipeline: sniff the artifact kind,
// decode, parse, run every validator, rank, and render a Report. This is
// what the MCP diagnose tool returns and what the CLI prints. No LLM lives
// here; a later explain layer consumes this package's output.
package diag

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"regexp"
	"strings"
)

// Kind is the sniffed artifact type.
type Kind string

const (
	KindAuto          Kind = "auto"
	KindSAMLResponse  Kind = "saml_response"
	KindSAMLMetadata  Kind = "saml_metadata"
	KindJWT           Kind = "jwt"
	KindOIDCDiscovery Kind = "oidc_discovery"
	KindOAuthRedirect Kind = "oauth_redirect"
	KindCert          Kind = "cert"
	KindUnknown       Kind = "unknown"
)

// jwtShape: three base64url segments; the last may be empty (alg none).
var jwtShape = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)

// Sniff guesses what the developer pasted. Order matters: cheap textual
// markers first, structural guesses last.
func Sniff(input string) Kind {
	s := strings.TrimSpace(input)
	s = strings.TrimPrefix(s, "Bearer ")
	switch {
	case s == "":
		return KindUnknown
	case strings.HasPrefix(s, "-----BEGIN CERTIFICATE"):
		return KindCert
	case strings.HasPrefix(s, "<"):
		if strings.Contains(s, "EntityDescriptor") {
			return KindSAMLMetadata
		}
		return KindSAMLResponse
	case strings.HasPrefix(s, "{"):
		if strings.Contains(s, `"authorization_endpoint"`) || strings.Contains(s, `"jwks_uri"`) {
			return KindOIDCDiscovery
		}
		if strings.Contains(s, `"error"`) {
			// A token-endpoint error body (RFC 6749 5.2).
			return KindOAuthRedirect
		}
		return KindUnknown
	case strings.Contains(s, "SAMLResponse=") || strings.Contains(s, "SAMLRequest="):
		return KindSAMLResponse
	case (strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")) && hasParam(s, "error", "code"):
		return KindOAuthRedirect
	case !strings.ContainsAny(s, " <\n") && hasParam("?"+s, "error", "code") && strings.Contains(s, "="):
		// A bare query string pasted from the address bar ("error=...&...").
		return KindOAuthRedirect
	case jwtShape.MatchString(s):
		return KindJWT
	}
	// Bare base64: a POST or Redirect SAML payload, or a DER cert.
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		raw, err := enc.DecodeString(strings.TrimRight(clean, "="))
		if err != nil {
			raw, err = enc.DecodeString(clean)
		}
		if err != nil || len(raw) == 0 {
			continue
		}
		if raw[0] == '<' || (len(raw) > 2 && raw[0] == 0xEF) {
			return KindSAMLResponse
		}
		if raw[0] == 0x30 && len(raw) > 4 { // ASN.1 SEQUENCE: DER certificate
			return KindCert
		}
		// Deflated XML has no magic bytes, so try the real thing on a prefix.
		if inflatesToXML(raw) {
			return KindSAMLResponse
		}
	}
	return KindUnknown
}

// inflatesToXML reports whether raw is a deflate stream whose first bytes
// decode to XML. It reads at most 16 bytes so a hostile stream costs nothing.
func inflatesToXML(raw []byte) bool {
	r := flate.NewReader(bytes.NewReader(raw))
	defer r.Close()
	head := make([]byte, 16)
	n, _ := io.ReadFull(r, head)
	head = bytes.TrimLeft(head[:n], " \t\r\n\xEF\xBB\xBF")
	return len(head) > 0 && head[0] == '<'
}

// hasParam reports whether s carries one of the named query (or fragment)
// parameters, as a whole name: "error=" but not "error_uri=" alone.
func hasParam(s string, names ...string) bool {
	for _, n := range names {
		for _, sep := range []string{"?", "&", "#"} {
			if strings.Contains(s, sep+n+"=") {
				return true
			}
		}
	}
	return false
}
