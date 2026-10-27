// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"encoding/base64"
	"testing"
)

func TestSniff(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want Kind
	}{
		{"empty", "  ", KindUnknown},
		{"xml response", `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`, KindSAMLResponse},
		{"xml metadata", `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"/>`, KindSAMLMetadata},
		{"base64 xml", base64.StdEncoding.EncodeToString([]byte("<samlp:Response/>")), KindSAMLResponse},
		{"form body", "SAMLResponse=PHNhbWxwOlJlc3BvbnNlLz4%3D&RelayState=x", KindSAMLResponse},
		{"jwt", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", KindJWT},
		{"jwt alg none", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.", KindJWT},
		{"bearer jwt", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", KindJWT},
		{"pem cert", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----", KindCert},
		{"der cert b64", base64.StdEncoding.EncodeToString(append([]byte{0x30, 0x82, 0x01, 0x00}, make([]byte, 256)...)), KindCert},
		{"discovery", `{"issuer":"https://op","authorization_endpoint":"https://op/auth"}`, KindOIDCDiscovery},
		{"oauth redirect", "https://app.example.com/cb?error=invalid_grant&error_description=x", KindOAuthRedirect},
		{"json other", `{"a":1}`, KindUnknown},
		{"prose", "hello world", KindUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Sniff(tc.in); got != tc.want {
				t.Errorf("Sniff = %s, want %s", got, tc.want)
			}
		})
	}
}
