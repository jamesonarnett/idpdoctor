// SPDX-License-Identifier: Apache-2.0

package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func readDialect(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "dialects", name+".xml"))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(b)
}

func deflateB64(t *testing.T, xml []byte) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(xml); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestDecodeBindings(t *testing.T) {
	xml := readDialect(t, "okta")
	post := base64.StdEncoding.EncodeToString(xml)
	redirect := deflateB64(t, xml)

	tests := []struct {
		name        string
		input       string
		binding     Binding
		wantBinding Binding
		wantRelay   string
	}{
		{"raw xml", string(xml), BindingAuto, BindingXML, ""},
		{"raw xml with leading whitespace", "\n  " + string(xml), BindingAuto, BindingXML, ""},
		{"post base64", post, BindingAuto, BindingPOST, ""},
		{"post base64 wrapped lines", post[:60] + "\n" + post[60:], BindingAuto, BindingPOST, ""},
		{"post base64 url-safe no padding", base64.RawURLEncoding.EncodeToString(xml), BindingAuto, BindingPOST, ""},
		{"redirect deflate", redirect, BindingAuto, BindingRedirect, ""},
		{"form body", "SAMLResponse=" + url.QueryEscape(post) + "&RelayState=abc", BindingAuto, BindingPOST, "abc"},
		{"full url", "https://sp.example.com/acs?SAMLResponse=" + url.QueryEscape(redirect) + "&RelayState=xyz&SigAlg=rsa&Signature=zz", BindingAuto, BindingRedirect, "xyz"},
		{"forced post", post, BindingPOST, BindingPOST, ""},
		{"forced xml", string(xml), BindingXML, BindingXML, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(tc.input, tc.binding)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got.Binding != tc.wantBinding {
				t.Errorf("binding = %s, want %s", got.Binding, tc.wantBinding)
			}
			if !bytes.Equal(got.XML, xml) {
				t.Errorf("xml round trip mismatch (len %d vs %d)", len(got.XML), len(xml))
			}
			if got.RelayState != tc.wantRelay {
				t.Errorf("relay = %q want %q", got.RelayState, tc.wantRelay)
			}
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	xml := readDialect(t, "okta")
	tests := []struct {
		name    string
		input   string
		binding Binding
		want    error
	}{
		{"empty", "   ", BindingAuto, ErrEmptyInput},
		{"garbage", "!!!not base64!!!", BindingAuto, ErrBadBase64},
		{"base64 of junk", base64.StdEncoding.EncodeToString([]byte("hello")), BindingAuto, ErrNotXML},
		{"form body without field", "RelayState=abc&foo=bar&SAMLResponse=", BindingAuto, ErrNoSAMLField},
		{"forced redirect on post bytes", base64.StdEncoding.EncodeToString(xml), BindingRedirect, ErrBadDeflate},
		{"forced xml on base64", base64.StdEncoding.EncodeToString(xml), BindingXML, ErrNotXML},
		{"bad binding", string(xml), Binding("soap"), ErrBadBinding},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.input, tc.binding)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
