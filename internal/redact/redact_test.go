// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"errors"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

func TestValue(t *testing.T) {
	tests := []struct {
		name, kind, in string
		wantEmpty      bool
	}{
		{"empty stays empty", "nameid", "", true},
		{"masked", "nameid", "alice@example.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Value(tc.kind, tc.in)
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("got %q want empty", got)
				}
				return
			}
			if !strings.HasPrefix(got, "[REDACTED:nameid:") || strings.Contains(got, tc.in) {
				t.Fatalf("got %q", got)
			}
			if got != Value(tc.kind, tc.in) {
				t.Fatal("masking must be deterministic")
			}
			if got == Value(tc.kind, tc.in+"x") {
				t.Fatal("different values must mask differently")
			}
		})
	}
}

const sampleXML = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Assertion>
    <saml:Subject><saml:NameID Format="urn:x">alice@example.com<!-- evil -->.attacker</saml:NameID></saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="email"><saml:AttributeValue>alice@example.com</saml:AttributeValue></saml:Attribute>
      <saml:Attribute Name="groups"><saml:AttributeValue>admins</saml:AttributeValue><saml:AttributeValue>devs</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`

func TestXML(t *testing.T) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(sampleXML); err != nil {
		t.Fatal(err)
	}
	XML(doc.Root())
	out, _ := doc.WriteToString()
	for _, leak := range []string{"alice", "attacker", "admins", "devs", "evil"} {
		if strings.Contains(out, leak) {
			t.Errorf("leaked %q in %s", leak, out)
		}
	}
	for _, keep := range []string{"https://idp.example.com", `Name="email"`, `Name="groups"`, `Format="urn:x"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("over-redacted: missing %q", keep)
		}
	}
	if strings.Count(out, "[REDACTED:attr:") != 3 {
		t.Errorf("want 3 attribute masks, got %s", out)
	}
}

func TestClaims(t *testing.T) {
	in := map[string]any{
		"iss": "https://op.example.com", "aud": "client-1", "exp": 1.7e9,
		"sub": "u-123", "email": "alice@example.com", "groups": []any{"g1", "g2"}, "nonce": "n-1",
	}
	out := Claims(in)
	if out["iss"] != in["iss"] || out["aud"] != in["aud"] || out["exp"] != in["exp"] || out["nonce"] != "n-1" {
		t.Errorf("non-PII claims must pass through: %v", out)
	}
	if out["sub"] == "u-123" || out["email"] == "alice@example.com" {
		t.Errorf("PII leaked: %v", out)
	}
	g, ok := out["groups"].([]any)
	if !ok || len(g) != 2 || g[0] == "g1" {
		t.Errorf("groups should be masked element-wise: %v", out["groups"])
	}
	if len(in) != 7 || in["sub"] != "u-123" {
		t.Error("input must not be mutated")
	}
}

func TestStore(t *testing.T) {
	s := NewStore()
	ref := s.Put([]byte("secret"))
	if !strings.HasPrefix(ref, "art_") || len(ref) != 20 {
		t.Fatalf("bad ref %q", ref)
	}
	got, err := s.Get(ref)
	if err != nil || string(got) != "secret" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	got[0] = 'X'
	again, _ := s.Get(ref)
	if string(again) != "secret" {
		t.Fatal("Get must return a copy")
	}
	if _, err := s.Get("art_nope"); !errors.Is(err, ErrUnknownRef) {
		t.Fatalf("want ErrUnknownRef, got %v", err)
	}
	s.Delete(ref)
	if s.Len() != 0 {
		t.Fatal("Delete did not remove")
	}
}

func TestTruncate(t *testing.T) {
	if Truncate("abc", 10) != "abc" {
		t.Fatal("short strings pass through")
	}
	if got := Truncate("abcdef", 3); got != "abc\n...[truncated]" {
		t.Fatalf("got %q", got)
	}
}
