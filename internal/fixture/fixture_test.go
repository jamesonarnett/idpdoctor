// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/saml"
)

func mustTestKeys(t *testing.T) *Keys {
	t.Helper()
	k, err := TestKeys()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestMintSAMLVerifiesInEveryDialect(t *testing.T) {
	keys := mustTestKeys(t)
	for _, dialect := range []string{"generic", "okta", "entra", "auth0"} {
		for _, sign := range []string{"assertion", "response", "both"} {
			t.Run(dialect+"/"+sign, func(t *testing.T) {
				p := DefaultParams()
				p.Dialect, p.Sign = dialect, sign
				xml, labels, err := MintSAML(p, keys)
				if err != nil {
					t.Fatal(err)
				}
				if len(labels) != 0 {
					t.Errorf("healthy mint produced labels %v", labels)
				}
				parsed, err := saml.Parse(xml)
				if err != nil {
					t.Fatalf("parse: %v\n%s", err, xml)
				}
				s := parsed.Summary
				if s.Issuer != p.IdPEntityID || s.Assertion == nil || s.Assertion.Subject.NameID != p.NameID {
					t.Fatalf("summary wrong: %+v", s)
				}
				if s.Assertion.Conditions.Audiences[0] != p.SPEntityID {
					t.Errorf("audience = %v", s.Assertion.Conditions.Audiences)
				}
				wantSigs := map[string]int{"assertion": 1, "response": 1, "both": 2}[sign]
				if len(s.Signatures) != wantSigs {
					t.Fatalf("signatures = %d, want %d", len(s.Signatures), wantSigs)
				}
				vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{keys.Cert}})
				vc.Clock = dsig.NewFakeClockAt(FixedNow)
				if sign != "assertion" {
					if _, err := vc.Validate(parsed.Response); err != nil {
						t.Errorf("response signature: %v", err)
					}
				}
				if sign != "response" {
					if _, err := vc.Validate(parsed.Assertions[0]); err != nil {
						t.Errorf("assertion signature: %v", err)
					}
				}
				// Realism: the Signature sits right after Issuer.
				if sign == "assertion" {
					if kids := parsed.Assertions[0].ChildElements(); kids[1].Tag != "Signature" {
						t.Errorf("second child is %s, want Signature", kids[1].Tag)
					}
				}
			})
		}
	}
}

func TestTamperBreaksSignature(t *testing.T) {
	keys := mustTestKeys(t)
	m, ok := SAMLMutator("signature_tampered")
	if !ok {
		t.Fatal("mutator missing")
	}
	xml, labels, err := MintSAML(DefaultParams(), keys, m)
	if err != nil {
		t.Fatal(err)
	}
	if len(labels) != 1 || labels[0].Code != finding.SAMLSignatureInvalid {
		t.Fatalf("labels = %v", labels)
	}
	parsed, err := saml.Parse(xml)
	if err != nil {
		t.Fatal(err)
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{keys.Cert}})
	vc.Clock = dsig.NewFakeClockAt(FixedNow)
	if _, err := vc.Validate(parsed.Assertions[0]); err == nil {
		t.Fatal("tampered assertion verified")
	}
}

// TestEveryCatalogMutatorExists keeps codes.go honest: a Mutator name in
// the catalog must be implemented here, and every mutator here must point
// at a catalog code.
func TestEveryCatalogMutatorExists(t *testing.T) {
	for _, s := range finding.Catalog {
		if s.Mutator == "" {
			continue
		}
		_, saml := SAMLMutator(s.Mutator)
		_, jwt := JWTMutatorByName(s.Mutator)
		if !saml && !jwt {
			t.Errorf("%s names mutator %q which does not exist", s.Code, s.Mutator)
		}
	}
	for _, m := range SAMLMutators() {
		if _, ok := finding.Lookup(m.Code); !ok {
			t.Errorf("mutator %s -> unknown code %s", m.Name, m.Code)
		}
	}
	for _, m := range JWTMutators() {
		if _, ok := finding.Lookup(m.Code); !ok {
			t.Errorf("jwt mutator %s -> unknown code %s", m.Name, m.Code)
		}
	}
}

func TestAllSAMLMutatorsProduceParsableXML(t *testing.T) {
	keys := mustTestKeys(t)
	for _, m := range SAMLMutators() {
		t.Run(m.Name, func(t *testing.T) {
			xml, labels, err := MintSAML(DefaultParams(), keys, m)
			if err != nil {
				t.Fatal(err)
			}
			if len(labels) != 1 || labels[0].Code != m.Code || labels[0].Path == "" {
				t.Errorf("label = %+v", labels)
			}
			if _, err := saml.Parse(xml); err != nil {
				t.Fatalf("parse: %v", err)
			}
		})
	}
}

func TestMintJWT(t *testing.T) {
	keys := mustTestKeys(t)
	p := DefaultJWTParams()
	tok, labels, err := MintJWT(p, keys.Key)
	if err != nil || len(labels) != 0 {
		t.Fatal(err, labels)
	}
	parsed, err := jwt.Parse(tok, func(tk *jwt.Token) (any, error) {
		if tk.Header["kid"] != p.KID {
			t.Errorf("kid = %v", tk.Header["kid"])
		}
		return &keys.Key.PublicKey, nil
	}, jwt.WithTimeFunc(func() time.Time { return FixedNow }), jwt.WithIssuer(p.Issuer), jwt.WithAudience(p.Audience))
	if err != nil || !parsed.Valid {
		t.Fatalf("healthy token did not verify: %v", err)
	}
	if strings.Count(tok, ".") != 2 {
		t.Error("not a compact JWS")
	}

	// alg=none must produce an empty signature segment; HS256 must not verify with the RSA key.
	none, _ := JWTMutatorByName("jwt_alg_none")
	tok, _, err = MintJWT(p, keys.Key, none)
	if err != nil || !strings.HasSuffix(tok, ".") {
		t.Errorf("alg none token = %q, %v", tok, err)
	}
	hs, _ := JWTMutatorByName("jwt_hs256_confusion")
	tok, _, err = MintJWT(p, keys.Key, hs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jwt.Parse(tok, func(*jwt.Token) (any, error) { return &keys.Key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"})); err == nil {
		t.Error("HS256 token verified as RS256")
	}

	jwks := JWKS(RSAJWK(p.KID, &keys.Key.PublicKey))
	if !strings.Contains(jwks, `"kid":"test-key-1"`) || !strings.Contains(jwks, `"kty":"RSA"`) {
		t.Errorf("jwks = %s", jwks)
	}
}
