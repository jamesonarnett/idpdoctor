// SPDX-License-Identifier: Apache-2.0

package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// selfSigned mints a throwaway cert; 1024 bits keeps the test fast and
// doubles as the weak-key case.
func selfSigned(t *testing.T, bits int, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "TEST ONLY idp"},
		NotBefore:    notBefore, NotAfter: notAfter,
		DNSNames: []string{"idp.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseFormats(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	der := selfSigned(t, 1024, now.Add(-time.Hour), now.Add(24*time.Hour))
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	b64 := base64.StdEncoding.EncodeToString(der)
	wrapped := b64[:40] + "\n  " + b64[40:] // metadata-style line wrapping

	for name, in := range map[string]string{"pem": pemText, "bare": b64, "wrapped": wrapped} {
		t.Run(name, func(t *testing.T) {
			c, err := Parse(in)
			if err != nil {
				t.Fatal(err)
			}
			if c.Subject.CommonName != "TEST ONLY idp" {
				t.Fatalf("wrong cert: %s", c.Subject)
			}
		})
	}
	if _, err := Parse(""); !errors.Is(err, ErrNoCertificate) {
		t.Errorf("empty: %v", err)
	}
	if _, err := Parse("not a cert"); !errors.Is(err, ErrNoCertificate) {
		t.Errorf("garbage: %v", err)
	}
}

func TestInspectFindings(t *testing.T) {
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
		wantNotes int
	}{
		{"expired weak", now.Add(-48 * time.Hour), now.Add(-time.Hour), 2},
		{"not yet valid weak", now.Add(time.Hour), now.Add(48 * time.Hour), 2},
		{"valid weak", now.Add(-time.Hour), now.Add(48 * time.Hour), 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := x509.ParseCertificate(selfSigned(t, 1024, tc.notBefore, tc.notAfter))
			if err != nil {
				t.Fatal(err)
			}
			info := Inspect(c, now)
			if len(info.Findings) != tc.wantNotes {
				t.Fatalf("findings = %d, want %d: %+v", len(info.Findings), tc.wantNotes, info.Findings)
			}
			for _, f := range info.Findings {
				if f.Code != finding.CertExpiredOrWeak {
					t.Errorf("unexpected code %s", f.Code)
				}
			}
			if !info.SelfSigned || info.KeyAlg != "RSA" || info.KeyBits != 1024 {
				t.Errorf("info = %+v", info)
			}
			if strings.Count(info.SHA256, ":") != 31 || strings.Count(info.SHA1, ":") != 19 {
				t.Errorf("fingerprints malformed: %s / %s", info.SHA256, info.SHA1)
			}
		})
	}
}
