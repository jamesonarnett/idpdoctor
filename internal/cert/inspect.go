// SPDX-License-Identifier: Apache-2.0

// Package cert parses X.509 certificates as they appear in SAML metadata and
// KeyInfo (PEM or bare base64 DER) and reports expiry, key strength and
// fingerprints. It reports; it never rejects, because an expired IdP cert is
// a diagnosis, not a parse failure.
package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 fingerprints are how IdP consoles display certs; not used for security.
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// ErrNoCertificate means the input held neither a PEM block nor base64 DER.
var ErrNoCertificate = errors.New("cert: no certificate found in input")

// MinRSABits is the smallest RSA modulus not reported as weak.
const MinRSABits = 2048

// Parse accepts a PEM CERTIFICATE block or bare base64 DER (the form inside
// <ds:X509Certificate>), with any whitespace. It returns the first cert.
func Parse(input string) (*x509.Certificate, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, ErrNoCertificate
	}
	if strings.Contains(s, "-----BEGIN") {
		for rest := []byte(s); len(rest) > 0; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				return x509.ParseCertificate(block.Bytes)
			}
		}
		return nil, fmt.Errorf("%w: PEM present but no CERTIFICATE block", ErrNoCertificate)
	}
	// Bare base64: IdP metadata wraps it at arbitrary widths, so strip all whitespace.
	clean := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		der, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(clean, "="))
		if err != nil {
			return nil, fmt.Errorf("%w: not PEM and not base64 (%v)", ErrNoCertificate, err)
		}
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w: parse DER: %v", ErrNoCertificate, err)
	}
	return c, nil
}

// Info is the cert_inspect output. Everything here is public-key material or
// metadata about it, so nothing is redacted.
type Info struct {
	Subject       string            `json:"subject"`
	Issuer        string            `json:"issuer"`
	Serial        string            `json:"serial"`
	NotBefore     string            `json:"not_before"`
	NotAfter      string            `json:"not_after"`
	DaysRemaining int               `json:"days_remaining"`
	KeyAlg        string            `json:"key_alg"`
	KeyBits       int               `json:"key_bits"`
	SigAlg        string            `json:"sig_alg"`
	SHA1          string            `json:"sha1"`
	SHA256        string            `json:"sha256"`
	SAN           []string          `json:"san"`
	SelfSigned    bool              `json:"self_signed"`
	Findings      []finding.Finding `json:"findings"`
}

// Inspect describes a certificate as of now and attaches CERT_EXPIRED_OR_WEAK
// findings for expiry, not-yet-valid, small RSA keys and SHA-1 signatures.
func Inspect(c *x509.Certificate, now time.Time) Info {
	info := Info{
		Subject:       c.Subject.String(),
		Issuer:        c.Issuer.String(),
		Serial:        c.SerialNumber.Text(16),
		NotBefore:     c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      c.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining: int(c.NotAfter.Sub(now).Hours() / 24),
		SigAlg:        c.SignatureAlgorithm.String(),
		SHA1:          Fingerprint(sha1.Sum(c.Raw)),
		SHA256:        FingerprintSHA256(c),
		SAN:           append(append([]string{}, c.DNSNames...), c.EmailAddresses...),
		SelfSigned:    c.Subject.String() == c.Issuer.String(),
		Findings:      []finding.Finding{},
	}
	info.KeyAlg, info.KeyBits = keyInfo(c)

	if now.After(c.NotAfter) {
		info.Findings = append(info.Findings, finding.New(finding.CertExpiredOrWeak, finding.Evidence{
			Path: "/Certificate/NotAfter", Actual: info.NotAfter, Expected: "> " + now.UTC().Format(time.RFC3339),
			Note: "certificate expired",
		}))
	}
	if now.Before(c.NotBefore) {
		info.Findings = append(info.Findings, finding.New(finding.CertExpiredOrWeak, finding.Evidence{
			Path: "/Certificate/NotBefore", Actual: info.NotBefore, Expected: "<= " + now.UTC().Format(time.RFC3339),
			Note: "certificate not yet valid",
		}))
	}
	if info.KeyAlg == "RSA" && info.KeyBits < MinRSABits {
		info.Findings = append(info.Findings, finding.New(finding.CertExpiredOrWeak, finding.Evidence{
			Path: "/Certificate/PublicKey", Actual: fmt.Sprintf("RSA %d bits", info.KeyBits), Expected: fmt.Sprintf("RSA >= %d bits", MinRSABits),
		}))
	}
	if isSHA1(c.SignatureAlgorithm) {
		// The cert's own signature algorithm matters little for a self-signed
		// IdP cert, so this is a warning rather than an error.
		f := finding.New(finding.CertExpiredOrWeak, finding.Evidence{
			Path: "/Certificate/SignatureAlgorithm", Actual: info.SigAlg, Expected: "SHA-256 or stronger",
		})
		f.Severity = finding.SeverityWarn
		info.Findings = append(info.Findings, f)
	}
	return info
}

// Fingerprint renders a hash as colon-separated upper-case hex, the way IdP
// consoles show it.
func Fingerprint(sum [20]byte) string { return colonHex(sum[:]) }

// FingerprintSHA256 is the colon-hex SHA-256 of the DER encoding.
func FingerprintSHA256(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return colonHex(sum[:])
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	parts := make([]string, 0, len(h)/2)
	for i := 0; i+2 <= len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func keyInfo(c *x509.Certificate) (string, int) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	}
	return c.PublicKeyAlgorithm.String(), 0
}

func isSHA1(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		return true
	}
	return false
}
