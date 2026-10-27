// SPDX-License-Identifier: Apache-2.0

package saml

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Signature verification errors. goxmldsig exposes only two sentinels and
// returns strings for the rest, so we classify by message once, here, and
// the validator switches on these.
var (
	ErrSigMissing   = errors.New("saml: element carries no signature")
	ErrSigInvalid   = errors.New("saml: signature does not verify")
	ErrSigUntrusted = errors.New("saml: signing certificate is not the trusted one")
	ErrSigNoCert    = errors.New("saml: no certificate available to verify with")
)

// SHA-1 algorithm URIs, flagged by the posture lane.
const (
	algRSASHA1    = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	algDigestSHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"
)

// VerifyResult says what happened when verifying one element.
type VerifyResult struct {
	Err error
	// CertUsed is the certificate the signature was checked against.
	CertUsed *x509.Certificate
	// CertExpiredAtNow is true when the signature verified cryptographically
	// but the certificate was outside its validity period at now. goxmldsig
	// would refuse that outright; we verify at a time inside the cert's
	// window so expiry becomes a separate finding instead of hiding the
	// crypto result.
	CertExpiredAtNow bool
}

// verifyElement checks the enveloped signature on el against trusted. It
// returns only the result; the caller turns it into checks and findings.
func verifyElement(el *etree.Element, trusted *x509.Certificate, now time.Time) VerifyResult {
	if trusted == nil {
		return VerifyResult{Err: ErrSigNoCert}
	}
	res := VerifyResult{CertUsed: trusted}
	clock := now
	if now.Before(trusted.NotBefore) || now.After(trusted.NotAfter) {
		res.CertExpiredAtNow = true
		clock = trusted.NotAfter.Add(-time.Second)
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{trusted}})
	vc.Clock = dsig.NewFakeClockAt(clock)
	if _, err := vc.Validate(el); err != nil {
		res.Err = classify(err)
	}
	return res
}

// classify maps goxmldsig's mixed sentinel/string errors onto ours.
func classify(err error) error {
	switch {
	case errors.Is(err, dsig.ErrMissingSignature):
		return ErrSigMissing
	case errors.Is(err, dsig.ErrInvalidSignature):
		return fmt.Errorf("%w: %v", ErrSigInvalid, err)
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "trusted"), strings.Contains(msg, "Could not verify certificate"):
		return fmt.Errorf("%w: %v", ErrSigUntrusted, err)
	case strings.Contains(msg, "Missing signature"):
		return ErrSigMissing
	}
	return fmt.Errorf("%w: %v", ErrSigInvalid, err)
}

// embeddedCert returns the KeyInfo certificate of the first signature on el.
func embeddedCert(el *etree.Element) *x509.Certificate {
	sig := child(el, NSDSig, "Signature")
	if sig == nil {
		return nil
	}
	return signatureInfo(sig, "").Cert
}

func isSHA1Alg(uri string) bool { return uri == algRSASHA1 || uri == algDigestSHA1 }
