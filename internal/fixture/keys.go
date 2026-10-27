// SPDX-License-Identifier: Apache-2.0

// Package fixture is the in-process test IdP: it mints signed SAML Responses,
// JWTs and JWKS documents, and applies one mutator per failure code so every
// negative case in the test suite and the eval dataset is self-made. No real
// tenant data exists anywhere in this repository.
package fixture

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Keys is an IdP signing identity: private key plus its self-signed cert.
type Keys struct {
	Key     *rsa.PrivateKey
	Cert    *x509.Certificate
	CertDER []byte
}

// CertPEM renders the certificate as PEM, the form an SP admin pastes into
// a config file.
func (k *Keys) CertPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.CertDER}))
}

// TestKeys returns the committed TEST ONLY keypair (testkey.go). Use it for
// anything that is golden-tested so fingerprints stay stable.
func TestKeys() (*Keys, error) {
	cb, _ := pem.Decode([]byte(testCertPEM))
	kb, _ := pem.Decode([]byte(testKeyPEM))
	if cb == nil || kb == nil {
		return nil, errors.New("fixture: embedded test key is malformed")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fixture: parse test cert: %w", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("fixture: parse test key: %w", err)
	}
	return &Keys{Key: key, Cert: cert, CertDER: cb.Bytes}, nil
}

// GenerateKeys mints a fresh self-signed cert with the given validity and
// key size. Used for the "wrong cert", "expired cert" and "weak key" cases
// where the committed key would not do.
func GenerateKeys(cn string, notBefore, notAfter time.Time, bits int) (*Keys, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "TEST ONLY " + cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Keys{Key: key, Cert: cert, CertDER: der}, nil
}
