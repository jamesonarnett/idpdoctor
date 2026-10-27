// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jamesonarnett/idpdoctor/internal/fixture"
)

// runCLI executes the cobra tree in-process and captures stdout.
func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func TestDiagnoseCLI(t *testing.T) {
	k, _ := fixture.TestKeys()
	m, _ := fixture.SAMLMutator("expired")
	minted, _ := fixture.MintSAML(fixture.DefaultParams(), k, m)
	dir := t.TempDir()
	resp := filepath.Join(dir, "response.xml")
	certFile := filepath.Join(dir, "idp.pem")
	if err := os.WriteFile(resp, minted.XML, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, []byte(k.CertPEM()), 0o600); err != nil {
		t.Fatal(err)
	}
	p := minted.Params

	out, err := runCLI(t, "diagnose", "-f", resp, "--sp-entity-id", p.SPEntityID, "--acs-url", p.ACSURL,
		"--idp-entity-id", p.IdPEntityID, "--idp-cert", certFile, "--request-id", p.RequestID, "--now", "2026-01-15T12:00:00Z")
	var ee exitError
	if !errors.As(err, &ee) || ee.code != 2 {
		t.Fatalf("want exit 2 for a broken artifact, got %v", err)
	}
	for _, want := range []string{"Top cause: SAML_TIME_WINDOW_INVALID", "signature_verify=pass", "fix:"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, p.NameID) {
		t.Error("CLI output leaked the NameID")
	}

	// Replayed at capture time, the same artifact is healthy.
	out, err = runCLI(t, "diagnose", "-f", resp, "--idp-cert", certFile, "--now", "2026-01-15T11:38:00Z", "--json")
	if err != nil {
		t.Fatalf("replay: %v\n%s", err, out)
	}
	if !strings.Contains(out, `"redaction": "default"`) {
		t.Errorf("json output: %s", out)
	}
}

func TestDecodeAndCertCLI(t *testing.T) {
	k, _ := fixture.TestKeys()
	minted, _ := fixture.MintSAML(fixture.DefaultParams(), k)
	resp := filepath.Join(t.TempDir(), "r.xml")
	if err := os.WriteFile(resp, minted.XML, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCLI(t, "saml", "decode", "-f", resp)
	if err != nil || !strings.Contains(out, "[REDACTED:nameid:") || strings.Contains(out, "alice") {
		t.Errorf("decode: %v\n%s", err, out)
	}
	out, err = runCLI(t, "cert", "inspect", "--input", k.CertPEM(), "--now", "2026-01-15T12:00:00Z")
	if err != nil || !strings.Contains(out, "2048 bits") || !strings.Contains(out, "findings: 0") {
		t.Errorf("cert inspect: %v\n%s", err, out)
	}
	if _, err := runCLI(t, "saml", "decode"); err == nil {
		t.Error("no input must error")
	}
}
