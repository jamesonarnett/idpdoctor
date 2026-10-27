// SPDX-License-Identifier: Apache-2.0

package bundle_test

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/jamesonarnett/idpdoctor/internal/bundle"
	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/fixture"
)

func TestBundleHoldsRedactedFilesOnly(t *testing.T) {
	k, _ := fixture.TestKeys()
	m, _ := fixture.SAMLMutator("audience_mismatch")
	minted, err := fixture.MintSAML(fixture.DefaultParams(), k, m)
	if err != nil {
		t.Fatal(err)
	}
	exp := expected.Expected{SPEntityID: minted.Params.SPEntityID, IdPCertPEM: k.CertPEM(), AccessToken: "at-secret", Now: "2026-01-15T12:00:00Z"}
	res, err := diag.Run(context.Background(), diag.Input{Artifact: string(minted.XML), Expected: exp, Now: fixture.FixedNow})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := bundle.Write(&buf, bundle.Input{Artifact: minted.XML, Result: res, Expected: exp, Symptom: "Invalid audience", Version: "test", Now: fixture.FixedNow}); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		got[f.Name] = string(b)
	}
	for _, name := range []string{"manifest.json", "findings.json", "summary.json", "artifact.redacted.txt", "params.json", "REDACTION.md"} {
		if got[name] == "" {
			t.Errorf("missing %s", name)
		}
	}
	if len(got) != 6 {
		t.Errorf("unexpected entries: %d", len(got))
	}
	all := strings.Join([]string{got["manifest.json"], got["findings.json"], got["summary.json"], got["artifact.redacted.txt"], got["params.json"]}, "\n")
	for _, secret := range []string{"alice@example.com", "Alice", "Admins", "at-secret"} {
		if strings.Contains(all, secret) {
			t.Errorf("bundle leaks %q", secret)
		}
	}
	// The signature value must be masked: nothing in the bundle may be replayable.
	if strings.Contains(got["artifact.redacted.txt"], "<ds:SignatureValue>M") || !strings.Contains(got["artifact.redacted.txt"], "[REDACTED:sig:") {
		t.Error("SignatureValue not masked in the redacted artifact")
	}
	if !strings.Contains(got["findings.json"], "SAML_AUDIENCE_MISMATCH") || !strings.Contains(got["manifest.json"], `"redaction": "default"`) {
		t.Error("findings/manifest content wrong")
	}
	if !strings.Contains(got["params.json"], "[REDACTED:access_token:") || !strings.Contains(got["params.json"], "BEGIN CERTIFICATE") {
		t.Error("params should mask the access token and keep the public cert")
	}
}
