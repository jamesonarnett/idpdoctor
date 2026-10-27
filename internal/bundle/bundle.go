// SPDX-License-Identifier: Apache-2.0

// Package bundle writes the redacted support-ticket export (BUILD_PLAN
// 2.7, "--redacted-bundle"): the Report, the redacted summary and
// structure, the parameters used, a manifest and a REDACTION.md that says
// what was removed. The raw artifact is never included and nothing in the
// zip can be replayed as a credential (signature values are masked).
package bundle

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/mcpserver"
	"github.com/jamesonarnett/idpdoctor/internal/redact"
)

// Input is what a bundle is made from. Artifact is hashed for the manifest
// and otherwise untouched.
type Input struct {
	Artifact []byte
	Result   *diag.Result
	Expected expected.Expected
	Symptom  string
	Version  string
	Now      time.Time
}

// Manifest is manifest.json.
type Manifest struct {
	Tool           string   `json:"tool"`
	Version        string   `json:"version"`
	Created        string   `json:"created"`
	ArtifactKind   string   `json:"artifact_kind"`
	ArtifactSHA256 string   `json:"artifact_sha256"`
	Redaction      string   `json:"redaction"`
	Files          []string `json:"files"`
}

// Files in the zip, in order.
var files = []string{"manifest.json", "findings.json", "summary.json", "artifact.redacted.txt", "params.json", "REDACTION.md"}

// Write streams the zip to w.
func Write(w io.Writer, in Input) error {
	if in.Result == nil {
		return fmt.Errorf("bundle: Result is required")
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	sum := sha256.Sum256(in.Artifact)
	manifest := Manifest{
		Tool: "idpdoctor", Version: in.Version, Created: now.UTC().Format(time.RFC3339),
		ArtifactKind: string(in.Result.Kind), ArtifactSHA256: hex.EncodeToString(sum[:]), Redaction: "default", Files: files,
	}
	findings := map[string]any{
		"artifact_kind": in.Result.Kind, "findings": in.Result.Report.Findings, "top_cause": in.Result.TopCause,
		"checks": in.Result.Report.Checks, "needs": in.Result.Report.Needs, "symptom": in.Symptom,
		"text": diag.Text(in.Result.Report, in.Result.TopCause), "redaction": "default",
	}
	params := in.Expected
	// These never leave the process even hashed-and-labelled; the bundle
	// records that they were supplied, not what they were.
	params.AccessToken = redact.Value("access_token", params.AccessToken)
	params.CodeVerifier = redact.Value("code_verifier", params.CodeVerifier)

	zw := zip.NewWriter(w)
	entries := []struct {
		name string
		body func() ([]byte, error)
	}{
		{"manifest.json", func() ([]byte, error) { return jsonBytes(manifest) }},
		{"findings.json", func() ([]byte, error) { return jsonBytes(findings) }},
		{"summary.json", func() ([]byte, error) { return jsonBytes(summaryOf(in.Result)) }},
		{"artifact.redacted.txt", func() ([]byte, error) { return []byte(diag.RedactedText(in.Result, mcpserver.MaxToolOutput)), nil }},
		{"params.json", func() ([]byte, error) { return jsonBytes(params) }},
		{"REDACTION.md", func() ([]byte, error) { return []byte(redactionNote), nil }},
	}
	for _, e := range entries {
		body, err := e.body()
		if err != nil {
			return fmt.Errorf("bundle: %s: %w", e.name, err)
		}
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: zip.Deflate, Modified: now})
		if err != nil {
			return err
		}
		if _, err := fw.Write(body); err != nil {
			return err
		}
	}
	return zw.Close()
}

// summaryOf picks the parsed view; each type's JSON form is already
// redacted by its MarshalJSON.
func summaryOf(res *diag.Result) any {
	switch {
	case res.SAML != nil:
		return res.SAML
	case res.JWT != nil:
		return res.JWT
	case res.Cert != nil:
		return res.Cert
	}
	return map[string]any{"artifact_kind": res.Kind}
}

func jsonBytes(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

const redactionNote = `# What this bundle does not contain

This bundle was produced by idpdoctor with redaction "default", the only mode
that exists. It is safe to attach to a support ticket.

Removed or masked before export:

- the raw artifact (SAML Response, id_token, discovery document or redirect
  URL): only its SHA-256 is recorded in manifest.json
- NameID, EncryptedID and BaseID values
- every AttributeValue
- JWT claims that identify a person (sub, email, name, preferred_username,
  upn, oid, groups, ...) and hash claims (at_hash, c_hash)
- SignatureValue and CipherValue, so nothing here can be replayed
- the access token and PKCE code_verifier supplied as expected values
- authorization codes in redirect URLs

Masked values appear as [REDACTED:<kind>:<sha256 prefix>] so two occurrences
of the same value can be matched without learning it.

Kept in clear because diagnosis needs them and they are not PII: entity IDs,
URLs, timestamps, status codes, algorithm URIs, key IDs, certificate
fingerprints and subjects, attribute names, and the IdP signing certificate
(public key material).
`
