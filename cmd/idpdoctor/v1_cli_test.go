// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jamesonarnett/idpdoctor/internal/agent/agenttest"
	"github.com/jamesonarnett/idpdoctor/internal/fixture"
)

func writeFixture(t *testing.T, mutator string) (resp, certFile string, p fixture.Params) {
	t.Helper()
	k, _ := fixture.TestKeys()
	var muts []fixture.Mutator
	if mutator != "" {
		m, ok := fixture.SAMLMutator(mutator)
		if !ok {
			t.Fatal(mutator)
		}
		muts = append(muts, m)
	}
	minted, err := fixture.MintSAML(fixture.DefaultParams(), k, muts...)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	resp = filepath.Join(dir, "response.xml")
	certFile = filepath.Join(dir, "idp.pem")
	if err := os.WriteFile(resp, minted.XML, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, []byte(k.CertPEM()), 0o600); err != nil {
		t.Fatal(err)
	}
	return resp, certFile, minted.Params
}

func TestDiagnoseExplainCLI(t *testing.T) {
	rec := agenttest.Install(t, agenttest.ModeSuccess)
	resp, certFile, p := writeFixture(t, "audience_mismatch")
	for _, mode := range []string{"tools-off", "tools-on"} {
		out, _ := runCLI(t, "diagnose", "-f", resp, "--sp-entity-id", p.SPEntityID, "--idp-cert", certFile, "--now", "2026-01-15T12:00:00Z",
			"--explain", "--explain-mode", mode, "--symptom", "Invalid audience")
		for _, want := range []string{"Top cause: SAML_AUDIENCE_MISMATCH", "Explained by sonnet (" + mode + "): SAML_AUDIENCE_MISMATCH", "WARNING: 1 cited path", "list-price equivalent $0.0123"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: missing %q in:\n%s", mode, want, out)
			}
		}
		if strings.Contains(out, p.NameID) {
			t.Error("explain output leaked the NameID")
		}
		seen := agenttest.Record(t, rec)
		if strings.Contains(seen["STDIN"], p.NameID) {
			t.Errorf("%s: prompt leaked the NameID", mode)
		}
	}
	// tools-on needs a file; stdin is refused before any call.
	t.Setenv("FAKE_CLAUDE_MODE", agenttest.ModeMalformed)
	xml, _ := os.ReadFile(resp)
	root := newRootCmd()
	root.SetIn(strings.NewReader(string(xml)))
	root.SetArgs([]string{"diagnose", "-f", "-", "--explain", "--now", "2026-01-15T12:00:00Z"})
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "needs the artifact in a file") {
		t.Errorf("stdin + tools-on should be refused: %v", err)
	}
	// A failed explain still prints the deterministic result.
	out, err := runCLI(t, "diagnose", "-f", resp, "--sp-entity-id", p.SPEntityID, "--explain", "--explain-mode", "tools-off", "--now", "2026-01-15T12:00:00Z")
	if err == nil || !strings.Contains(err.Error(), "explain:") || !strings.Contains(out, "Top cause: SAML_AUDIENCE_MISMATCH") {
		t.Errorf("failed explain: err=%v out=%s", err, out)
	}
	// --no-llm wins over --explain and makes no call.
	t.Setenv("FAKE_CLAUDE_RECORD", filepath.Join(t.TempDir(), "none"))
	if _, err := runCLI(t, "diagnose", "-f", resp, "--sp-entity-id", p.SPEntityID, "--explain", "--no-llm", "--now", "2026-01-15T12:00:00Z"); err == nil {
		t.Error("broken artifact must still exit 2")
	}
	if _, err := os.Stat(os.Getenv("FAKE_CLAUDE_RECORD")); err == nil {
		t.Error("--no-llm must not invoke claude")
	}
}

func TestBundleCLI(t *testing.T) {
	resp, _, p := writeFixture(t, "expired")
	out := filepath.Join(t.TempDir(), "ticket.zip")
	txt, err := runCLI(t, "bundle", "--redacted", "-f", resp, "--out", out, "--sp-entity-id", p.SPEntityID, "--symptom", "expired")
	if err != nil || !strings.Contains(txt, "wrote") {
		t.Fatalf("bundle: %v %s", err, txt)
	}
	zr, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	for _, want := range []string{"manifest.json", "findings.json", "summary.json", "artifact.redacted.txt", "params.json", "REDACTION.md"} {
		if !names[want] {
			t.Errorf("zip missing %s", want)
		}
	}
	if names["response.xml"] || names["artifact.txt"] {
		t.Error("raw artifact must never be in the bundle")
	}
	if _, err := runCLI(t, "bundle", "--redacted=false", "-f", resp, "--out", out); err == nil {
		t.Error("unredacted bundles must not exist")
	}
}

func TestEvalCLI(t *testing.T) {
	agenttest.Install(t, agenttest.ModeSuccess)
	dir := t.TempDir()
	ds, res := filepath.Join(dir, "ds"), filepath.Join(dir, "res")
	out, err := runCLI(t, "eval", "gen", "--per-class", "1", "--controls", "2", "--out", ds, "--templates", "../../evals/symptom_templates")
	if err != nil || !strings.Contains(out, "wrote") {
		t.Fatalf("gen: %v %s", err, out)
	}
	out, err = runCLI(t, "eval", "run", "--dataset", ds, "--results", res, "--arm", "rules,llm-tools-off", "--only", "saml_audience_mismatch-00,healthy-samlresponse-01", "--max-calls", "5")
	if err != nil || !strings.Contains(out, "rules: 2 cases, 2 correct") || !strings.Contains(out, "real claude calls this invocation: 2") {
		t.Fatalf("run: %v %s", err, out)
	}
	t.Setenv("FAKE_CLAUDE_MODE", agenttest.ModeJudge)
	out, err = runCLI(t, "eval", "judge", "--results", res, "--rubric", "../../evals/rubric.md", "--labels", filepath.Join(dir, "nolabels.csv"), "--limit", "2")
	if err != nil || !strings.Contains(out, "judged 2 result(s) with opus") {
		t.Fatalf("judge: %v %s", err, out)
	}
	md := filepath.Join(dir, "report.md")
	out, err = runCLI(t, "eval", "report", "--results", res, "--dataset", ds, "--labels", "", "--out", md)
	if err != nil || !strings.Contains(out, "| rules-only |") || !strings.Contains(out, "| LLM, tools off (sonnet) |") {
		t.Fatalf("report: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "summary.json")); err != nil {
		t.Error("summary.json not written beside the report")
	}
	if _, err := runCLI(t, "eval", "run", "--dataset", ds, "--results", res, "--arm", "nope"); err == nil {
		t.Error("unknown arm must error")
	}
}
