// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jamesonarnett/idpdoctor/internal/agent"
	"github.com/jamesonarnett/idpdoctor/internal/agent/agenttest"
	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/fixture"
	"github.com/jamesonarnett/idpdoctor/internal/redact"
)

// secrets are the fixture's identity values; none may reach a prompt.
var secrets = []string{"alice@example.com", "Alice", "Admins", "Everyone"}

func mintCase(t *testing.T) (path string, data []byte, res *diag.Result, exp expected.Expected) {
	t.Helper()
	k, _ := fixture.TestKeys()
	m, _ := fixture.SAMLMutator("audience_mismatch")
	minted, err := fixture.MintSAML(fixture.DefaultParams(), k, m)
	if err != nil {
		t.Fatal(err)
	}
	exp = expected.Expected{SPEntityID: minted.Params.SPEntityID, IdPCertPEM: k.CertPEM(), Now: "2026-01-15T12:00:00Z", AccessToken: "at-secret-value"}
	res, err = diag.Run(context.Background(), diag.Input{Artifact: string(minted.XML), Expected: exp, Now: fixture.FixedNow})
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "response.xml")
	if err := os.WriteFile(path, minted.XML, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, minted.XML, res, exp
}

func TestExplainToolsOffUsesRedactedTextOnly(t *testing.T) {
	rec := agenttest.Install(t, agenttest.ModeSuccess)
	path, _, res, exp := mintCase(t)
	out, err := agent.Explain(context.Background(), &agent.Runner{}, agent.ExplainInput{
		Mode: agent.ModeToolsOff, ArtifactPath: path, Result: res, Symptom: "Okta says Invalid audience", Expected: exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Diagnosis.RootCauseCode != "SAML_AUDIENCE_MISMATCH" || out.ValidCitations != 1 || len(out.Hallucinated) != 1 || out.Hallucinated[0] != "/Response/Made/Up" {
		t.Errorf("explanation: %+v", out)
	}
	if out.ToolCalls != 0 || out.Mode != agent.ModeToolsOff || out.Model != "sonnet" {
		t.Errorf("tools-off facts: %+v", out)
	}
	got := agenttest.Record(t, rec)
	for _, s := range secrets {
		if strings.Contains(got["STDIN"], s) || strings.Contains(out.Prompt, s) {
			t.Errorf("prompt leaked %q", s)
		}
	}
	for _, want := range []string{"[REDACTED:nameid:", "Invalid audience", "sp_entity_id", "Redacted artifact"} {
		if !strings.Contains(got["STDIN"], want) {
			t.Errorf("prompt missing %q", want)
		}
	}
	if strings.Contains(got["STDIN"], "at-secret-value") || !strings.Contains(got["STDIN"], "[REDACTED:access_token:") {
		t.Error("access_token must be masked in the prompt")
	}
	if strings.Contains(got["ARGS"], "--mcp-config") {
		t.Error("tools-off must not configure MCP")
	}
	if !strings.Contains(got["ARGS"], "[--max-turns] [3]") {
		t.Errorf("tools-off max-turns: %s", got["ARGS"])
	}
}

func TestExplainToolsOnPassesHandleNeverArtifact(t *testing.T) {
	rec := agenttest.Install(t, agenttest.ModeSuccess)
	path, data, res, exp := mintCase(t)
	trace := filepath.Join(t.TempDir(), "trace.jsonl")
	// Pretend the MCP server made two calls; the fake claude never starts it.
	if err := os.WriteFile(trace, []byte("{\"tool\":\"diagnose\"}\n{\"tool\":\"saml_validate\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := agent.Explain(context.Background(), &agent.Runner{}, agent.ExplainInput{
		Mode: agent.ModeToolsOn, ArtifactPath: path, Result: res, Expected: exp, ServerBin: "/usr/local/bin/idpdoctor", TracePath: trace,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.ToolCalls != 2 {
		t.Errorf("tool calls from trace = %d", out.ToolCalls)
	}
	got := agenttest.Record(t, rec)
	handle := redact.RefFor(data)
	if !strings.Contains(got["STDIN"], handle) {
		t.Errorf("prompt must carry the handle %s: %s", handle, got["STDIN"])
	}
	if strings.Contains(got["STDIN"], "<") || strings.Contains(got["STDIN"], "REDACTED:nameid") {
		t.Error("tools-on prompt must not carry the artifact in any form")
	}
	for _, s := range secrets {
		if strings.Contains(got["STDIN"], s) {
			t.Errorf("prompt leaked %q", s)
		}
	}
	for _, want := range []string{"[--mcp-config]", "[--allowedTools] [mcp__idpdoctor__*]", "[--max-turns] [8]", "[--strict-mcp-config]"} {
		if !strings.Contains(got["ARGS"], want) {
			t.Errorf("args missing %s: %s", want, got["ARGS"])
		}
	}
	// The mcp config named the server binary and the artifact path only.
	i := strings.Index(got["ARGS"], "[--mcp-config] [")
	cfgPath := got["ARGS"][i+len("[--mcp-config] ["):]
	cfgPath = cfgPath[:strings.Index(cfgPath, "]")]
	if _, err := os.Stat(cfgPath); err == nil {
		t.Error("mcp config temp dir should be removed after the run")
	}
	if !strings.Contains(agent.SystemPrompt(agent.ModeToolsOn), "stash_file") || strings.Contains(agent.SystemPrompt(agent.ModeToolsOff), "MCP tools") {
		t.Error("system prompt should mention tools only in tools-on mode")
	}
}

func TestExplainToolsOnNeedsPath(t *testing.T) {
	agenttest.Install(t, agenttest.ModeSuccess)
	_, _, res, exp := mintCase(t)
	_, err := agent.Explain(context.Background(), &agent.Runner{}, agent.ExplainInput{Mode: agent.ModeToolsOn, Result: res, Expected: exp})
	if err != agent.ErrNeedArtifactPath {
		t.Fatalf("want ErrNeedArtifactPath, got %v", err)
	}
}

func TestCheckCitationsNormalises(t *testing.T) {
	known := []string{"/Response/Assertion/Subject/NameID", "/claims/aud"}
	valid, bad := agent.CheckCitations([]agent.Citation{
		{Path: "/Response/Assertion[1]/Subject/NameID "}, {Path: "/claims/aud/"}, {Path: "/claims/sub"}, {Path: ""},
	}, known)
	if valid != 2 || len(bad) != 2 {
		t.Errorf("valid=%d bad=%v", valid, bad)
	}
}

// TestExplainCitationBins drives the three citation outcomes through the
// fake claude: a verbatim path is valid, "checks/audience" is normalised to
// the Audience path (and the diagnosis carries the mapped path), and both a
// fabricated path and an ambiguous check name stay hallucinated. The
// prompt v2 contract is checked on the wire too: the allowed-path list and
// the worked examples are in the user turn, and the schema enum carries the
// allowed paths and nothing else.
func TestExplainCitationBins(t *testing.T) {
	rec := agenttest.Install(t, agenttest.ModeCheckName)
	path, _, res, exp := mintCase(t)
	out, err := agent.Explain(context.Background(), &agent.Runner{}, agent.ExplainInput{
		Mode: agent.ModeToolsOff, ArtifactPath: path, Result: res, Symptom: "Invalid audience", Expected: exp,
	})
	if err != nil {
		t.Fatal(err)
	}
	const audience = "/Response/Assertion/Conditions/AudienceRestriction/Audience"

	// 1. A correct path counts as valid and nothing else.
	if out.ValidCitations != 1 {
		t.Errorf("valid = %d, want 1 (the verbatim Audience path)", out.ValidCitations)
	}
	// 2. The check-name citation is normalised, recorded, rewritten, and not counted as valid.
	if len(out.Normalised) != 1 || out.Normalised[0].Cited != "checks/audience" || out.Normalised[0].Path != audience {
		t.Errorf("normalised = %+v", out.Normalised)
	}
	if got := out.Diagnosis.Evidence[1].Path; got != audience {
		t.Errorf("normalised citation not rewritten in the diagnosis: %q", got)
	}
	// 3. The fabricated path stays hallucinated; so does "issuer", which is
	//    ambiguous for SAML (Response/Issuer vs Assertion/Issuer, no finding).
	if len(out.Hallucinated) != 2 || out.Hallucinated[0] != "issuer" || out.Hallucinated[1] != "/Response/Made/Up" {
		t.Errorf("hallucinated = %v", out.Hallucinated)
	}
	if out.ValidCitations+len(out.Normalised)+len(out.Hallucinated) != len(out.Diagnosis.Evidence) {
		t.Error("every citation must land in exactly one bin")
	}

	got := agenttest.Record(t, rec)
	for _, want := range []string{
		"Allowed evidence paths for this artifact", "  " + audience + "\n",
		`Correct:   {"path": "` + audience + `"`, `Incorrect: {"path": "checks/audience"`, "paraphrased",
	} {
		if !strings.Contains(got["STDIN"], want) {
			t.Errorf("prompt missing %q", want)
		}
	}
	if !strings.Contains(agent.SystemPrompt(agent.ModeToolsOff), "copied verbatim") {
		t.Error("system prompt must state the verbatim rule")
	}
	i := strings.Index(got["ARGS"], "[--json-schema] [")
	if i < 0 {
		t.Fatalf("no --json-schema in %s", got["ARGS"])
	}
	schema := got["ARGS"][i:]
	if !strings.Contains(schema, `"enum":[`) || !strings.Contains(schema, `"`+audience+`"`) {
		t.Errorf("schema must enumerate the allowed paths: %s", schema[:min(len(schema), 400)])
	}
	if strings.Contains(schema, "Made/Up") || strings.Contains(schema, "checks/") {
		t.Error("schema enum must hold only allowed paths")
	}
}

func TestClassifyCitationsBins(t *testing.T) {
	allowed := []string{"/claims/aud", "/claims/iss", "/header/alg"}
	checkPaths := map[string]string{"aud": "/claims/aud", "alg_allowed": "/header/alg", "stale": "/claims/gone"}
	cites := []agent.Citation{
		{Path: "/claims/aud"},         // valid
		{Path: "checks/aud"},          // normalised
		{Path: "/checks/alg_allowed"}, // normalised (leading slash)
		{Path: "aud"},                 // normalised (bare name)
		{Path: "iss"},                 // check name with no mapping: hallucinated
		{Path: "stale"},               // mapped to a path that is not allowed: hallucinated
		{Path: "/claims/sub"},         // fabricated: hallucinated
		{Path: "checks/aud/value"},    // not an exact check-name shape: hallucinated
	}
	valid, norm, bad := agent.ClassifyCitations(cites, allowed, checkPaths)
	if valid != 1 || len(norm) != 3 || len(bad) != 4 {
		t.Fatalf("valid=%d normalised=%+v hallucinated=%v", valid, norm, bad)
	}
	for i, want := range []string{"/claims/aud", "/claims/aud", "/header/alg", "/claims/aud"} {
		if cites[i].Path != want {
			t.Errorf("cites[%d].Path = %q, want %q", i, cites[i].Path, want)
		}
	}
	for i, want := range []string{"iss", "stale", "/claims/sub", "checks/aud/value"} {
		if bad[i] != want {
			t.Errorf("hallucinated[%d] = %q, want %q (must be reported as written)", i, bad[i], want)
		}
	}
	// Without a map nothing is normalised and the old split is unchanged.
	v2, b2 := agent.CheckCitations([]agent.Citation{{Path: "/claims/aud"}, {Path: "checks/aud"}}, allowed)
	if v2 != 1 || len(b2) != 1 || b2[0] != "checks/aud" {
		t.Errorf("CheckCitations: valid=%d bad=%v", v2, b2)
	}
}

func TestDiagnosisSchemaForEnum(t *testing.T) {
	var s map[string]any
	if err := json.Unmarshal(agent.DiagnosisSchemaFor([]string{"/a", "/b"}), &s); err != nil {
		t.Fatal(err)
	}
	path := s["properties"].(map[string]any)["evidence"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["path"].(map[string]any)
	enum, _ := path["enum"].([]any)
	if len(enum) != 2 || enum[0] != "/a" || enum[1] != "/b" {
		t.Errorf("enum = %v", path["enum"])
	}
	if err := json.Unmarshal(agent.DiagnosisSchema(), &s); err != nil {
		t.Fatal(err)
	}
	path = s["properties"].(map[string]any)["evidence"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["path"].(map[string]any)
	if _, has := path["enum"]; has {
		t.Error("the unconstrained schema must not carry an enum")
	}
}
