// SPDX-License-Identifier: Apache-2.0

package eval_test

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jamesonarnett/idpdoctor/internal/agent"
	"github.com/jamesonarnett/idpdoctor/internal/agent/agenttest"
	"github.com/jamesonarnett/idpdoctor/internal/eval"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

const templates = "../../evals/symptom_templates"

func gen(t *testing.T, perClass, controls int) (string, []*eval.Case) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "ds")
	cases, err := eval.Gen(eval.GenOptions{Seed: 42, PerClass: perClass, Controls: controls, Templates: templates, Out: out})
	if err != nil {
		t.Fatal(err)
	}
	return out, cases
}

func TestGenLayoutAndDeterminism(t *testing.T) {
	out, cases := gen(t, 2, 6)
	classes := 0
	for _, s := range finding.Catalog {
		if s.Mutator != "" && s.Lane == finding.LaneFault {
			classes++
		}
	}
	// 2 per fault class, 1 per posture code (per-class/2), 6 controls.
	if want := classes*2 + 8 + 6; len(cases) != want {
		t.Fatalf("cases = %d, want %d", len(cases), want)
	}
	loaded, err := eval.Load(out)
	if err != nil || len(loaded) != len(cases) {
		t.Fatalf("load: %v (%d)", err, len(loaded))
	}
	seen := map[string]bool{}
	for _, c := range loaded {
		for _, f := range []string{eval.FileArtifact, eval.FileExpected, eval.FileLabel, eval.FileMeta, eval.FileSymptom} {
			if _, err := os.Stat(filepath.Join(c.Dir, f)); err != nil {
				t.Errorf("%s missing %s", c.Meta.ID, f)
			}
		}
		if seen[c.Meta.Hash] {
			t.Errorf("duplicate case content: %s", c.Meta.ID)
		}
		seen[c.Meta.Hash] = true
		if c.Meta.Kind == "jwt" && c.Keys.Empty() {
			t.Errorf("%s: JWT case without keys", c.Meta.ID)
		}
		if c.IsPosture() && c.Label.Code != "HEALTHY" {
			t.Errorf("%s: posture fixture must be labelled HEALTHY", c.Meta.ID)
		}
	}
	// Same seed, same bytes.
	out2 := filepath.Join(t.TempDir(), "ds2")
	again, err := eval.Gen(eval.GenOptions{Seed: 42, PerClass: 2, Controls: 6, Templates: templates, Out: out2})
	if err != nil {
		t.Fatal(err)
	}
	for i := range cases {
		if cases[i].Meta.Hash != again[i].Meta.Hash {
			t.Errorf("%s not deterministic", cases[i].Meta.ID)
		}
	}
	// Dialect coverage and symptom templates land.
	dialects, symptoms, misleading := map[string]bool{}, 0, 0
	for _, c := range loaded {
		dialects[c.Meta.Dialect] = true
		if c.Symptom != "" {
			symptoms++
		}
		if c.Meta.Misleading {
			misleading++
		}
	}
	if len(dialects) < 3 || symptoms == 0 || misleading == 0 {
		t.Errorf("dialects=%v symptoms=%d misleading=%d", dialects, symptoms, misleading)
	}
}

// TestRulesArmIsExactOnFullCases: the generator's contract with the
// validators, checked end to end through the runner. The only misses the
// rules arm may have are the cases whose decisive expected value was
// withheld, where the right answer is a question.
func TestRulesArmIsExactOnFullCases(t *testing.T) {
	ds, _ := gen(t, 8, 10)
	var tally bytes.Buffer
	results, calls, err := eval.Run(context.Background(), eval.RunOptions{Dataset: ds, Arm: eval.ArmRules, Results: filepath.Join(t.TempDir(), "res"), Out: &tally})
	if err != nil || calls != 0 {
		t.Fatalf("run: %v calls=%d", err, calls)
	}
	for _, r := range results {
		if r.Error != "" {
			t.Errorf("%s: %s", r.CaseID, r.Error)
		}
		switch {
		case r.Meta.Completeness == "none" && len(r.Label.Needs) > 0:
			if r.Correct() {
				continue
			}
			asked := false
			for _, q := range r.Output.Questions {
				for _, n := range r.Label.Needs {
					if strings.Contains(q, n) {
						asked = true
					}
				}
			}
			if !asked {
				t.Errorf("%s: withheld %v but rules did not ask: %v", r.CaseID, r.Label.Needs, r.Output.Questions)
			}
		case !r.Correct():
			t.Errorf("%s: rules said %s, label %s", r.CaseID, r.Output.RootCauseCode, r.Label.Code)
		}
		if r.IsPostureCase() && !containsAll(r.Output.PostureCodes, r.Label.PostureCodes) {
			t.Errorf("%s: posture %v not reported (%v)", r.CaseID, r.Label.PostureCodes, r.Output.PostureCodes)
		}
	}
	if !strings.Contains(tally.String(), "acc ") {
		t.Error("no running tally printed")
	}
}

func containsAll(have, want []string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			if h == w {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func TestLLMArmsCacheResumeAndCap(t *testing.T) {
	rec := agenttest.Install(t, agenttest.ModeSuccess)
	ds, cases := gen(t, 1, 2)
	res := filepath.Join(t.TempDir(), "res")
	only := []string{cases[0].Meta.ID, cases[1].Meta.ID, cases[2].Meta.ID}

	// Cap at 2 real calls: the third case must not run.
	got, calls, err := eval.Run(context.Background(), eval.RunOptions{Dataset: ds, Arm: eval.ArmToolsOff, Results: res, Only: only, MaxCalls: 2, ServerBin: "/bin/idpdoctor"})
	if err != eval.ErrMaxCalls || calls != 2 || len(got) != 2 {
		t.Fatalf("cap: err=%v calls=%d results=%d", err, calls, len(got))
	}
	// Resume: the two cached cases cost nothing; only the third runs.
	got, calls, err = eval.Run(context.Background(), eval.RunOptions{Dataset: ds, Arm: eval.ArmToolsOff, Results: res, Only: only, ServerBin: "/bin/idpdoctor"})
	if err != nil || calls != 1 || len(got) != 3 {
		t.Fatalf("resume: err=%v calls=%d results=%d", err, calls, len(got))
	}
	for _, r := range got {
		if r.Output == nil || r.Output.RootCauseCode != "SAML_AUDIENCE_MISMATCH" || r.CostUSD != 0.0123 || r.Usage.OutputTokens != 40 {
			t.Errorf("%s: %+v", r.CaseID, r)
		}
		if len(r.Hallucinated) != 1 {
			t.Errorf("%s: the fake cites one made-up path; hallucinated=%v", r.CaseID, r.Hallucinated)
		}
	}
	if _, err := os.Stat(filepath.Join(eval.ArmDir(res, eval.ArmToolsOff, "sonnet"), "manifest.json")); err != nil {
		t.Error("manifest missing")
	}
	// The prompt the fake saw carried no raw identity value.
	seen := agenttest.Record(t, rec)
	for _, s := range []string{"alice@example.com", "Alice", "AUTHCODE-secret", "verifier-secret"} {
		if strings.Contains(seen["STDIN"], s) {
			t.Errorf("prompt leaked %q", s)
		}
	}

	// Tools-on: handle in the prompt, mcp-config on the command line.
	got, calls, err = eval.Run(context.Background(), eval.RunOptions{Dataset: ds, Arm: eval.ArmToolsOn, Results: res, Only: only[:1], ServerBin: "/bin/idpdoctor", Concurrency: 5})
	if err != nil || calls != 1 || len(got) != 1 {
		t.Fatalf("tools-on: err=%v calls=%d results=%d", err, calls, len(got))
	}
	seen = agenttest.Record(t, rec)
	if !strings.Contains(seen["ARGS"], "--mcp-config") || !strings.Contains(seen["STDIN"], "art_") || strings.Contains(seen["STDIN"], "<") {
		t.Errorf("tools-on prompt/args wrong: %s / %s", seen["ARGS"], seen["STDIN"])
	}

	// Errors are recorded, not fatal, and are retried on the next run.
	t.Setenv("FAKE_CLAUDE_MODE", agenttest.ModeDenial)
	got, _, err = eval.Run(context.Background(), eval.RunOptions{Dataset: ds, Arm: eval.ArmToolsOn, Results: res, Only: only[1:2], ServerBin: "/bin/idpdoctor"})
	if err != nil || len(got) != 1 || !strings.Contains(got[0].Error, "permission denials") {
		t.Fatalf("denial: err=%v got=%+v", err, got)
	}
	t.Setenv("FAKE_CLAUDE_MODE", agenttest.ModeSuccess)
	_, calls, _ = eval.Run(context.Background(), eval.RunOptions{Dataset: ds, Arm: eval.ArmToolsOn, Results: res, Only: only[1:2], ServerBin: "/bin/idpdoctor"})
	if calls != 1 {
		t.Errorf("a failed case must be retried, calls=%d", calls)
	}
}

func TestJudgeAndReport(t *testing.T) {
	agenttest.Install(t, agenttest.ModeSuccess)
	ds, cases := gen(t, 1, 2)
	res := filepath.Join(t.TempDir(), "res")
	only := []string{cases[0].Meta.ID, cases[1].Meta.ID}
	if _, _, err := eval.Run(context.Background(), eval.RunOptions{Dataset: ds, Arm: eval.ArmRules, Results: res, Only: only}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := eval.Run(context.Background(), eval.RunOptions{Dataset: ds, Arm: eval.ArmToolsOff, Results: res, Only: only, ServerBin: "/bin/idpdoctor"}); err != nil {
		t.Fatal(err)
	}

	t.Setenv("FAKE_CLAUDE_MODE", agenttest.ModeJudge)
	armDir := filepath.Base(eval.ArmDir(res, eval.ArmToolsOff, "sonnet"))
	verdicts, calls, err := eval.Judge(context.Background(), eval.JudgeOptions{Results: res, Arms: []string{armDir, eval.ArmRules}, Rubric: "../../evals/rubric.md", Limit: 3})
	if err != nil || calls != 3 || len(verdicts) != 3 {
		t.Fatalf("judge: err=%v calls=%d verdicts=%d", err, calls, len(verdicts))
	}
	if v := verdicts[0]; !v.EvidenceCorrect || v.FixScore != 4 || v.Judge != "opus" || v.CostUSD != 0.02 {
		t.Errorf("verdict: %+v", v)
	}
	// Cached on the second pass.
	_, calls, err = eval.Judge(context.Background(), eval.JudgeOptions{Results: res, Arms: []string{armDir, eval.ArmRules}, Rubric: "../../evals/rubric.md"})
	if err != nil || calls != 1 {
		t.Errorf("judge resume: err=%v calls=%d (one rules verdict was beyond the limit)", err, calls)
	}

	labels := filepath.Join(t.TempDir(), "hand_labels.csv")
	csv := "case_id,arm,evidence_correct,fix_score,notes\n" +
		cases[0].Meta.ID + "," + armDir + ",1,4,placeholder\n" +
		cases[1].Meta.ID + "," + armDir + ",0,2,placeholder\n"
	if err := os.WriteFile(labels, []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := eval.Build(eval.ReportOptions{Results: res, Dataset: ds, Labels: labels})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Arms) != 2 || rep.Arms[0].Arm != eval.ArmRules || rep.Arms[1].Judged != 2 || rep.Agreement == nil || rep.Agreement.Pairs != 2 || !rep.Agreement.Placeholder {
		t.Fatalf("report: %+v", rep)
	}
	md := rep.Markdown()
	for _, want := range []string{"| Arm | Root-cause acc. | Top-2 | FP rate (controls) | Evidence correct (judge) | Fix score (1-5) | p50 / p95 latency | Tool calls/case | Tokens/case (in / out) | List-price equiv./case |",
		"| rules-only |", "| LLM, tools off (sonnet) |", "PLACEHOLDER", "Confusion matrix", "Hallucinated citations", "$0.0123"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
	// The LLM arm's hallucination rate: the fake cites 2 paths per case, 1 made up.
	if h := float64(rep.Arms[1].HallucinationRate); math.Abs(h-0.5) > 0.001 {
		t.Errorf("hallucination rate = %v", h)
	}
}

func TestKappa(t *testing.T) {
	bin := []int{0, 1}
	if k := eval.Kappa([]int{1, 0, 1, 0}, []int{1, 0, 1, 0}, bin); k != 1 {
		t.Errorf("perfect agreement kappa = %v", k)
	}
	if k := eval.Kappa([]int{1, 1, 0, 0}, []int{1, 0, 1, 0}, bin); k != 0 {
		t.Errorf("chance agreement kappa = %v", k)
	}
	if k := eval.Kappa([]int{1, 0}, []int{0, 1}, bin); k != -1 {
		t.Errorf("total disagreement kappa = %v", k)
	}
	if k := eval.Kappa([]int{1, 1}, []int{1, 1}, bin); !math.IsNaN(k) {
		t.Errorf("degenerate kappa should be NaN, got %v", k)
	}
	// Textbook example: kappa = (0.70 - 0.50) / (1 - 0.50) = 0.4 for
	// a=[1x20,0x5 | 1x10,0x15] style data.
	var a, b []int
	for i := 0; i < 20; i++ {
		a, b = append(a, 1), append(b, 1)
	}
	for i := 0; i < 5; i++ {
		a, b = append(a, 1), append(b, 0)
	}
	for i := 0; i < 10; i++ {
		a, b = append(a, 0), append(b, 1)
	}
	for i := 0; i < 15; i++ {
		a, b = append(a, 0), append(b, 0)
	}
	if k := eval.Kappa(a, b, bin); math.Abs(k-0.4) > 1e-9 {
		t.Errorf("textbook kappa = %v, want 0.4", k)
	}
	likert := []int{1, 2, 3, 4, 5}
	if k := eval.WeightedKappa([]int{1, 2, 3, 4, 5}, []int{1, 2, 3, 4, 5}, likert); k != 1 {
		t.Errorf("weighted perfect = %v", k)
	}
	near := eval.WeightedKappa([]int{1, 2, 3, 4, 5, 1, 5}, []int{2, 2, 3, 4, 4, 1, 5}, likert)
	far := eval.WeightedKappa([]int{1, 2, 3, 4, 5, 1, 5}, []int{5, 2, 3, 4, 1, 1, 5}, likert)
	if !(near > far) || near <= 0 {
		t.Errorf("quadratic weights: near=%v far=%v", near, far)
	}
	if p := eval.PercentAgreement([]int{1, 0, 1}, []int{1, 1, 1}); math.Abs(p-2.0/3) > 1e-9 {
		t.Errorf("percent agreement = %v", p)
	}
}

func TestUnsafeFixRegex(t *testing.T) {
	bad := []string{"Disable signature validation on the SP.", "Just accept unsigned assertions for now", "Increase the clock skew to 30 minutes", "skip the audience check", "downgrade to SHA1"}
	good := []string{"Set the IdP application's Audience URI to the SP entity ID exactly.", "Keep clock skew at or below 3 minutes and fix NTP.", "Require a signed assertion."}
	for _, s := range bad {
		if !eval.UnsafeFixRegex(s) {
			t.Errorf("should flag %q", s)
		}
	}
	for _, s := range good {
		if eval.UnsafeFixRegex(s) {
			t.Errorf("should not flag %q", s)
		}
	}
}

// TestStaleCacheRerunsOnPromptVersion: the cache key is case hash plus
// prompt version. A result stamped with an older prompt is re-run and
// counts as a real call; a current one is reused.
func TestStaleCacheRerunsOnPromptVersion(t *testing.T) {
	agenttest.Install(t, agenttest.ModeCheckName)
	ds, cases := gen(t, 1, 1)
	res := filepath.Join(t.TempDir(), "res")
	only := []string{cases[0].Meta.ID, cases[1].Meta.ID}
	got, calls, err := eval.Run(context.Background(), eval.RunOptions{Dataset: ds, Arm: eval.ArmToolsOff, Results: res, Only: only, ServerBin: "/bin/idpdoctor"})
	if err != nil || calls != 2 || len(got) != 2 {
		t.Fatalf("first run: err=%v calls=%d results=%d", err, calls, len(got))
	}
	for _, r := range got {
		if r.PromptVersion != agent.PromptVersion {
			t.Errorf("%s: prompt_version = %d, want %d", r.CaseID, r.PromptVersion, agent.PromptVersion)
		}
		// The fake cites: Audience (valid), checks/audience (normalised),
		// issuer (hallucinated: ambiguous), /Response/Made/Up (hallucinated).
		if r.ValidCitations != 1 || len(r.Normalised) != 1 || len(r.Hallucinated) != 2 {
			t.Errorf("%s: valid=%d normalised=%+v hallucinated=%v", r.CaseID, r.ValidCitations, r.Normalised, r.Hallucinated)
		}
	}
	// Age one cached result to prompt v1 (as the committed smoke results are).
	stale := filepath.Join(eval.ArmDir(res, eval.ArmToolsOff, "sonnet"), cases[0].Meta.Hash+".json")
	b, err := os.ReadFile(stale)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.Replace(b, []byte(`"prompt_version": `+itoa(agent.PromptVersion)), []byte(`"prompt_version": 1`), 1)
	if err := os.WriteFile(stale, b, 0o644); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	_, calls, err = eval.Run(context.Background(), eval.RunOptions{Dataset: ds, Arm: eval.ArmToolsOff, Results: res, Only: only, ServerBin: "/bin/idpdoctor", Out: &log})
	if err != nil || calls != 1 {
		t.Fatalf("stale rerun: err=%v calls=%d\n%s", err, calls, log.String())
	}
	if !strings.Contains(log.String(), "stale (prompt v1, now v"+itoa(agent.PromptVersion)+")") || !strings.Contains(log.String(), "cached") {
		t.Errorf("log should show one stale and one cached case:\n%s", log.String())
	}
	var man eval.Manifest
	mb, _ := os.ReadFile(filepath.Join(eval.ArmDir(res, eval.ArmToolsOff, "sonnet"), "manifest.json"))
	if err := json.Unmarshal(mb, &man); err != nil || man.PromptVersion != agent.PromptVersion {
		t.Errorf("manifest prompt_version: %+v (%v)", man, err)
	}
	// Normalised citations are their own column, never folded into valid.
	rep, err := eval.Build(eval.ReportOptions{Results: res, Dataset: ds})
	if err != nil {
		t.Fatal(err)
	}
	m := rep.Arms[0]
	if m.Citations != 8 || math.Abs(float64(m.HallucinationRate)-0.5) > 0.001 || math.Abs(float64(m.NormalisedRate)-0.25) > 0.001 {
		t.Errorf("citations=%d hallucinated=%v normalised=%v", m.Citations, m.HallucinationRate, m.NormalisedRate)
	}
	if md := rep.Markdown(); !strings.Contains(md, "| Normalised citations |") || !strings.Contains(md, "| 50.0% (8 cited) | 25.0% |") {
		t.Errorf("markdown:\n%s", md)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
