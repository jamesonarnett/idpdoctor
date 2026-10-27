// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/jamesonarnett/idpdoctor/internal/agent"
	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/fixture"
)

// Arms (BUILD_PLAN 5.4).
const (
	ArmRules    = "rules"
	ArmToolsOff = "llm-tools-off"
	ArmToolsOn  = "llm-tools-on"
)

// Arms in report order.
var Arms = []string{ArmRules, ArmToolsOff, ArmToolsOn}

// ErrMaxCalls stops a run when the real-call cap is reached.
var ErrMaxCalls = errors.New("eval: max real claude calls reached")

// RunOptions drives one arm over one dataset.
type RunOptions struct {
	Dataset string
	Arm     string
	Model   string // diagnoser alias; ignored for rules
	// Results is the root results dir; the arm writes to Results/<arm>/.
	Results string
	// Concurrency is 1 by default and capped at 2 (subscription etiquette).
	Concurrency int
	// MaxCalls caps real model calls in this invocation (0 = no cap). Cached
	// cases do not count. The smoke eval uses it as a hard stop.
	MaxCalls int
	// ServerBin is the idpdoctor binary the tools-on MCP server runs as.
	ServerBin string
	// Only restricts the run to these case IDs (nil = all).
	Only []string
	// Out receives the running tally; nil means discard.
	Out io.Writer
	// Runner lets tests inject timeouts; nil means defaults.
	Runner *agent.Runner
}

// Output is the arm's answer in a shape shared by all three arms: the
// rules arm fills it from the deterministic Report, the LLM arms from the
// model's Diagnosis.
type Output struct {
	RootCauseCode string              `json:"root_cause_code"`
	Confidence    float64             `json:"confidence"`
	Evidence      []agent.Citation    `json:"evidence"`
	Fix           string              `json:"fix"`
	PostureCodes  []string            `json:"posture_codes"`
	Alternatives  []agent.Alternative `json:"alternatives"`
	Questions     []string            `json:"questions"`
}

// CaseResult is one cached result file.
type CaseResult struct {
	CaseID   string    `json:"case_id"`
	CaseHash string    `json:"case_hash"`
	Arm      string    `json:"arm"`
	Model    string    `json:"model,omitempty"`
	Label    Label     `json:"label"`
	Kind     string    `json:"kind"`
	Meta     Meta      `json:"meta"`
	Output   *Output   `json:"output"`
	Error    string    `json:"error,omitempty"`
	Started  time.Time `json:"started"`
	// Facts for the metrics.
	DurationMS     int64                       `json:"duration_ms"`
	ToolCalls      int                         `json:"tool_calls"`
	NumTurns       int                         `json:"num_turns"`
	Usage          agent.Usage                 `json:"usage"`
	CostUSD        float64                     `json:"cost_usd"`
	ModelUsage     map[string]agent.ModelUsage `json:"model_usage,omitempty"`
	Hallucinated   []string                    `json:"hallucinated"`
	ValidCitations int                         `json:"valid_citations"`
	// Envelope is the raw CLI envelope for audit; it holds no artifact.
	Envelope json.RawMessage `json:"envelope,omitempty"`
}

// Correct reports whether the root cause matches the label.
func (r *CaseResult) Correct() bool { return r.Output != nil && r.Output.RootCauseCode == r.Label.Code }

// IsPostureCase reports whether the label carries posture codes.
func (r *CaseResult) IsPostureCase() bool { return len(r.Label.PostureCodes) > 0 }

// Top2 reports whether the label is the answer or the first alternative.
func (r *CaseResult) Top2() bool {
	if r.Correct() {
		return true
	}
	return r.Output != nil && len(r.Output.Alternatives) > 0 && r.Output.Alternatives[0].Code == r.Label.Code
}

// Manifest records how an arm was run.
type Manifest struct {
	Arm           string    `json:"arm"`
	Model         string    `json:"model,omitempty"`
	Dataset       string    `json:"dataset"`
	Started       time.Time `json:"started"`
	ClaudeVersion string    `json:"claude_version,omitempty"`
	Version       string    `json:"idpdoctor_version"`
	Concurrency   int       `json:"concurrency"`
}

// Version is stamped by the CLI.
var Version = "dev"

// Run executes one arm, resuming from cached results. It returns the
// results for every case (cached or fresh) and the number of real calls
// made in this invocation.
func Run(ctx context.Context, o RunOptions) ([]*CaseResult, int, error) {
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 1
	}
	if o.Concurrency > 2 {
		o.Concurrency = 2
	}
	if o.Arm == ArmRules {
		o.Concurrency = 1
	}
	if o.Model == "" {
		o.Model = agent.DefaultModel
	}
	if o.Runner == nil {
		o.Runner = &agent.Runner{Model: o.Model}
	}
	cases, err := Load(o.Dataset)
	if err != nil {
		return nil, 0, err
	}
	cases = filterCases(cases, o.Only)
	dir := ArmDir(o.Results, o.Arm, o.Model)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, 0, err
	}
	man := Manifest{Arm: o.Arm, Model: o.Model, Dataset: o.Dataset, Started: time.Now(), Version: Version, Concurrency: o.Concurrency}
	if o.Arm != ArmRules {
		man.ClaudeVersion = claudeVersion(ctx)
	}
	if err := writeJSON(filepath.Join(dir, "manifest.json"), man); err != nil {
		return nil, 0, err
	}

	var (
		mu      sync.Mutex
		results = make([]*CaseResult, len(cases))
		calls   int
		done    int
		correct int
		stop    error
	)
	sem := make(chan struct{}, o.Concurrency)
	var wg sync.WaitGroup
	for i, c := range cases {
		path := filepath.Join(dir, c.Meta.Hash+".json")
		if cached, err := readResult(path); err == nil && cached.Error == "" {
			results[i] = cached
			mu.Lock()
			done++
			if cached.Correct() {
				correct++
			}
			fmt.Fprintf(o.Out, "[%d/%d] %-40s cached  %s  acc %.0f%%\n", done, len(cases), c.Meta.ID, mark(cached), 100*float64(correct)/float64(done))
			mu.Unlock()
			continue
		}
		mu.Lock()
		if o.MaxCalls > 0 && o.Arm != ArmRules && calls >= o.MaxCalls {
			stop = ErrMaxCalls
			mu.Unlock()
			break
		}
		if o.Arm != ArmRules {
			calls++
		}
		mu.Unlock()
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, c *Case, path string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := runOne(ctx, o, c)
			_ = writeJSON(path, r)
			mu.Lock()
			results[i] = r
			done++
			if r.Correct() {
				correct++
			}
			fmt.Fprintf(o.Out, "[%d/%d] %-40s %5.1fs  %s  $%.4f  acc %.0f%%\n", done, len(cases), c.Meta.ID, float64(r.DurationMS)/1000, mark(r), r.CostUSD, 100*float64(correct)/float64(done))
			mu.Unlock()
		}(i, c, path)
	}
	wg.Wait()
	var out []*CaseResult
	for _, r := range results {
		if r != nil {
			out = append(out, r)
		}
	}
	return out, calls, stop
}

func mark(r *CaseResult) string {
	switch {
	case r.Error != "":
		return "ERR  " + truncate(r.Error, 40)
	case r.Correct():
		return "ok   " + r.Output.RootCauseCode
	default:
		return "MISS " + r.Output.RootCauseCode + " (label " + r.Label.Code + ")"
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// runOne produces one CaseResult; errors are recorded, never fatal, so a
// bad case cannot sink a long run.
func runOne(ctx context.Context, o RunOptions, c *Case) *CaseResult {
	r := &CaseResult{CaseID: c.Meta.ID, CaseHash: c.Meta.Hash, Arm: o.Arm, Label: c.Label, Kind: c.Meta.Kind, Meta: c.Meta, Started: time.Now(), Hallucinated: []string{}}
	if o.Arm != ArmRules {
		r.Model = o.Model
	}
	start := time.Now()
	res, err := diag.Run(ctx, diag.Input{Artifact: c.Artifact, Expected: c.Expected, Keys: c.Keys, Now: fixture.FixedNow})
	if err != nil {
		r.Error = "pipeline: " + err.Error()
		return r
	}
	if o.Arm == ArmRules {
		r.Output = rulesOutput(res)
		r.DurationMS = time.Since(start).Milliseconds()
		r.ValidCitations = len(r.Output.Evidence)
		return r
	}
	mode := agent.ModeToolsOff
	if o.Arm == ArmToolsOn {
		mode = agent.ModeToolsOn
	}
	ex, err := agent.Explain(ctx, o.Runner, agent.ExplainInput{
		Mode: mode, ArtifactPath: c.ArtifactPath(), Artifact: []byte(c.Artifact), Result: res,
		Symptom: c.Symptom, Expected: c.Expected, Keys: c.Keys, Model: o.Model, ServerBin: o.ServerBin,
	})
	if ex != nil && ex.Envelope != nil {
		env := ex.Envelope
		r.DurationMS, r.NumTurns, r.Usage, r.CostUSD, r.ModelUsage, r.Envelope = env.DurationMS, env.NumTurns, env.Usage, env.TotalCostUSD, env.ModelUsage, env.Raw
	}
	if err != nil {
		r.Error = err.Error()
		return r
	}
	d := ex.Diagnosis
	r.Output = &Output{RootCauseCode: d.RootCauseCode, Confidence: d.Confidence, Evidence: d.Evidence, Fix: d.Fix,
		PostureCodes: orEmpty(d.PostureCodes), Alternatives: d.Alternatives, Questions: orEmpty(d.Questions)}
	if r.Output.Alternatives == nil {
		r.Output.Alternatives = []agent.Alternative{}
	}
	r.ToolCalls, r.Hallucinated, r.ValidCitations = ex.ToolCalls, ex.Hallucinated, ex.ValidCitations
	return r
}

// rulesOutput projects the deterministic Report into the shared shape:
// top cause (or HEALTHY), its evidence, posture codes, the other fault
// codes as alternatives, and the skipped checks' needs as questions.
func rulesOutput(res *diag.Result) *Output {
	out := &Output{RootCauseCode: "HEALTHY", Confidence: 1, Evidence: []agent.Citation{}, PostureCodes: []string{}, Alternatives: []agent.Alternative{}, Questions: append([]string{}, res.Report.Needs...)}
	if res.TopCause != nil {
		out.RootCauseCode = string(res.TopCause.Code)
		out.Confidence = res.TopCause.Confidence
		out.Fix = res.TopCause.Fix
		for _, e := range res.TopCause.Evidence {
			out.Evidence = append(out.Evidence, agent.Citation{Path: e.Path, Actual: e.Actual, Expected: e.Expected, Note: e.Note})
		}
	} else {
		out.Fix = "No change needed: every applicable check passed."
	}
	seen := map[finding.Code]bool{}
	for _, f := range res.Report.Findings {
		switch {
		case f.Lane == finding.LanePosture:
			if !contains(out.PostureCodes, string(f.Code)) {
				out.PostureCodes = append(out.PostureCodes, string(f.Code))
			}
		case string(f.Code) != out.RootCauseCode && !seen[f.Code]:
			seen[f.Code] = true
			out.Alternatives = append(out.Alternatives, agent.Alternative{Code: string(f.Code), WhyNot: "ranked below the top cause (" + string(f.Severity) + ")"})
		}
	}
	return out
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ArmDir is where an arm's results live: <results>/<arm> for rules,
// <results>/<arm>-<model> otherwise, so two models never share a cache.
func ArmDir(results, arm, model string) string {
	if arm == ArmRules || model == "" {
		return filepath.Join(results, arm)
	}
	return filepath.Join(results, arm+"-"+model)
}

// LoadResults reads every result file in an arm dir, sorted by case ID.
func LoadResults(dir string) ([]*CaseResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*CaseResult
	for _, e := range entries {
		if e.IsDir() || e.Name() == "manifest.json" || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		r, err := readResult(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CaseID < out[j].CaseID })
	return out, nil
}

func readResult(path string) (*CaseResult, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r CaseResult
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &r, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func filterCases(cases []*Case, only []string) []*Case {
	if len(only) == 0 {
		return cases
	}
	want := map[string]bool{}
	for _, id := range only {
		want[id] = true
	}
	var out []*Case
	for _, c := range cases {
		if want[c.Meta.ID] {
			out = append(out, c)
		}
	}
	return out
}
