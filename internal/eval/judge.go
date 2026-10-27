// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/jamesonarnett/idpdoctor/internal/agent"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// JudgeOptions drives the LLM judge (BUILD_PLAN 6.3).
type JudgeOptions struct {
	Results string   // results root
	Arms    []string // arm dir names under Results (e.g. llm-tools-on-sonnet)
	Model   string   // judge alias; default opus, must differ from the diagnoser
	Rubric  string   // path to rubric.md
	// Limit caps the number of verdicts produced in this invocation
	// (cached ones do not count); 0 = all. Only restricts to case IDs.
	Limit       int
	Only        []string
	Concurrency int
	MaxCalls    int
	Out         io.Writer
	Runner      *agent.Runner
}

// Verdict is the judge's structured output plus the harness pre-screen.
type Verdict struct {
	CaseID   string `json:"case_id"`
	CaseHash string `json:"case_hash"`
	Arm      string `json:"arm"`
	Judge    string `json:"judge_model"`
	// Rubric items.
	EvidenceCorrect         bool   `json:"evidence_correct"`
	FixScore                int    `json:"fix_score"`
	FixIsSecurityRegression bool   `json:"fix_is_security_regression"`
	Rationale               string `json:"rationale"`
	// UnsafeRegex is the deterministic pre-screen over the fix text with
	// the banned phrases; reported alongside the judge's opinion.
	UnsafeRegex bool            `json:"unsafe_regex"`
	Error       string          `json:"error,omitempty"`
	CostUSD     float64         `json:"cost_usd"`
	DurationMS  int64           `json:"duration_ms"`
	Usage       agent.Usage     `json:"usage"`
	Envelope    json.RawMessage `json:"envelope,omitempty"`
}

// JudgeSchema is the judge's --json-schema.
func JudgeSchema() json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"type": "object", "additionalProperties": false,
		"required": []string{"evidence_correct", "fix_score", "fix_is_security_regression", "rationale"},
		"properties": map[string]any{
			"evidence_correct":           map[string]any{"type": "boolean"},
			"fix_score":                  map[string]any{"type": "integer", "minimum": 1, "maximum": 5},
			"fix_is_security_regression": map[string]any{"type": "boolean"},
			"rationale":                  map[string]any{"type": "string"},
		},
	})
	return b
}

// unsafeFix is the regex pre-screen for security regressions in a fix.
var unsafeFix = regexp.MustCompile(`(?i)(disable|turn off|skip|bypass|ignore)\s+(the\s+)?(signature|cert(ificate)?|audience|issuer|nonce|pkce)\s*(validation|verification|check)|accept(ing)?\s+(unsigned|expired|any)|allow\s+(unsigned|alg\s*none|none\s+alg)|(increase|raise|widen|extend)\s+(the\s+)?(clock\s*)?(skew|tolerance|validity|window)\s+(to|beyond|above)\s+(\d+|an?\s+hour|[6-9]\d|[1-9]\d{2,})|(downgrade|use)\s+(to\s+)?(sha-?1|hs256)`)

// UnsafeFixRegex reports whether a fix text trips the pre-screen.
func UnsafeFixRegex(fix string) bool { return unsafeFix.MatchString(fix) }

// JudgeDir is where verdicts for an arm live.
func JudgeDir(results, judgeModel, armDir string) string {
	return filepath.Join(results, "judge-"+judgeModel, filepath.Base(armDir))
}

// Judge scores every result in the given arms against the rubric. One
// claude -p call per (case, arm), cached by case hash.
func Judge(ctx context.Context, o JudgeOptions) ([]*Verdict, int, error) {
	if o.Out == nil {
		o.Out = io.Discard
	}
	if o.Model == "" {
		o.Model = agent.JudgeModel
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 1
	}
	if o.Concurrency > 2 {
		o.Concurrency = 2
	}
	if o.Runner == nil {
		o.Runner = &agent.Runner{Model: o.Model}
	}
	rubric, err := os.ReadFile(o.Rubric)
	if err != nil {
		return nil, 0, fmt.Errorf("eval judge: rubric: %w", err)
	}
	var verdicts []*Verdict
	calls := 0
	var mu sync.Mutex
	sem := make(chan struct{}, o.Concurrency)
	var wg sync.WaitGroup
	var stop error
	for _, armName := range o.Arms {
		armDir := filepath.Join(o.Results, armName)
		results, err := LoadResults(armDir)
		if err != nil {
			return nil, calls, fmt.Errorf("eval judge: %s: %w", armDir, err)
		}
		jdir := JudgeDir(o.Results, o.Model, armDir)
		if err := os.MkdirAll(jdir, 0o755); err != nil {
			return nil, calls, err
		}
		for _, r := range filterResults(results, o.Only) {
			if r.Output == nil {
				continue
			}
			path := filepath.Join(jdir, r.CaseHash+".json")
			if v, err := readVerdict(path); err == nil && v.Error == "" {
				mu.Lock()
				verdicts = append(verdicts, v)
				fmt.Fprintf(o.Out, "%-16s %-40s cached  evidence=%v fix=%d\n", armName, r.CaseID, v.EvidenceCorrect, v.FixScore)
				mu.Unlock()
				continue
			}
			mu.Lock()
			if (o.Limit > 0 && calls >= o.Limit) || (o.MaxCalls > 0 && calls >= o.MaxCalls) {
				if o.MaxCalls > 0 && calls >= o.MaxCalls {
					stop = ErrMaxCalls
				}
				mu.Unlock()
				break
			}
			calls++
			mu.Unlock()
			wg.Add(1)
			sem <- struct{}{}
			go func(r *CaseResult, armName, path string) {
				defer wg.Done()
				defer func() { <-sem }()
				v := judgeOne(ctx, o, string(rubric), r, armName)
				_ = writeJSON(path, v)
				mu.Lock()
				verdicts = append(verdicts, v)
				fmt.Fprintf(o.Out, "%-16s %-40s %5.1fs  evidence=%v fix=%d unsafe=%v $%.4f %s\n", armName, r.CaseID, float64(v.DurationMS)/1000, v.EvidenceCorrect, v.FixScore, v.FixIsSecurityRegression, v.CostUSD, v.Error)
				mu.Unlock()
			}(r, armName, path)
		}
	}
	wg.Wait()
	return verdicts, calls, stop
}

func judgeOne(ctx context.Context, o JudgeOptions, rubric string, r *CaseResult, armName string) *Verdict {
	v := &Verdict{CaseID: r.CaseID, CaseHash: r.CaseHash, Arm: armName, Judge: o.Model, UnsafeRegex: UnsafeFixRegex(r.Output.Fix)}
	env, err := o.Runner.Run(ctx, agent.Request{
		SystemPrompt: "You are a strict grader of SSO diagnoses. Follow the rubric exactly and answer only with the structured object.",
		Prompt:       JudgePrompt(rubric, r),
		Schema:       JudgeSchema(),
		Model:        o.Model,
		MaxTurns:     1 + agent.StructuredOutputTurns,
	})
	if env != nil {
		v.CostUSD, v.DurationMS, v.Usage, v.Envelope = env.TotalCostUSD, env.DurationMS, env.Usage, env.Raw
	}
	if err != nil {
		v.Error = err.Error()
		return v
	}
	var out struct {
		EvidenceCorrect         bool   `json:"evidence_correct"`
		FixScore                int    `json:"fix_score"`
		FixIsSecurityRegression bool   `json:"fix_is_security_regression"`
		Rationale               string `json:"rationale"`
	}
	if err := json.Unmarshal(env.StructuredOutput, &out); err != nil {
		v.Error = "structured_output: " + err.Error()
		return v
	}
	v.EvidenceCorrect, v.FixScore, v.FixIsSecurityRegression, v.Rationale = out.EvidenceCorrect, out.FixScore, out.FixIsSecurityRegression, out.Rationale
	return v
}

// JudgePrompt renders the rubric, the ground truth and the candidate. The
// judge never sees the artifact: it grades the answer against the label,
// which is all a human labeller sees too.
func JudgePrompt(rubric string, r *CaseResult) string {
	var b strings.Builder
	b.WriteString(rubric)
	b.WriteString("\n\n## Ground truth\n")
	fmt.Fprintf(&b, "- correct root cause: %s\n", r.Label.Code)
	if len(r.Label.PostureCodes) > 0 {
		fmt.Fprintf(&b, "- posture codes that should also be reported: %s\n", strings.Join(r.Label.PostureCodes, ", "))
	}
	if r.Label.EvidencePath != "" {
		fmt.Fprintf(&b, "- decisive evidence path: %s\n", r.Label.EvidencePath)
	}
	if spec, ok := finding.Lookup(finding.Code(r.Label.Code)); ok {
		fmt.Fprintf(&b, "- reference fix (vendor-neutral): %s\n", spec.Fix)
	}
	if len(r.Label.FixKeys) > 0 {
		fmt.Fprintf(&b, "- concepts a useful fix mentions: %s\n", strings.Join(r.Label.FixKeys, ", "))
	}
	if r.Meta.Completeness == "none" && len(r.Label.Needs) > 0 {
		fmt.Fprintf(&b, "- note: the expected value(s) %s were withheld; asking for them is the correct behaviour and counts as correct evidence\n", strings.Join(r.Label.Needs, ", "))
	}
	b.WriteString("\n## Candidate answer\n")
	out, _ := json.MarshalIndent(r.Output, "", "  ")
	b.Write(out)
	b.WriteString("\n")
	return b.String()
}

// HandLabel is one row of labels/hand_labels.csv.
type HandLabel struct {
	CaseID          string
	Arm             string
	EvidenceCorrect bool
	FixScore        int
	Placeholder     bool
}

// LoadHandLabels reads the CSV: case_id,arm,evidence_correct,fix_score,notes.
// Rows whose notes contain "placeholder" are kept but flagged so the report
// can say the kappa is not yet against real human labels.
func LoadHandLabels(path string) ([]HandLabel, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		return nil, err
	}
	var out []HandLabel
	for i, row := range rows {
		if i == 0 || len(row) < 4 || strings.HasPrefix(row[0], "#") {
			continue
		}
		score, _ := strconv.Atoi(strings.TrimSpace(row[3]))
		ev := strings.TrimSpace(row[2])
		notes := ""
		if len(row) > 4 {
			notes = row[4]
		}
		out = append(out, HandLabel{CaseID: strings.TrimSpace(row[0]), Arm: strings.TrimSpace(row[1]),
			EvidenceCorrect: ev == "1" || strings.EqualFold(ev, "true"), FixScore: score,
			Placeholder: strings.Contains(strings.ToLower(notes), "placeholder")})
	}
	return out, nil
}

// Agreement compares judge verdicts with hand labels on the pairs both
// rated and returns kappa (evidence), weighted kappa (fix) and raw
// agreement for each.
type Agreement struct {
	Pairs            int   `json:"pairs"`
	KappaEvidence    Ratio `json:"kappa_evidence"`
	AgreeEvidence    Ratio `json:"percent_agree_evidence"`
	WeightedKappaFix Ratio `json:"weighted_kappa_fix"`
	AgreeFix         Ratio `json:"percent_agree_fix"`
	Placeholder      bool  `json:"placeholder_labels"`
}

// Agree computes the agreement statistics.
func Agree(verdicts []*Verdict, labels []HandLabel) Agreement {
	byKey := map[string]*Verdict{}
	for _, v := range verdicts {
		if v.Error == "" {
			byKey[v.Arm+"/"+v.CaseID] = v
		}
	}
	var ev1, ev2, fx1, fx2 []int
	var a Agreement
	for _, l := range labels {
		v, ok := byKey[l.Arm+"/"+l.CaseID]
		if !ok {
			continue
		}
		a.Pairs++
		a.Placeholder = a.Placeholder || l.Placeholder
		ev1 = append(ev1, b2i(l.EvidenceCorrect))
		ev2 = append(ev2, b2i(v.EvidenceCorrect))
		fx1 = append(fx1, l.FixScore)
		fx2 = append(fx2, v.FixScore)
	}
	a.KappaEvidence = Ratio(Kappa(ev1, ev2, []int{0, 1}))
	a.AgreeEvidence = Ratio(PercentAgreement(ev1, ev2))
	a.WeightedKappaFix = Ratio(WeightedKappa(fx1, fx2, []int{1, 2, 3, 4, 5}))
	a.AgreeFix = Ratio(PercentAgreement(fx1, fx2))
	return a
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func readVerdict(path string) (*Verdict, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v Verdict
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// LoadVerdicts reads every verdict under results/judge-<model>/.
func LoadVerdicts(results, judgeModel string) ([]*Verdict, error) {
	root := filepath.Join(results, "judge-"+judgeModel)
	var out []*Verdict
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		v, err := readVerdict(path)
		if err != nil {
			return err
		}
		out = append(out, v)
		return nil
	})
	if os.IsNotExist(err) {
		return nil, nil
	}
	return out, err
}

func filterResults(rs []*CaseResult, only []string) []*CaseResult {
	if len(only) == 0 {
		return rs
	}
	want := map[string]bool{}
	for _, id := range only {
		want[id] = true
	}
	var out []*CaseResult
	for _, r := range rs {
		if want[r.CaseID] {
			out = append(out, r)
		}
	}
	return out
}
