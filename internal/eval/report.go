// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/agent"
)

// ReportOptions selects what to aggregate.
type ReportOptions struct {
	Results    string
	Dataset    string
	JudgeModel string
	Labels     string // hand_labels.csv; "" or missing = no kappa line
}

// ArmMetrics are the README numbers for one arm (BUILD_PLAN 6.2).
type ArmMetrics struct {
	Arm               string                    `json:"arm"`
	Model             string                    `json:"model,omitempty"`
	Cases             int                       `json:"cases"`
	Errors            int                       `json:"errors"`
	Accuracy          Ratio                     `json:"root_cause_accuracy"`
	Top2              Ratio                     `json:"top2_accuracy"`
	FPRate            Ratio                     `json:"false_positive_rate"`
	Controls          int                       `json:"controls"`
	PostureRecall     Ratio                     `json:"posture_recall"`
	PostureCases      int                       `json:"posture_cases"`
	Abstention        Ratio                     `json:"abstention_quality"`
	AbstentionCases   int                       `json:"abstention_cases"`
	HallucinationRate Ratio                     `json:"hallucinated_citation_rate"`
	NormalisedRate    Ratio                     `json:"normalised_citation_rate"`
	Citations         int                       `json:"citations"`
	EvidenceCorrect   Ratio                     `json:"evidence_correct"`
	FixScore          Ratio                     `json:"fix_score"`
	UnsafeFixRate     Ratio                     `json:"unsafe_fix_rate"`
	Judged            int                       `json:"judged"`
	P50MS             int64                     `json:"p50_ms"`
	P95MS             int64                     `json:"p95_ms"`
	ToolCallsPerCase  float64                   `json:"tool_calls_per_case"`
	InTokensPerCase   float64                   `json:"input_tokens_per_case"`
	CachedPerCase     float64                   `json:"cached_tokens_per_case"`
	OutTokensPerCase  float64                   `json:"output_tokens_per_case"`
	CostPerCase       float64                   `json:"list_price_usd_per_case"`
	CostTotal         float64                   `json:"list_price_usd_total"`
	Confusion         map[string]map[string]int `json:"confusion"` // label -> predicted -> n
}

// Report is everything the markdown renders; summary.json holds it too.
type Report struct {
	Dataset   string       `json:"dataset"`
	Cases     int          `json:"cases"`
	Arms      []ArmMetrics `json:"arms"`
	Judge     string       `json:"judge_model,omitempty"`
	Agreement *Agreement   `json:"agreement,omitempty"`
	Claude    string       `json:"claude_version,omitempty"`
}

// Build aggregates every arm dir under Results.
func Build(o ReportOptions) (*Report, error) {
	if o.JudgeModel == "" {
		o.JudgeModel = agent.JudgeModel
	}
	rep := &Report{Dataset: o.Dataset, Judge: o.JudgeModel}
	if cases, err := Load(o.Dataset); err == nil {
		rep.Cases = len(cases)
	}
	verdicts, err := LoadVerdicts(o.Results, o.JudgeModel)
	if err != nil {
		return nil, err
	}
	byArm := map[string]map[string]*Verdict{}
	for _, v := range verdicts {
		if byArm[v.Arm] == nil {
			byArm[v.Arm] = map[string]*Verdict{}
		}
		byArm[v.Arm][v.CaseID] = v
	}
	entries, err := os.ReadDir(o.Results)
	if err != nil {
		return nil, fmt.Errorf("eval report: %w", err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), "judge-") {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Slice(dirs, func(i, j int) bool { return armRank(dirs[i]) < armRank(dirs[j]) })
	for _, d := range dirs {
		results, err := LoadResults(filepath.Join(o.Results, d))
		if err != nil || len(results) == 0 {
			continue
		}
		m := metrics(d, results, byArm[d])
		if man, err := readManifest(filepath.Join(o.Results, d, "manifest.json")); err == nil {
			m.Model = man.Model
			if man.ClaudeVersion != "" {
				rep.Claude = man.ClaudeVersion
			}
		}
		rep.Arms = append(rep.Arms, m)
	}
	if o.Labels != "" {
		if labels, err := LoadHandLabels(o.Labels); err == nil && len(labels) > 0 {
			a := Agree(verdicts, labels)
			rep.Agreement = &a
		}
	}
	return rep, nil
}

func armRank(dir string) int {
	for i, a := range Arms {
		if strings.HasPrefix(dir, a) {
			return i
		}
	}
	return len(Arms)
}

func readManifest(path string) (Manifest, error) {
	var m Manifest
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	return m, unmarshal(b, &m)
}

// metrics computes one arm's numbers.
func metrics(arm string, rs []*CaseResult, verdicts map[string]*Verdict) ArmMetrics {
	m := ArmMetrics{Arm: arm, Cases: len(rs), Confusion: map[string]map[string]int{}}
	var correct, top2, controls, fp, posture, postureHit, abst, abstHit, cites, halluc, normalised, judged, evOK, unsafe int
	var fixSum float64
	var durations []int64
	var tools, in, cached, out, cost float64
	for _, r := range rs {
		if r.Error != "" || r.Output == nil {
			m.Errors++
			continue
		}
		pred := r.Output.RootCauseCode
		if m.Confusion[r.Label.Code] == nil {
			m.Confusion[r.Label.Code] = map[string]int{}
		}
		m.Confusion[r.Label.Code][pred]++
		if r.Correct() {
			correct++
		}
		if r.Top2() {
			top2++
		}
		if r.Label.Code == "HEALTHY" {
			controls++
			if pred != "HEALTHY" {
				fp++
			}
		}
		if len(r.Label.PostureCodes) > 0 {
			posture++
			if containsAll(r.Output.PostureCodes, r.Label.PostureCodes) {
				postureHit++
			}
		}
		if r.Meta.Completeness == "none" && len(r.Label.Needs) > 0 {
			abst++
			if asksFor(r.Output.Questions, r.Label.Needs) {
				abstHit++
			}
		}
		cites += len(r.Output.Evidence)
		halluc += len(r.Hallucinated)
		normalised += len(r.Normalised)
		durations = append(durations, r.DurationMS)
		tools += float64(r.ToolCalls)
		in += float64(r.Usage.InputTokens)
		cached += float64(r.Usage.CacheCreationInputTokens + r.Usage.CacheReadInputTokens)
		out += float64(r.Usage.OutputTokens)
		cost += r.CostUSD
		if v, ok := verdicts[r.CaseID]; ok && v.Error == "" {
			judged++
			if v.EvidenceCorrect {
				evOK++
			}
			fixSum += float64(v.FixScore)
			if v.FixIsSecurityRegression || v.UnsafeRegex {
				unsafe++
			}
		}
	}
	n := float64(len(rs) - m.Errors)
	m.Accuracy = ratio(correct, int(n))
	m.Top2 = ratio(top2, int(n))
	m.Controls, m.FPRate = controls, ratio(fp, controls)
	m.PostureCases, m.PostureRecall = posture, ratio(postureHit, posture)
	m.AbstentionCases, m.Abstention = abst, ratio(abstHit, abst)
	m.Citations, m.HallucinationRate, m.NormalisedRate = cites, ratio(halluc, cites), ratio(normalised, cites)
	m.Judged = judged
	m.EvidenceCorrect = ratio(evOK, judged)
	if judged > 0 {
		m.FixScore = Ratio(fixSum / float64(judged))
	} else {
		m.FixScore = Ratio(math.NaN())
	}
	m.UnsafeFixRate = ratio(unsafe, judged)
	m.P50MS, m.P95MS = percentile(durations, 0.50), percentile(durations, 0.95)
	if n > 0 {
		m.ToolCallsPerCase, m.InTokensPerCase, m.CachedPerCase, m.OutTokensPerCase, m.CostPerCase = tools/n, in/n, cached/n, out/n, cost/n
	}
	m.CostTotal = cost
	return m
}

// Ratio is a float that renders as null in JSON when undefined (NaN), so
// an arm with no controls or no judged cases still produces summary.json.
type Ratio float64

// MarshalJSON writes null for NaN.
func (r Ratio) MarshalJSON() ([]byte, error) {
	if math.IsNaN(float64(r)) {
		return []byte("null"), nil
	}
	return json.Marshal(float64(r))
}

// UnmarshalJSON reads null back as NaN.
func (r *Ratio) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*r = Ratio(math.NaN())
		return nil
	}
	var f float64
	if err := json.Unmarshal(b, &f); err != nil {
		return err
	}
	*r = Ratio(f)
	return nil
}

func ratio(a, b int) Ratio {
	if b == 0 {
		return Ratio(math.NaN())
	}
	return Ratio(float64(a) / float64(b))
}

func percentile(ds []int64, p float64) int64 {
	if len(ds) == 0 {
		return 0
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	i := int(math.Ceil(p*float64(len(ds)))) - 1
	if i < 0 {
		i = 0
	}
	return ds[i]
}

func containsAll(have, want []string) bool {
	for _, w := range want {
		if !contains(have, w) {
			return false
		}
	}
	return true
}

// asksFor reports whether any question names one of the needed fields.
func asksFor(questions, needs []string) bool {
	for _, q := range questions {
		for _, n := range needs {
			if strings.Contains(strings.ToLower(q), strings.ReplaceAll(n, "_", " ")) || strings.Contains(strings.ToLower(q), n) {
				return true
			}
		}
	}
	return false
}

// Markdown renders the README numbers table (exact shape of BUILD_PLAN
// 6.5), the extra rates, and a per-class confusion matrix per arm.
func (r *Report) Markdown() string {
	var b strings.Builder
	b.WriteString("| Arm | Root-cause acc. | Top-2 | FP rate (controls) | Evidence correct (judge) | Fix score (1-5) | p50 / p95 latency | Tool calls/case | Tokens/case (in / out) | List-price equiv./case |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|---|\n")
	for _, m := range r.Arms {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %.1fs / %.1fs | %.1f | %.0f / %.0f | $%.4f |\n",
			armLabel(m), pct(m.Accuracy), pct(m.Top2), pct(m.FPRate), judgePct(m.EvidenceCorrect, m.Judged), score(m.FixScore, m.Judged),
			float64(m.P50MS)/1000, float64(m.P95MS)/1000, m.ToolCallsPerCase, m.InTokensPerCase+m.CachedPerCase, m.OutTokensPerCase, m.CostPerCase)
	}
	fmt.Fprintf(&b, "\nDataset: %d cases, generated by `idpdoctor eval gen` (%s).\n", r.Cases, r.Dataset)
	if r.Agreement != nil && r.Agreement.Pairs > 0 {
		note := ""
		if r.Agreement.Placeholder {
			note = " (PLACEHOLDER labels written by the harness author, not yet hand-labelled)"
		}
		fmt.Fprintf(&b, "Judge: %s, calibrated on %d labelled pairs: kappa(evidence)=%s, weighted kappa(fix)=%s, raw agreement %s / %s%s.\n",
			r.Judge, r.Agreement.Pairs, f2(r.Agreement.KappaEvidence), f2(r.Agreement.WeightedKappaFix), pct(r.Agreement.AgreeEvidence), pct(r.Agreement.AgreeFix), note)
	} else {
		fmt.Fprintf(&b, "Judge: %s; no hand labels yet, so no kappa.\n", r.Judge)
	}
	if r.Claude != "" {
		fmt.Fprintf(&b, "Diagnoser via %s headless.\n", r.Claude)
	}
	b.WriteString("\n| Arm | Hallucinated citations | Normalised citations | Unsafe fixes (judge or regex) | Posture recall | Abstention quality | Errors |\n|---|---|---|---|---|---|---|\n")
	for _, m := range r.Arms {
		fmt.Fprintf(&b, "| %s | %s (%d cited) | %s | %s (%d judged) | %s (%d cases) | %s (%d cases) | %d |\n",
			armLabel(m), pct(m.HallucinationRate), m.Citations, pct(m.NormalisedRate), pct(m.UnsafeFixRate), m.Judged, pct(m.PostureRecall), m.PostureCases, pct(m.Abstention), m.AbstentionCases, m.Errors)
	}
	b.WriteString("\nHallucinated = cited path not on the artifact's allowed list after normalisation. Normalised = an exact check-name citation the harness mapped to its one canonical path; counted here, never as correct.\n")
	for _, m := range r.Arms {
		fmt.Fprintf(&b, "\n### Confusion matrix: %s\n\n", armLabel(m))
		b.WriteString(confusionTable(m.Confusion))
	}
	return b.String()
}

func armLabel(m ArmMetrics) string {
	switch {
	case strings.HasPrefix(m.Arm, ArmToolsOn):
		return "LLM, tools on (" + m.Model + ")"
	case strings.HasPrefix(m.Arm, ArmToolsOff):
		return "LLM, tools off (" + m.Model + ")"
	}
	return "rules-only"
}

func pct(v Ratio) string {
	if math.IsNaN(float64(v)) {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100*v)
}

func judgePct(v Ratio, judged int) string {
	if judged == 0 {
		return "n/a"
	}
	return pct(v)
}

func score(v Ratio, judged int) string {
	if judged == 0 || math.IsNaN(float64(v)) {
		return "n/a"
	}
	return fmt.Sprintf("%.1f", v)
}

func f2(v Ratio) string {
	if math.IsNaN(float64(v)) {
		return "n/a"
	}
	return fmt.Sprintf("%.2f", v)
}

// confusionTable renders label rows x predicted columns, codes shortened
// to keep the table readable.
func confusionTable(c map[string]map[string]int) string {
	labels := sortedKeys(c)
	predSet := map[string]bool{}
	for _, row := range c {
		for p := range row {
			predSet[p] = true
		}
	}
	preds := sortedKeys(predSet)
	var b strings.Builder
	b.WriteString("| label \\ predicted |")
	for _, p := range preds {
		b.WriteString(" " + short(p) + " |")
	}
	b.WriteString("\n|---|")
	for range preds {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	for _, l := range labels {
		fmt.Fprintf(&b, "| %s |", short(l))
		for _, p := range preds {
			n := c[l][p]
			cell := fmt.Sprintf(" %d |", n)
			if n == 0 {
				cell = " . |"
			} else if l == p {
				cell = fmt.Sprintf(" **%d** |", n)
			}
			b.WriteString(cell)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// short abbreviates a code for table cells: SAML_AUDIENCE_MISMATCH -> SAML_AUD_MIS.
func short(code string) string {
	parts := strings.Split(code, "_")
	if len(parts) <= 2 {
		return code
	}
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 4 {
			parts[i] = parts[i][:4]
		}
	}
	return strings.Join(parts, "_")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
