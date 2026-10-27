// SPDX-License-Identifier: Apache-2.0

// Package finding defines the output vocabulary shared by every validator,
// the CLI and the MCP server: Finding, Evidence, Check and Report, plus the
// failure-class catalog in codes.go (the single source of truth that
// go generate renders into docs/TAXONOMY.md).
package finding

import (
	"sort"
)

// Severity orders findings. "error" means the artifact will be rejected by a
// correct SP; "warn" means it may be accepted but something is off; "info" is
// context the caller may want.
type Severity string

const (
	SeverityError Severity = "error"
	SeverityWarn  Severity = "warn"
	SeverityInfo  Severity = "info"
)

// rank gives severities a numeric order for sorting. Unknown values sort last.
func (s Severity) rank() int {
	switch s {
	case SeverityError:
		return 0
	case SeverityWarn:
		return 1
	case SeverityInfo:
		return 2
	}
	return 3
}

// Lane separates "it is broken" from "it works but is unsafe" (LANDSCAPE R4).
type Lane string

const (
	LaneFault   Lane = "fault"
	LanePosture Lane = "posture"
)

// Code is a catalog constant such as SAML_AUDIENCE_MISMATCH. Codes are
// declared in codes.go; validators never invent new ones at runtime.
type Code string

// Evidence points at the parsed field a finding is about. Path is a stable,
// namespace-free element path (e.g. /Response/Assertion/Conditions/
// AudienceRestriction/Audience) so an LLM can cite it and a harness can
// check the citation against the parsed Summary. Values are already redacted
// by the time they land here.
type Evidence struct {
	Path     string `json:"path"`
	Actual   string `json:"actual,omitempty"`
	Expected string `json:"expected,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Finding is one diagnosed problem. Title and Fix default from the catalog
// entry for Code; validators override them only to add specifics.
type Finding struct {
	Code       Code       `json:"code"`
	Lane       Lane       `json:"lane"`
	Severity   Severity   `json:"severity"`
	Title      string     `json:"title"`
	Evidence   []Evidence `json:"evidence"`
	Fix        string     `json:"fix"`
	Confidence float64    `json:"confidence"`
	Source     string     `json:"source"`
	Refs       []string   `json:"refs,omitempty"`
}

// CheckStatus is the outcome of one named check.
type CheckStatus string

const (
	CheckPass CheckStatus = "pass"
	CheckFail CheckStatus = "fail"
	CheckWarn CheckStatus = "warn"
	// CheckSkip means the check could not run because the caller did not
	// supply the expected value; Needs names what to supply.
	CheckSkip CheckStatus = "skip"
)

// Check reports every validation that ran (or could not), so a caller can
// see passes as well as failures and knows what to ask the human for.
type Check struct {
	Name   string      `json:"name"`
	Status CheckStatus `json:"status"`
	Detail string      `json:"detail,omitempty"`
	Needs  string      `json:"needs,omitempty"`
}

// Report is the deterministic pipeline's output and what the diagnose tool
// returns. Redaction is always "default": it documents a property of the
// output, not a setting the caller controls.
type Report struct {
	ArtifactKind string    `json:"artifact_kind"`
	Findings     []Finding `json:"findings"`
	Checks       []Check   `json:"checks"`
	Needs        []string  `json:"needs"`
	Redaction    string    `json:"redaction"`
}

// New builds a Finding from the catalog entry for code, filling Lane,
// Severity, Title, Fix and Refs. Confidence defaults to 1.0 and Source to
// "validator"; callers adjust for heuristics. Unknown codes panic because
// that is a programming error, not a runtime condition.
func New(code Code, evidence ...Evidence) Finding {
	spec, ok := Lookup(code)
	if !ok {
		panic("finding: unknown code " + string(code))
	}
	if evidence == nil {
		evidence = []Evidence{}
	}
	return Finding{
		Code:       code,
		Lane:       spec.Lane,
		Severity:   spec.Severity,
		Title:      spec.Title,
		Evidence:   evidence,
		Fix:        spec.Fix,
		Confidence: 1.0,
		Source:     "validator",
		Refs:       spec.Refs,
	}
}

// Sort orders findings in place: fault lane before posture, severity desc,
// confidence desc, then catalog order (earlier classes are more common root
// causes). It is stable so validators' own ordering breaks remaining ties.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Lane != b.Lane {
			return a.Lane == LaneFault
		}
		if a.Severity != b.Severity {
			return a.Severity.rank() < b.Severity.rank()
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		return prior(a.Code) < prior(b.Code)
	})
}

// prior is a code's index in the catalog; unknown codes sort after all known.
func prior(c Code) int {
	for i, s := range Catalog {
		if s.Code == c {
			return i
		}
	}
	return len(Catalog)
}

// Lookup returns the catalog entry for a code.
func Lookup(c Code) (Spec, bool) {
	for _, s := range Catalog {
		if s.Code == c {
			return s, true
		}
	}
	return Spec{}, false
}

// NewReport returns a Report with non-nil slices so JSON renders [] not null.
func NewReport(kind string) *Report {
	return &Report{
		ArtifactKind: kind,
		Findings:     []Finding{},
		Checks:       []Check{},
		Needs:        []string{},
		Redaction:    "default",
	}
}

// Add appends a finding to the report.
func (r *Report) Add(f Finding) { r.Findings = append(r.Findings, f) }

// AddCheck appends a check and, if it was skipped, records what it needs.
func (r *Report) AddCheck(c Check) {
	r.Checks = append(r.Checks, c)
	if c.Status == CheckSkip && c.Needs != "" {
		for _, n := range r.Needs {
			if n == c.Needs {
				return
			}
		}
		r.Needs = append(r.Needs, c.Needs)
	}
}

// OK reports whether no fault-lane finding has severity error.
func (r *Report) OK() bool {
	for _, f := range r.Findings {
		if f.Lane == LaneFault && f.Severity == SeverityError {
			return false
		}
	}
	return true
}
