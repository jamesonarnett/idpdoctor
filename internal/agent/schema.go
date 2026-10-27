// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/json"
	"fmt"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// Verdict codes that are not catalog classes.
const (
	CodeHealthy = "HEALTHY"
	CodeUnknown = "UNKNOWN"
)

// Diagnosis is the model's structured answer (BUILD_PLAN 5.3). It mirrors
// finding.Finding closely on purpose: the deterministic report and the
// explained one are compared field by field in the eval.
type Diagnosis struct {
	RootCauseCode string        `json:"root_cause_code"`
	Confidence    float64       `json:"confidence"`
	Evidence      []Citation    `json:"evidence"`
	Fix           string        `json:"fix"`
	PostureCodes  []string      `json:"posture_codes,omitempty"`
	Alternatives  []Alternative `json:"alternatives,omitempty"`
	Questions     []string      `json:"questions,omitempty"`
}

// Citation is one piece of evidence the model points at. Path is required
// by the schema and must be one of the parsed paths; the harness rejects
// anything else as a hallucinated citation (R2).
type Citation struct {
	Path     string `json:"path"`
	Actual   string `json:"actual"`
	Expected string `json:"expected,omitempty"`
	Note     string `json:"note,omitempty"`
}

// Alternative is a runner-up the model considered and why it lost.
type Alternative struct {
	Code   string `json:"code"`
	WhyNot string `json:"why_not"`
}

// AllCodes is every value root_cause_code may take: the fault classes in
// catalog order, then HEALTHY and UNKNOWN. Posture codes are not root
// causes; they go in posture_codes.
func AllCodes() []string {
	var out []string
	for _, s := range finding.Catalog {
		if s.Lane == finding.LaneFault {
			out = append(out, string(s.Code))
		}
	}
	return append(out, CodeHealthy, CodeUnknown)
}

// PostureCodes is every posture-lane code.
func PostureCodes() []string {
	var out []string
	for _, s := range finding.Catalog {
		if s.Lane == finding.LanePosture {
			out = append(out, string(s.Code))
		}
	}
	return out
}

// DiagnosisSchema is the unconstrained --json-schema document: any string
// is accepted as an evidence path. Explain uses DiagnosisSchemaFor so the
// path is an enum of this artifact's allowed paths.
func DiagnosisSchema() json.RawMessage { return DiagnosisSchemaFor(nil) }

// DiagnosisSchemaFor is the --json-schema document, built from the catalog
// at runtime so adding a class to codes.go is enough. When allowedPaths is
// non-empty, evidence[].path becomes an enum of exactly those strings, so
// the CLI's structured-output enforcement rejects a check name or a
// paraphrased path before it ever reaches the harness (prompt v2).
func DiagnosisSchemaFor(allowedPaths []string) json.RawMessage {
	path := map[string]any{"type": "string", "description": "an allowed evidence path, copied verbatim from the list in the task; never a check name"}
	if len(allowedPaths) > 0 {
		path["enum"] = allowedPaths
	} else {
		path["description"] = "a path returned by a tool or present in the redacted artifact, e.g. /Response/Assertion/Conditions/AudienceRestriction/Audience"
	}
	schema := map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"root_cause_code", "confidence", "evidence", "fix"},
		"properties": map[string]any{
			"root_cause_code": map[string]any{"type": "string", "enum": AllCodes()},
			"confidence":      map[string]any{"type": "number", "minimum": 0, "maximum": 1},
			"evidence": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"required":             []string{"path", "actual"},
					"properties": map[string]any{
						"path":     path,
						"actual":   map[string]any{"type": "string"},
						"expected": map[string]any{"type": "string"},
						"note":     map[string]any{"type": "string"},
					},
				},
			},
			"fix":           map[string]any{"type": "string"},
			"posture_codes": map[string]any{"type": "array", "items": map[string]any{"type": "string", "enum": PostureCodes()}},
			"alternatives": map[string]any{
				"type": "array",
				"items": map[string]any{
					"type":                 "object",
					"additionalProperties": false,
					"required":             []string{"code", "why_not"},
					"properties": map[string]any{
						"code":    map[string]any{"type": "string"},
						"why_not": map[string]any{"type": "string"},
					},
				},
			},
			"questions": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		},
	}
	b, err := json.Marshal(schema)
	if err != nil {
		panic("agent: schema: " + err.Error())
	}
	return b
}

// ParseDiagnosis decodes structured_output and checks the code is one the
// schema allows (the CLI enforces the schema, but a fake or an older CLI
// might not).
func ParseDiagnosis(raw json.RawMessage) (*Diagnosis, error) {
	var d Diagnosis
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("agent: structured_output: %w", err)
	}
	if !contains(AllCodes(), d.RootCauseCode) {
		return nil, fmt.Errorf("agent: root_cause_code %q is not a catalog code", d.RootCauseCode)
	}
	if d.Evidence == nil {
		d.Evidence = []Citation{}
	}
	return &d, nil
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}
