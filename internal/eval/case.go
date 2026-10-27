// SPDX-License-Identifier: Apache-2.0

// Package eval is the benchmark harness (BUILD_PLAN 6): a generator that
// mints a labelled dataset from internal/fixture, a runner for the three
// arms (rules, llm-tools-off, llm-tools-on), an LLM judge with Cohen's
// kappa against hand labels, and a report that renders the README numbers
// table and per-class confusion matrices. Every model call goes through
// internal/agent; tests use the fake claude from agenttest.
package eval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/jwt"
)

// Case file names inside cases/<id>/.
const (
	FileArtifact = "artifact.txt"
	FileExpected = "expected.json"
	FileSymptom  = "symptom.txt"
	FileLabel    = "label.json"
	FileMeta     = "meta.json"
	// FileKeys is optional: JWT cases carry the OP's JWKS (public material).
	FileKeys = "keys.json"
)

// Label is the ground truth for one case (BUILD_PLAN 6.1).
type Label struct {
	// Code is the fault class, or HEALTHY for controls and posture fixtures.
	Code string `json:"code"`
	// PostureCodes are the posture findings a correct answer also reports.
	PostureCodes []string `json:"posture_codes"`
	// EvidencePath is the path the fixture mutator promised.
	EvidencePath string `json:"evidence_path,omitempty"`
	// FixKeys are 2-4 concepts a correct fix must mention; the judge reads
	// them as a rubric, nothing string-matches them.
	FixKeys []string `json:"fix_keys"`
	// Needs lists the expected fields the class depends on; when the case
	// withholds them (Completeness != full) the right answer is to ask.
	Needs []string `json:"needs,omitempty"`
}

// Meta describes how the case was generated.
type Meta struct {
	ID           string `json:"id"`
	Kind         string `json:"kind"`
	Dialect      string `json:"dialect,omitempty"`
	Mutator      string `json:"mutator,omitempty"`
	Completeness string `json:"expected_completeness"`  // full | partial | none
	SymptomFrom  string `json:"symptom_from,omitempty"` // template file or "misleading" / ""
	Misleading   bool   `json:"misleading_symptom,omitempty"`
	Seed         uint64 `json:"seed"`
	Index        int    `json:"index"`
	// Hash identifies the case content (artifact + expected + symptom) so
	// results can be cached and a regenerated identical case reuses them.
	Hash string `json:"hash"`
}

// Case is one dataset entry in memory.
type Case struct {
	Meta     Meta
	Label    Label
	Artifact string
	Expected expected.Expected
	Keys     jwt.Keys
	Symptom  string
	// Dir is where it was read from or written to.
	Dir string
}

// Hash computes the content hash: artifact, canonical expected JSON and
// symptom. Meta and label are excluded on purpose so a relabel does not
// invalidate cached model outputs.
func (c *Case) Hash() string {
	exp, _ := json.Marshal(c.Expected)
	keys, _ := json.Marshal(c.Keys)
	h := sha256.New()
	h.Write([]byte(c.Artifact))
	h.Write([]byte{0})
	h.Write(exp)
	h.Write([]byte{0})
	h.Write(keys)
	h.Write([]byte{0})
	h.Write([]byte(c.Symptom))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Write stores the case under dir/cases/<id>/.
func (c *Case) Write(root string) error {
	c.Meta.Hash = c.Hash()
	dir := filepath.Join(root, "cases", c.Meta.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	c.Dir = dir
	files := map[string][]byte{FileArtifact: []byte(c.Artifact), FileSymptom: []byte(c.Symptom)}
	for name, v := range map[string]any{FileExpected: c.Expected, FileLabel: c.Label, FileMeta: c.Meta} {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		files[name] = append(b, '\n')
	}
	if !c.Keys.Empty() {
		b, err := json.MarshalIndent(c.Keys, "", "  ")
		if err != nil {
			return err
		}
		files[FileKeys] = append(b, '\n')
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Load reads every case under root/cases, sorted by ID.
func Load(root string) ([]*Case, error) {
	entries, err := os.ReadDir(filepath.Join(root, "cases"))
	if err != nil {
		return nil, fmt.Errorf("eval: dataset %s: %w (run `idpdoctor eval gen` first)", root, err)
	}
	var cases []*Case
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		c, err := LoadCase(filepath.Join(root, "cases", e.Name()))
		if err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].Meta.ID < cases[j].Meta.ID })
	return cases, nil
}

// LoadCase reads one case directory.
func LoadCase(dir string) (*Case, error) {
	c := &Case{Dir: dir}
	art, err := os.ReadFile(filepath.Join(dir, FileArtifact))
	if err != nil {
		return nil, err
	}
	c.Artifact = string(art)
	sym, _ := os.ReadFile(filepath.Join(dir, FileSymptom))
	c.Symptom = string(sym)
	for name, v := range map[string]any{FileExpected: &c.Expected, FileLabel: &c.Label, FileMeta: &c.Meta} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, v); err != nil {
			return nil, fmt.Errorf("%s/%s: %w", dir, name, err)
		}
	}
	if b, err := os.ReadFile(filepath.Join(dir, FileKeys)); err == nil {
		if err := json.Unmarshal(b, &c.Keys); err != nil {
			return nil, fmt.Errorf("%s/%s: %w", dir, FileKeys, err)
		}
	}
	if c.Meta.Hash == "" {
		c.Meta.Hash = c.Hash()
	}
	return c, nil
}

// ArtifactPath is the on-disk artifact, which the tools-on arm preloads.
func (c *Case) ArtifactPath() string { return filepath.Join(c.Dir, FileArtifact) }

// IsControl reports whether the case is labelled HEALTHY (a control or a
// posture fixture).
func (c *Case) IsControl() bool { return c.Label.Code == "HEALTHY" }

// IsPosture reports whether the case is a validating artifact with an
// unsafe property.
func (c *Case) IsPosture() bool { return c.IsControl() && len(c.Label.PostureCodes) > 0 }

// String is the one-line form for tallies.
func (c *Case) String() string {
	return fmt.Sprintf("%s (%s)", c.Meta.ID, strings.TrimPrefix(c.Label.Code, ""))
}
