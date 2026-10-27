// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/jwt"
	"github.com/jamesonarnett/idpdoctor/internal/mcpserver"
	"github.com/jamesonarnett/idpdoctor/internal/redact"
)

// ErrNeedArtifactPath: tools-on mode starts an MCP server that preloads the
// artifact from disk, so it needs a file, not bytes.
var ErrNeedArtifactPath = errors.New("agent: tools-on mode needs ArtifactPath")

// ExplainInput is everything one explain call needs. Result is the
// deterministic pipeline's output, computed by the caller first: the
// explain layer never replaces the validators, it narrates them (R2).
type ExplainInput struct {
	Mode Mode
	// ArtifactPath is the capture on disk; required in tools-on mode (the
	// MCP server reads it) and used to derive the handle.
	ArtifactPath string
	// Artifact is the raw bytes; used only to derive the handle when
	// ArtifactPath is empty, and never placed in a prompt.
	Artifact []byte
	Result   *diag.Result
	Symptom  string
	Expected expected.Expected
	// Keys is the OP's public verification material (JWKS / PEM) for a JWT;
	// public, so it goes in the prompt in clear.
	Keys  jwt.Keys
	Model string
	// ServerBin is the idpdoctor executable the MCP server runs as; ""
	// means os.Executable().
	ServerBin string
	// TracePath receives one JSON line per tool call; "" means a temp file
	// that is read for the count and discarded.
	TracePath string
}

// Explanation is the parsed answer plus the facts the eval reports.
type Explanation struct {
	Diagnosis Diagnosis `json:"diagnosis"`
	Mode      Mode      `json:"mode"`
	Model     string    `json:"model"`
	// ToolCalls counts lines in the trace file (tools-on) and is 0 otherwise.
	ToolCalls int `json:"tool_calls"`
	// Hallucinated lists cited paths that are not in diag.KnownPaths for
	// this result even after normalisation; ValidCitations counts the paths
	// cited verbatim. Normalised lists check-name citations the harness
	// mapped to their canonical path (diag.CheckPaths); they are counted
	// separately, never as valid, and the Diagnosis carries the mapped path.
	Hallucinated   []string     `json:"hallucinated"`
	ValidCitations int          `json:"valid_citations"`
	Normalised     []Normalised `json:"normalised"`
	Envelope       *Envelope    `json:"envelope"`
	// Prompt is kept so tests (and the eval cache) can prove no raw value
	// ever reached the model.
	Prompt string `json:"-"`
}

// Explain runs one headless call in the given mode. The tools-on arm
// writes a throw-away --mcp-config pointing at `idpdoctor mcp --preload
// <file>` in an empty temp dir; the file holds a path, never the artifact.
func Explain(ctx context.Context, r *Runner, in ExplainInput) (*Explanation, error) {
	if in.Result == nil {
		return nil, errors.New("agent: ExplainInput.Result is required")
	}
	model := in.Model
	if model == "" {
		model = r.model()
	}
	kind := string(in.Result.Kind)
	allowed := NewAllowed(in.Result)
	req := Request{SystemPrompt: SystemPrompt(in.Mode), Schema: DiagnosisSchemaFor(allowed.Paths), Model: model}
	tmp, err := os.MkdirTemp("", "idpdoctor-explain-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	trace := in.TracePath
	if trace == "" {
		trace = filepath.Join(tmp, "trace.jsonl")
	}

	switch in.Mode {
	case ModeToolsOn:
		if in.ArtifactPath == "" {
			return nil, ErrNeedArtifactPath
		}
		data, err := os.ReadFile(in.ArtifactPath)
		if err != nil {
			return nil, err
		}
		cfg, err := writeMCPConfig(tmp, in.ServerBin, in.ArtifactPath, trace)
		if err != nil {
			return nil, err
		}
		req.MCPConfig = cfg
		req.AllowedTools = []string{"mcp__idpdoctor__*"}
		req.MaxTurns = ToolsOnPlannedCalls + StructuredOutputTurns
		req.Env = map[string]string{"IDPDOCTOR_TRACE": trace}
		req.Prompt = ToolsOnPrompt(redact.RefFor(data), kind, in.Symptom, in.Expected, in.Keys, allowed)
	case ModeToolsOff:
		req.MaxTurns = 1 + StructuredOutputTurns
		req.Prompt = ToolsOffPrompt(diag.RedactedText(in.Result, mcpserver.MaxToolOutput), kind, in.Symptom, in.Expected, in.Keys, allowed)
	default:
		return nil, fmt.Errorf("agent: unknown mode %q", in.Mode)
	}

	env, err := r.Run(ctx, req)
	if err != nil {
		return &Explanation{Mode: in.Mode, Model: model, Envelope: env, Prompt: req.Prompt, Hallucinated: []string{}, Normalised: []Normalised{}}, err
	}
	d, err := ParseDiagnosis(env.StructuredOutput)
	if err != nil {
		return &Explanation{Mode: in.Mode, Model: model, Envelope: env, Prompt: req.Prompt, Hallucinated: []string{}, Normalised: []Normalised{}}, err
	}
	out := &Explanation{Diagnosis: *d, Mode: in.Mode, Model: model, Envelope: env, Prompt: req.Prompt}
	out.ValidCitations, out.Normalised, out.Hallucinated = ClassifyCitations(out.Diagnosis.Evidence, allowed.Paths, diag.CheckPaths(in.Result))
	out.ToolCalls = countLines(trace)
	return out, nil
}

// Normalised records one check-name citation the harness rewrote.
type Normalised struct {
	Cited string `json:"cited"` // what the model wrote, e.g. "checks/audience"
	Path  string `json:"path"`  // the canonical evidence path it was mapped to
}

// CheckCitations splits cited paths into known and hallucinated with no
// check-name normalisation. Paths are canonicalised first so
// "/Response/Assertion[1]/..." matches.
func CheckCitations(cites []Citation, known []string) (valid int, hallucinated []string) {
	valid, _, hallucinated = ClassifyCitations(cites, known, nil)
	return valid, hallucinated
}

// ClassifyCitations sorts every citation into exactly one of three bins,
// in this order:
//
//  1. valid: the path, after diag.NormalizePath, is on the allowed list;
//  2. normalised: the path is an exact check-name citation ("audience",
//     "checks/audience", "/checks/audience") and checkPaths maps that name
//     unambiguously; the citation's Path is rewritten in place to the
//     canonical path and the pair is recorded;
//  3. hallucinated: everything else, including check names checkPaths
//     declines to map.
//
// Normalised citations are never counted as valid: the metric stays
// strict, the rewrite only makes the rendered diagnosis point somewhere
// real.
func ClassifyCitations(cites []Citation, allowed []string, checkPaths map[string]string) (valid int, normalised []Normalised, hallucinated []string) {
	set := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		set[diag.NormalizePath(k)] = true
	}
	normalised, hallucinated = []Normalised{}, []string{}
	for i := range cites {
		c := &cites[i]
		if set[diag.NormalizePath(c.Path)] {
			valid++
			continue
		}
		if name, ok := checkNameCitation(c.Path); ok {
			if p, ok := checkPaths[name]; ok && set[diag.NormalizePath(p)] {
				normalised = append(normalised, Normalised{Cited: c.Path, Path: p})
				c.Path = p
				continue
			}
		}
		hallucinated = append(hallucinated, c.Path)
	}
	return valid, normalised, hallucinated
}

// checkNameRe is the shape of a validator check name (finding.Check.Name).
var checkNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// checkNameCitation recognises the exact ways a model writes a check name
// where a path belongs: the bare name, or the name under a "checks" (or
// "check") prefix with "/" or ".", with or without a leading slash. Any
// other shape is not a check-name citation.
func checkNameCitation(p string) (string, bool) {
	s := strings.TrimSpace(p)
	s = strings.TrimPrefix(s, "/")
	for _, prefix := range []string{"checks/", "check/", "checks.", "check."} {
		if strings.HasPrefix(s, prefix) {
			s = strings.TrimPrefix(s, prefix)
			break
		}
	}
	if !checkNameRe.MatchString(s) {
		return "", false
	}
	return s, true
}

// writeMCPConfig writes the --mcp-config file. Only the path of the
// artifact goes in; the server reads it itself.
func writeMCPConfig(dir, bin, artifactPath, trace string) (string, error) {
	if bin == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		bin = exe
	}
	abs, err := filepath.Abs(artifactPath)
	if err != nil {
		return "", err
	}
	cfg := map[string]any{"mcpServers": map[string]any{"idpdoctor": map[string]any{
		"command": bin,
		"args":    []string{"mcp", "--preload", abs},
		"env":     map[string]string{"IDPDOCTOR_TRACE": trace},
	}}}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	p := filepath.Join(dir, "mcp.json")
	return p, os.WriteFile(p, b, 0o600)
}

// countLines counts trace records; a missing file is zero calls.
func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if len(sc.Bytes()) > 0 {
			n++
		}
	}
	return n
}
