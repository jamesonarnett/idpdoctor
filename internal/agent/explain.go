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

	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
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
	Model    string
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
	// this result; ValidCitations counts the rest.
	Hallucinated   []string  `json:"hallucinated"`
	ValidCitations int       `json:"valid_citations"`
	Envelope       *Envelope `json:"envelope"`
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
	req := Request{SystemPrompt: SystemPrompt(in.Mode), Schema: DiagnosisSchema(), Model: model}
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
		req.Prompt = ToolsOnPrompt(redact.RefFor(data), kind, in.Symptom, in.Expected)
	case ModeToolsOff:
		req.MaxTurns = 1 + StructuredOutputTurns
		req.Prompt = ToolsOffPrompt(diag.RedactedText(in.Result, mcpserver.MaxToolOutput), kind, in.Symptom, in.Expected)
	default:
		return nil, fmt.Errorf("agent: unknown mode %q", in.Mode)
	}

	env, err := r.Run(ctx, req)
	if err != nil {
		return &Explanation{Mode: in.Mode, Model: model, Envelope: env, Prompt: req.Prompt, Hallucinated: []string{}}, err
	}
	d, err := ParseDiagnosis(env.StructuredOutput)
	if err != nil {
		return &Explanation{Mode: in.Mode, Model: model, Envelope: env, Prompt: req.Prompt, Hallucinated: []string{}}, err
	}
	out := &Explanation{Diagnosis: *d, Mode: in.Mode, Model: model, Envelope: env, Prompt: req.Prompt}
	out.ValidCitations, out.Hallucinated = CheckCitations(d.Evidence, diag.KnownPaths(in.Result))
	out.ToolCalls = countLines(trace)
	return out, nil
}

// CheckCitations splits cited paths into known and hallucinated. Paths are
// normalised first so "/Response/Assertion[1]/..." matches.
func CheckCitations(cites []Citation, known []string) (valid int, hallucinated []string) {
	set := make(map[string]bool, len(known))
	for _, k := range known {
		set[diag.NormalizePath(k)] = true
	}
	hallucinated = []string{}
	for _, c := range cites {
		if set[diag.NormalizePath(c.Path)] {
			valid++
		} else {
			hallucinated = append(hallucinated, c.Path)
		}
	}
	return valid, hallucinated
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
