// SPDX-License-Identifier: Apache-2.0

// Package agent runs the Claude Code CLI headlessly (`claude -p`) from Go
// and turns its JSON envelope into a typed Diagnosis. It is the only place
// in the tree that talks to a model. Design rules (BUILD_PLAN 5.2):
//
//   - subscription only: ANTHROPIC_API_KEY and ANTHROPIC_AUTH_TOKEN are
//     removed from the child's environment, so the CLI can only use the
//     /login OAuth credentials and nothing can route to API billing;
//   - no built-in tools (--tools ""), no project settings
//     (--setting-sources "", --strict-mcp-config, empty working directory),
//     no session files (--no-session-persistence);
//   - structured output via --json-schema, bounded by --max-turns and a
//     belt-and-braces --max-budget-usd;
//   - the raw artifact never enters a prompt: tools-on passes a handle,
//     tools-off passes the redacted structure.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Defaults.
const (
	DefaultModel     = "sonnet" // the diagnoser; the judge uses JudgeModel
	JudgeModel       = "opus"
	DefaultBudgetUSD = 1.00
	DefaultTimeout   = 5 * time.Minute
	// StructuredOutputTurns is what --json-schema costs on top of the tool
	// calls: verified locally, a one-turn run reported num_turns 2.
	StructuredOutputTurns = 2
)

// Errors a caller can test with errors.Is / errors.As.
var (
	ErrNotFound     = errors.New("agent: claude CLI not found on PATH")
	ErrMalformed    = errors.New("agent: claude did not print a JSON envelope")
	ErrTimeout      = errors.New("agent: claude timed out")
	ErrDenied       = errors.New("agent: claude reported permission denials")
	ErrIsError      = errors.New("agent: claude reported is_error")
	ErrNoStructured = errors.New("agent: envelope has no structured_output")
)

// MalformedError carries the first bytes of stdout so the human can see
// what the CLI printed instead of JSON (login prompt, update notice...).
type MalformedError struct {
	Head string
	Err  error
}

func (e *MalformedError) Error() string { return fmt.Sprintf("%v: %q", ErrMalformed, e.Head) }
func (e *MalformedError) Unwrap() error { return ErrMalformed }

// scrubbedEnv lists variables that must never reach the child. The first
// two are the billing rule; the CLAUDE_CODE_USE_* trio would route to a
// cloud provider; ANTHROPIC_BASE_URL could redirect traffic; CLAUDECODE is
// the "already inside Claude Code" marker a nested headless run should not
// inherit.
var scrubbedEnv = []string{
	"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
	"CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
	"CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT",
}

// Runner holds the per-process configuration for invoking the CLI.
type Runner struct {
	// Bin is the executable; "" means look up "claude" on PATH at call time
	// (tests put a fake script first on PATH).
	Bin string
	// Model is the default --model when a Request does not name one.
	Model string
	// MaxBudgetUSD is the --max-budget-usd cap. It is the CLI's own
	// client-side estimate guard, never a billing instrument.
	MaxBudgetUSD float64
	// Timeout bounds one invocation when the caller's context has no
	// deadline of its own.
	Timeout time.Duration
	// Env is the base environment; nil means os.Environ(). Scrubbing is
	// applied on top of it either way.
	Env []string
	// WorkDir is the child's working directory; "" means a fresh empty temp
	// dir per call so no CLAUDE.md or .mcp.json can be picked up.
	WorkDir string
}

// Request is one headless call.
type Request struct {
	SystemPrompt string
	Prompt       string          // sent on stdin, never on the command line
	Schema       json.RawMessage // --json-schema; nil means free text
	Model        string
	// MaxTurns should be the planned tool calls + StructuredOutputTurns.
	MaxTurns int
	// MCPConfig is the path of a --mcp-config file; "" means tools-off.
	MCPConfig string
	// AllowedTools are --allowedTools patterns (e.g. mcp__idpdoctor__*).
	AllowedTools []string
	// Env adds variables for the child (and so for its MCP servers).
	Env map[string]string
}

// Args renders the command line for req (exported so tests and the README
// can show exactly what runs). The prompt is not in it.
func (r *Runner) Args(req Request) []string {
	model := req.Model
	if model == "" {
		model = r.model()
	}
	turns := req.MaxTurns
	if turns <= 0 {
		turns = StructuredOutputTurns
	}
	args := []string{
		"-p",
		"--output-format", "json",
		"--model", model,
		"--tools", "",
		"--setting-sources", "",
		"--strict-mcp-config",
		"--no-session-persistence",
		"--permission-mode", "dontAsk",
		"--max-turns", strconv.Itoa(turns),
		"--max-budget-usd", strconv.FormatFloat(r.budget(), 'f', 2, 64),
	}
	if req.SystemPrompt != "" {
		args = append(args, "--system-prompt", req.SystemPrompt)
	}
	if req.Schema != nil {
		args = append(args, "--json-schema", string(req.Schema))
	}
	if req.MCPConfig != "" {
		args = append(args, "--mcp-config", req.MCPConfig)
		for _, t := range req.AllowedTools {
			args = append(args, "--allowedTools", t)
		}
	}
	return args
}

func (r *Runner) model() string {
	if r.Model != "" {
		return r.Model
	}
	return DefaultModel
}

func (r *Runner) budget() float64 {
	if r.MaxBudgetUSD > 0 {
		return r.MaxBudgetUSD
	}
	return DefaultBudgetUSD
}

// ScrubEnv returns base without the scrubbed variables plus extra. It is
// exported so the eval harness can assert the property in its own tests.
func ScrubEnv(base []string, extra map[string]string) []string {
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if isScrubbed(name) {
			continue
		}
		if _, override := extra[name]; override {
			continue
		}
		out = append(out, kv)
	}
	for k, v := range extra {
		out = append(out, k+"="+v)
	}
	return out
}

func isScrubbed(name string) bool {
	for _, s := range scrubbedEnv {
		if s == name {
			return true
		}
	}
	return false
}

// Run executes one headless call and returns the parsed envelope. It
// returns an error for anything that makes the run unusable: no CLI,
// timeout, non-JSON output, is_error, permission denials, or (when a
// schema was given) a missing structured_output. The envelope is returned
// alongside the error whenever one was parsed, so callers can log usage.
func (r *Runner) Run(ctx context.Context, req Request) (*Envelope, error) {
	bin := r.Bin
	if bin == "" {
		p, err := exec.LookPath("claude")
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotFound, err)
		}
		bin = p
	}
	if _, has := ctx.Deadline(); !has {
		timeout := r.Timeout
		if timeout <= 0 {
			timeout = DefaultTimeout
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	dir := r.WorkDir
	if dir == "" {
		tmp, err := os.MkdirTemp("", "idpdoctor-agent-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(tmp)
		dir = tmp
	}

	base := r.Env
	if base == nil {
		base = os.Environ()
	}
	cmd := exec.CommandContext(ctx, bin, r.Args(req)...)
	cmd.Dir = dir
	cmd.Env = ScrubEnv(base, req.Env)
	cmd.Stdin = strings.NewReader(req.Prompt)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Give the CLI a moment to flush after SIGKILL on timeout, then stop
	// waiting on its pipes; otherwise an MCP child holding stdout open
	// would hang Wait forever.
	cmd.WaitDelay = 2 * time.Second

	runErr := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%w after %s", ErrTimeout, r.Timeout)
	}
	env, perr := parseEnvelope(stdout.Bytes())
	if perr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("%w (exit: %v, stderr: %s)", perr, runErr, head(stderr.Bytes(), 200))
		}
		return nil, perr
	}
	switch {
	case len(env.PermissionDenials) > 0:
		return env, fmt.Errorf("%w: %d (first: %s)", ErrDenied, len(env.PermissionDenials), env.PermissionDenials[0].ToolName)
	case env.IsError:
		return env, fmt.Errorf("%w: %s: %s", ErrIsError, env.Subtype, head([]byte(env.Result), 200))
	case req.Schema != nil && (len(env.StructuredOutput) == 0 || string(env.StructuredOutput) == "null"):
		return env, fmt.Errorf("%w (subtype %s)", ErrNoStructured, env.Subtype)
	}
	return env, nil
}
