// SPDX-License-Identifier: Apache-2.0

package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jamesonarnett/idpdoctor/internal/agent"
	"github.com/jamesonarnett/idpdoctor/internal/agent/agenttest"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

func TestRunSuccessParsesEnvelopeAndScrubsEnv(t *testing.T) {
	rec := agenttest.Install(t, agenttest.ModeSuccess)
	// Plant the banned variables: the child must not see them.
	t.Setenv("ANTHROPIC_API_KEY", "sk-should-never-leak")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "tok-should-never-leak")

	r := &agent.Runner{}
	env, err := r.Run(context.Background(), agent.Request{
		SystemPrompt: "sys", Prompt: "hello prompt", Schema: agent.DiagnosisSchema(), MaxTurns: 8,
		MCPConfig: "/tmp/x.json", AllowedTools: []string{"mcp__idpdoctor__*"}, Env: map[string]string{"IDPDOCTOR_TRACE": "/tmp/t"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if env.TotalCostUSD != 0.0123 || env.NumTurns != 3 || env.DurationMS != 1234 || env.Usage.OutputTokens != 40 || env.Usage.TotalInputTokens() != 600 {
		t.Errorf("envelope fields: %+v", env)
	}
	if mu := env.ModelUsage["claude-sonnet-4-5"]; mu.CostBasis != "list" || mu.CostUSD != 0.0123 {
		t.Errorf("modelUsage: %+v", env.ModelUsage)
	}
	d, err := agent.ParseDiagnosis(env.StructuredOutput)
	if err != nil || d.RootCauseCode != "SAML_AUDIENCE_MISMATCH" || len(d.Evidence) != 2 {
		t.Fatalf("diagnosis: %+v %v", d, err)
	}

	got := agenttest.Record(t, rec)
	if got["KEY"] != "unset" || got["TOKEN"] != "unset" {
		t.Errorf("banned env reached the child: KEY=%q TOKEN=%q", got["KEY"], got["TOKEN"])
	}
	if !strings.Contains(got["STDIN"], "hello prompt") {
		t.Errorf("prompt must arrive on stdin, got %q", got["STDIN"])
	}
	if strings.Contains(got["ARGS"], "hello prompt") {
		t.Error("prompt must not be on the command line")
	}
	for _, want := range []string{"[-p]", "[--output-format] [json]", "[--model] [sonnet]", "[--tools] []", "[--setting-sources] []",
		"[--strict-mcp-config]", "[--no-session-persistence]", "[--permission-mode] [dontAsk]", "[--max-turns] [8]",
		"[--max-budget-usd] [1.00]", "[--system-prompt] [sys]", "[--json-schema]", "[--mcp-config] [/tmp/x.json]", "[--allowedTools] [mcp__idpdoctor__*]"} {
		if !strings.Contains(got["ARGS"], want) {
			t.Errorf("args missing %s in %s", want, got["ARGS"])
		}
	}
	if strings.Contains(got["CWD"], "idpdoctor/internal") {
		t.Errorf("child must run in an empty temp dir, not the repo: %s", got["CWD"])
	}
}

func TestRunFailureModes(t *testing.T) {
	cases := []struct {
		mode string
		want error
	}{
		{agenttest.ModeMalformed, agent.ErrMalformed},
		{agenttest.ModeDenial, agent.ErrDenied},
		{agenttest.ModeError, agent.ErrIsError},
		{agenttest.ModeNoStructured, agent.ErrNoStructured},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			agenttest.Install(t, c.mode)
			r := &agent.Runner{}
			env, err := r.Run(context.Background(), agent.Request{Prompt: "x", Schema: agent.DiagnosisSchema()})
			if !errors.Is(err, c.want) {
				t.Fatalf("want %v, got %v", c.want, err)
			}
			if c.mode != agenttest.ModeMalformed && env == nil {
				t.Error("envelope should be returned alongside the error when it parsed")
			}
			if c.mode == agenttest.ModeMalformed {
				var me *agent.MalformedError
				if !errors.As(err, &me) || !strings.Contains(me.Head, "/login") {
					t.Errorf("malformed error should carry the head of stdout: %v", err)
				}
			}
		})
	}
}

func TestRunTimeout(t *testing.T) {
	agenttest.Install(t, agenttest.ModeTimeout)
	r := &agent.Runner{Timeout: 300 * time.Millisecond}
	start := time.Now()
	_, err := r.Run(context.Background(), agent.Request{Prompt: "x"})
	if !errors.Is(err, agent.ErrTimeout) {
		t.Fatalf("want ErrTimeout, got %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("timeout did not kill the child promptly")
	}
}

func TestRunNotFound(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := (&agent.Runner{}).Run(context.Background(), agent.Request{Prompt: "x"})
	if !errors.Is(err, agent.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestScrubEnv(t *testing.T) {
	in := []string{"PATH=/bin", "ANTHROPIC_API_KEY=x", "ANTHROPIC_AUTH_TOKEN=y", "CLAUDE_CODE_USE_BEDROCK=1", "HOME=/h", "CLAUDECODE=1"}
	out := agent.ScrubEnv(in, map[string]string{"IDPDOCTOR_TRACE": "/t", "HOME": "/other"})
	joined := strings.Join(out, "\n")
	for _, banned := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK", "CLAUDECODE"} {
		if strings.Contains(joined, banned) {
			t.Errorf("%s survived scrubbing: %v", banned, out)
		}
	}
	if !strings.Contains(joined, "PATH=/bin") || !strings.Contains(joined, "IDPDOCTOR_TRACE=/t") || !strings.Contains(joined, "HOME=/other") || strings.Contains(joined, "HOME=/h") {
		t.Errorf("scrubbed env wrong: %v", out)
	}
}

func TestDiagnosisSchemaCoversCatalog(t *testing.T) {
	var schema map[string]any
	if err := json.Unmarshal(agent.DiagnosisSchema(), &schema); err != nil {
		t.Fatal(err)
	}
	props := schema["properties"].(map[string]any)
	enum := props["root_cause_code"].(map[string]any)["enum"].([]any)
	seen := map[string]bool{}
	for _, e := range enum {
		seen[e.(string)] = true
	}
	for _, s := range finding.Catalog {
		if s.Lane == finding.LaneFault && !seen[string(s.Code)] {
			t.Errorf("schema enum missing %s", s.Code)
		}
		if s.Lane == finding.LanePosture && seen[string(s.Code)] {
			t.Errorf("posture code %s must not be a root cause", s.Code)
		}
	}
	if !seen["HEALTHY"] || !seen["UNKNOWN"] {
		t.Error("schema must allow HEALTHY and UNKNOWN")
	}
	ev := props["evidence"].(map[string]any)["items"].(map[string]any)
	req := ev["required"].([]any)
	if len(req) < 1 || req[0] != "path" {
		t.Errorf("evidence items must require path: %v", req)
	}
	if _, err := agent.ParseDiagnosis(json.RawMessage(`{"root_cause_code":"NOT_A_CODE","confidence":1,"evidence":[],"fix":""}`)); err == nil {
		t.Error("unknown code must be rejected")
	}
}
