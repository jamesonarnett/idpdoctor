// SPDX-License-Identifier: Apache-2.0

//go:build live

package agent_test

import (
	"context"
	"testing"
	"time"

	"github.com/jamesonarnett/idpdoctor/internal/agent"
)

// TestLiveOneCall makes exactly one real `claude -p` call on the Max
// subscription. Opt in with: go test -tags live ./internal/agent -run Live -v
// It proves the flag set is accepted by the installed CLI and the envelope
// shape still parses; it is not part of `go test ./...`.
func TestLiveOneCall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	r := &agent.Runner{MaxBudgetUSD: 0.25}
	env, err := r.Run(ctx, agent.Request{
		SystemPrompt: "Answer with the structured object only.",
		Prompt:       "The deterministic validator found no faults in a SAML response whose Audience equals the SP entity ID. Report HEALTHY with confidence 1 and no evidence.",
		Schema:       agent.DiagnosisSchema(),
		MaxTurns:     1 + agent.StructuredOutputTurns,
	})
	if err != nil {
		t.Fatalf("live call failed: %v (envelope: %+v)", err, env)
	}
	d, err := agent.ParseDiagnosis(env.StructuredOutput)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("model usage: %+v cost(list)=%.4f turns=%d duration=%dms code=%s", env.ModelUsage, env.TotalCostUSD, env.NumTurns, env.DurationMS, d.RootCauseCode)
	if d.RootCauseCode != "HEALTHY" {
		t.Errorf("expected HEALTHY, got %s", d.RootCauseCode)
	}
	if len(env.ModelUsage) == 0 || env.DurationMS == 0 {
		t.Errorf("envelope lacks usage/duration: %+v", env)
	}
}
