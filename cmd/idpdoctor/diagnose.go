// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jamesonarnett/idpdoctor/internal/agent"
	"github.com/jamesonarnett/idpdoctor/internal/diag"
)

func newDiagnoseCmd() *cobra.Command {
	var in inputFlags
	var out outputFlags
	var ef expectedFlags
	var kind, symptom string
	var noLLM, explain bool
	var explainMode, model string
	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Sniff the artifact, run every check, print ranked findings with a top cause",
		Long: `diagnose is rules-only by default: deterministic validators produce every
finding and the ranking, and no model is involved.

--explain adds one headless Claude Code call (your Max subscription login,
never an API key) that ranks and narrates the same findings and must cite a
parsed field per claim. tools-on (default) hands the model an opaque handle
and idpdoctor's own MCP tools; the artifact never enters the transcript.
tools-off hands it the redacted structure and no tools. Either way the
validators' findings are printed first and are never overridden.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := in.read(cmd)
			if err != nil {
				return err
			}
			exp, keys, err := ef.resolve(cmd)
			if err != nil {
				return err
			}
			res, err := diag.Run(cmd.Context(), diag.Input{
				Artifact: raw, Kind: diag.Kind(kind), Symptom: symptom, Expected: exp, Keys: keys, Now: time.Now(),
			})
			if err != nil {
				return err
			}
			text := diag.Text(res.Report, res.TopCause)
			payload := map[string]any{
				"artifact_kind": res.Kind, "findings": res.Report.Findings, "top_cause": res.TopCause,
				"checks": res.Report.Checks, "needs": res.Report.Needs, "redaction": "default",
			}
			if explain && !noLLM {
				mode := agent.Mode(explainMode)
				if mode == agent.ModeToolsOn && (in.file == "" || in.file == "-") {
					return errors.New("--explain in tools-on mode needs the artifact in a file (-f): the MCP server reads it; use --explain-mode tools-off for stdin")
				}
				ex, err := agent.Explain(cmd.Context(), &agent.Runner{Model: model}, agent.ExplainInput{
					Mode: mode, ArtifactPath: in.file, Artifact: []byte(raw), Result: res, Symptom: symptom, Expected: exp,
				})
				if err != nil {
					// The deterministic result is still useful; print it, then the error.
					if werr := out.write(cmd, text, payload); werr != nil {
						return werr
					}
					return fmt.Errorf("explain: %w", err)
				}
				payload["explanation"] = ex
				text += explainText(ex)
			}
			if err := out.write(cmd, text, payload); err != nil {
				return err
			}
			if !res.Report.OK() {
				// Exit status 2 lets scripts tell "broken" from "ran fine".
				return exitError{code: 2}
			}
			return nil
		},
	}
	in.bind(cmd)
	out.bind(cmd)
	ef.bindSAML(cmd)
	ef.bindJWT(cmd)
	ef.bindOAuth(cmd)
	ef.bindClock(cmd)
	cmd.Flags().StringVar(&kind, "kind", "auto", "auto, saml_response, jwt, cert, oidc_discovery or oauth_redirect")
	cmd.Flags().StringVar(&symptom, "symptom", "", "the error you see (carried to the explain layer; validators ignore it)")
	cmd.Flags().BoolVar(&noLLM, "no-llm", false, "force rules-only even if --explain is given")
	cmd.Flags().BoolVar(&explain, "explain", false, "add one headless claude -p call that narrates the findings (subscription login only)")
	cmd.Flags().StringVar(&explainMode, "explain-mode", string(agent.ModeToolsOn), "tools-on (handle + MCP tools) or tools-off (redacted structure, no tools)")
	cmd.Flags().StringVar(&model, "model", agent.DefaultModel, "model alias passed to claude --model for --explain")
	return cmd
}

// explainText renders the model's answer under the deterministic report.
func explainText(ex *agent.Explanation) string {
	d := ex.Diagnosis
	var b strings.Builder
	fmt.Fprintf(&b, "\nExplained by %s (%s): %s, confidence %.2f\n", ex.Model, ex.Mode, d.RootCauseCode, d.Confidence)
	for _, e := range d.Evidence {
		fmt.Fprintf(&b, "  %s", e.Path)
		if e.Actual != "" {
			fmt.Fprintf(&b, "  actual=%q", e.Actual)
		}
		if e.Expected != "" {
			fmt.Fprintf(&b, "  expected=%q", e.Expected)
		}
		if e.Note != "" {
			fmt.Fprintf(&b, "  (%s)", e.Note)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "  fix: %s\n", d.Fix)
	if len(d.PostureCodes) > 0 {
		fmt.Fprintf(&b, "  posture: %s\n", strings.Join(d.PostureCodes, ", "))
	}
	for _, a := range d.Alternatives {
		fmt.Fprintf(&b, "  not %s: %s\n", a.Code, a.WhyNot)
	}
	for _, q := range d.Questions {
		fmt.Fprintf(&b, "  question: %s\n", q)
	}
	if len(ex.Hallucinated) > 0 {
		fmt.Fprintf(&b, "  WARNING: %d cited path(s) not present in the parsed artifact: %s\n", len(ex.Hallucinated), strings.Join(ex.Hallucinated, ", "))
	}
	if env := ex.Envelope; env != nil {
		fmt.Fprintf(&b, "  usage: %d in (+%d cached) / %d out tokens, %d turns, %d tool calls, %.1fs, list-price equivalent $%.4f\n",
			env.Usage.InputTokens, env.Usage.CacheCreationInputTokens+env.Usage.CacheReadInputTokens, env.Usage.OutputTokens,
			env.NumTurns, ex.ToolCalls, float64(env.DurationMS)/1000, env.TotalCostUSD)
	}
	return b.String()
}



// exitError carries a process exit code without printing anything.
type exitError struct{ code int }

func (e exitError) Error() string { return "" }
