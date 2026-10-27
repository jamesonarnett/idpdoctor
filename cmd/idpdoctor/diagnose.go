// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/jamesonarnett/idpdoctor/internal/diag"
)

func newDiagnoseCmd() *cobra.Command {
	var in inputFlags
	var out outputFlags
	var ef expectedFlags
	var kind, symptom string
	var noLLM bool
	cmd := &cobra.Command{
		Use:   "diagnose",
		Short: "Sniff the artifact, run every check, print ranked findings with a top cause",
		Long: `diagnose is rules-only: deterministic validators produce every finding and
the ranking. --no-llm is the default and, in this version, the only mode;
an opt-in --explain layer is planned and will never override a validator.`,
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
			err = out.write(cmd, diag.Text(res.Report, res.TopCause), map[string]any{
				"artifact_kind": res.Kind, "findings": res.Report.Findings, "top_cause": res.TopCause,
				"checks": res.Report.Checks, "needs": res.Report.Needs, "redaction": "default",
			})
			if err != nil {
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
	ef.bindClock(cmd)
	cmd.Flags().StringVar(&kind, "kind", "auto", "auto, saml_response, jwt or cert")
	cmd.Flags().StringVar(&symptom, "symptom", "", "the error you see (recorded for the future explain layer)")
	cmd.Flags().BoolVar(&noLLM, "no-llm", true, "rules only (the default and, for now, the only mode)")
	return cmd
}

// exitError carries a process exit code without printing anything.
type exitError struct{ code int }

func (e exitError) Error() string { return "" }
