// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/jamesonarnett/idpdoctor/internal/bundle"
	"github.com/jamesonarnett/idpdoctor/internal/diag"
)

func newBundleCmd() *cobra.Command {
	var in inputFlags
	var ef expectedFlags
	var out, symptom string
	var redacted bool
	cmd := &cobra.Command{
		Use:   "bundle --redacted -f capture --out bundle.zip",
		Short: "Export a redacted zip (findings, summary, manifest) for a support ticket",
		Long: `bundle runs the same deterministic diagnosis as 'diagnose' and writes a zip
holding findings.json, the redacted summary and structure, params.json, a
manifest with the artifact's SHA-256, and REDACTION.md. The raw artifact is
never included and signature values are masked, so nothing in the zip can
be replayed. --redacted is the only mode and exists so the command line
says what the file is.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !redacted {
				return errors.New("bundle: only redacted bundles exist; drop --redacted=false")
			}
			if out == "" {
				return errors.New("bundle: --out is required")
			}
			raw, err := in.read(cmd)
			if err != nil {
				return err
			}
			exp, keys, err := ef.resolve(cmd)
			if err != nil {
				return err
			}
			res, err := diag.Run(cmd.Context(), diag.Input{Artifact: raw, Expected: exp, Keys: keys, Symptom: symptom, Now: time.Now()})
			if err != nil {
				return err
			}
			f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				return err
			}
			defer f.Close()
			if err := bundle.Write(f, bundle.Input{Artifact: []byte(raw), Result: res, Expected: exp, Symptom: symptom, Version: version}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (redacted; %d finding(s))\n", out, len(res.Report.Findings))
			return nil
		},
	}
	in.bind(cmd)
	ef.bindSAML(cmd)
	ef.bindJWT(cmd)
	ef.bindOAuth(cmd)
	ef.bindClock(cmd)
	cmd.Flags().StringVar(&out, "out", "", "zip file to write")
	cmd.Flags().StringVar(&symptom, "symptom", "", "the error you see, recorded in findings.json")
	cmd.Flags().BoolVar(&redacted, "redacted", true, "export redacted (the only mode)")
	return cmd
}
