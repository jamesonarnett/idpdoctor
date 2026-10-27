// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/saml"
)

func newSAMLCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "saml", Short: "Decode and validate SAML Responses"}
	cmd.AddCommand(newSAMLDecodeCmd(), newSAMLValidateCmd())
	return cmd
}

func newSAMLDecodeCmd() *cobra.Command {
	var in inputFlags
	var out outputFlags
	var binding string
	cmd := &cobra.Command{
		Use:   "decode",
		Short: "Decode a SAML Response (any binding) into a redacted summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := in.read(cmd)
			if err != nil {
				return err
			}
			dec, err := saml.Decode(raw, saml.Binding(binding))
			if err != nil {
				return err
			}
			p, err := saml.Parse(dec.XML)
			if err != nil {
				return err
			}
			p.Summary.RelayState = dec.RelayState
			if out.json {
				return out.write(cmd, "", map[string]any{
					"binding_detected": dec.Binding, "summary": p.Summary, "findings": p.Findings, "redaction": "default",
				})
			}
			return out.write(cmd, p.PrettyXML(1<<20), nil)
		},
	}
	in.bind(cmd)
	out.bind(cmd)
	cmd.Flags().StringVar(&binding, "binding", "auto", "auto, post, redirect or xml")
	return cmd
}

func newSAMLValidateCmd() *cobra.Command {
	var in inputFlags
	var out outputFlags
	var ef expectedFlags
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Run every SAML check against the SP's expected values",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := in.read(cmd)
			if err != nil {
				return err
			}
			exp, _, err := ef.resolve(cmd)
			if err != nil {
				return err
			}
			res, err := diag.Run(cmd.Context(), diag.Input{Artifact: raw, Kind: diag.KindSAMLResponse, Expected: exp, Now: time.Now()})
			if err != nil {
				return err
			}
			return out.write(cmd, diag.Text(res.Report, res.TopCause), map[string]any{
				"ok": res.Report.OK(), "checks": res.Report.Checks, "findings": res.Report.Findings,
				"needs": res.Report.Needs, "summary": res.SAML, "redaction": "default",
			})
		},
	}
	in.bind(cmd)
	out.bind(cmd)
	ef.bindSAML(cmd)
	ef.bindClock(cmd)
	return cmd
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
