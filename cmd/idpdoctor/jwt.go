// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/jwt"
)

func newJWTCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "jwt", Short: "Decode and validate JWTs (id_tokens, access tokens)"}
	cmd.AddCommand(newJWTDecodeCmd(), newJWTValidateCmd())
	return cmd
}

func newJWTDecodeCmd() *cobra.Command {
	var in inputFlags
	var out outputFlags
	cmd := &cobra.Command{
		Use:   "decode",
		Short: "Decode a JWT without verifying; claims are redacted",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := in.read(cmd)
			if err != nil {
				return err
			}
			d, err := jwt.Decode(raw, time.Now())
			if err != nil {
				return err
			}
			text := fmt.Sprintf("alg=%s kid=%s kind=%s exp_in=%ds findings=%d\n", d.Alg, d.KID, d.KindGuess, d.ExpInSeconds, len(d.Findings))
			if !out.json {
				// Text mode still shows the redacted claims; that is the point of decode.
				out.json = true
			}
			return out.write(cmd, text, d)
		},
	}
	in.bind(cmd)
	out.bind(cmd)
	return cmd
}

func newJWTValidateCmd() *cobra.Command {
	var in inputFlags
	var out outputFlags
	var ef expectedFlags
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a JWT against a JWKS or PEM key and check each claim",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := in.read(cmd)
			if err != nil {
				return err
			}
			exp, keys, err := ef.resolve(cmd)
			if err != nil {
				return err
			}
			res, err := diag.Run(cmd.Context(), diag.Input{Artifact: raw, Kind: diag.KindJWT, Expected: exp, Keys: keys, Now: time.Now()})
			if err != nil {
				return err
			}
			return out.write(cmd, diag.Text(res.Report, res.TopCause), map[string]any{
				"ok": res.Report.OK(), "checks": res.Report.Checks, "findings": res.Report.Findings,
				"needs": res.Report.Needs, "header": res.JWT.Header, "claims": res.JWT.Claims, "redaction": "default",
			})
		},
	}
	in.bind(cmd)
	out.bind(cmd)
	ef.bindJWT(cmd)
	ef.bindClock(cmd)
	return cmd
}
