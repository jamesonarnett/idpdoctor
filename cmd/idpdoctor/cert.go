// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/jamesonarnett/idpdoctor/internal/cert"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
)

func newCertCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cert", Short: "Inspect X.509 certificates"}
	var in inputFlags
	var out outputFlags
	var now string
	inspect := &cobra.Command{
		Use:   "inspect",
		Short: "Show subject, validity, key size, fingerprints and expiry/weakness findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := in.read(cmd)
			if err != nil {
				return err
			}
			at, err := (expected.Expected{Now: now}).NowOr(time.Now())
			if err != nil {
				return err
			}
			c, err := cert.Parse(raw)
			if err != nil {
				return err
			}
			info := cert.Inspect(c, at)
			text := fmt.Sprintf("subject:  %s\nissuer:   %s\nvalid:    %s to %s (%d days remaining)\nkey:      %s %d bits, %s\nsha256:   %s\nsha1:     %s\nfindings: %d\n",
				info.Subject, info.Issuer, info.NotBefore, info.NotAfter, info.DaysRemaining, info.KeyAlg, info.KeyBits, info.SigAlg, info.SHA256, info.SHA1, len(info.Findings))
			for _, f := range info.Findings {
				text += fmt.Sprintf("  [%s] %s: %s\n", f.Severity, f.Code, f.Evidence[0].Note+f.Evidence[0].Actual)
			}
			return out.write(cmd, text, info)
		},
	}
	in.bind(inspect)
	out.bind(inspect)
	inspect.Flags().StringVar(&now, "now", "", "RFC 3339 time to evaluate validity at")
	cmd.AddCommand(inspect)
	return cmd
}
