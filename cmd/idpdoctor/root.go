// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is overridden at build time by -ldflags "-X main.version=...".
var version = "dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "idpdoctor",
		Short: "Decode, validate and diagnose SAML / JWT / OIDC artifacts, locally",
		Long: `idpdoctor decodes and validates SAML responses, JWTs and X.509 certs and
diagnoses broken enterprise SSO setups. Everything runs locally; outputs are
redacted by default and nothing is persisted.`,
		// We print errors ourselves in main; cobra's default would also dump usage.
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newVersionCmd(), newSAMLCmd(), newJWTCmd(), newCertCmd(), newDiagnoseCmd(), newMCPCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the idpdoctor version",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "idpdoctor", version)
			return err
		},
	}
}
