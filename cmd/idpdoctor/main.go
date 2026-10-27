// SPDX-License-Identifier: Apache-2.0

// Command idpdoctor decodes and validates SAML / JWT / OIDC artifacts and
// diagnoses broken enterprise SSO setups. It is a thin wrapper: every
// subcommand calls the same internal packages the MCP server exposes.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// A signal-aware context so `idpdoctor mcp` shuts down cleanly on Ctrl-C
	// and every subcommand inherits cancellation via cobra's ExecuteContext.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "idpdoctor:", err)
		os.Exit(1)
	}
}
