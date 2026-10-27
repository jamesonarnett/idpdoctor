// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jamesonarnett/idpdoctor/internal/mcpserver"
)

func newMCPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Serve the idpdoctor tools over MCP stdio (for Claude Code, Cursor, ...)",
		Long: `Runs until stdin closes or the process is signalled. Nothing is logged to
stdout (that is the protocol channel) and nothing is written to disk. Add to
.mcp.json:  {"mcpServers":{"idpdoctor":{"command":"idpdoctor","args":["mcp"]}}}`,
		RunE: func(cmd *cobra.Command, args []string) error {
			mcpserver.Version = version
			fmt.Fprintln(os.Stderr, "idpdoctor mcp: serving on stdio (redaction: default, persistence: none)")
			return mcpserver.New().Run(cmd.Context())
		},
	}
}
