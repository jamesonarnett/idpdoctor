// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jamesonarnett/idpdoctor/internal/mcpserver"
)

func newMCPCmd() *cobra.Command {
	var preload []string
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve the idpdoctor tools over MCP stdio (for Claude Code, Cursor, ...)",
		Long: `Runs until stdin closes or the process is signalled. Nothing is logged to
stdout (that is the protocol channel) and nothing is written to disk. Add to
.mcp.json:  {"mcpServers":{"idpdoctor":{"command":"idpdoctor","args":["mcp"]}}}

--preload registers a local file under a deterministic input_ref before the
first request (used by 'diagnose --explain' and the eval harness so the agent
gets a handle, never the artifact). If $IDPDOCTOR_TRACE names a file, one
JSON line per tool call (tool, duration, finding codes; never inputs) is
appended to it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			mcpserver.Version = version
			srv, err := mcpserver.NewE(mcpserver.WithPreload(preload...), mcpserver.WithTrace(os.Getenv("IDPDOCTOR_TRACE")))
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "idpdoctor mcp: serving on stdio (redaction: default, persistence: none)")
			return srv.Run(cmd.Context())
		},
	}
	cmd.Flags().StringArrayVar(&preload, "preload", nil, "local artifact file to register under its deterministic input_ref (repeatable)")
	return cmd
}
