// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jamesonarnett/idpdoctor/internal/web"
)

func newWebCmd() *cobra.Command {
	var addr string
	cmd := &cobra.Command{
		Use:   "web",
		Short: "Serve a local-only paste-and-diagnose page on 127.0.0.1",
		Long: `Serves one HTML page and a /api/diagnose endpoint backed by the same pipeline
as 'idpdoctor diagnose'. Local only: it refuses to bind any non-loopback
address (0.0.0.0, ":port", a LAN IP) and rejects requests whose Host is not
loopback. Nothing is logged or stored: no request logs, no cookies, no
sessions, no files. Output is redacted. Never deploy this page; it is a
desktop convenience, not a service. Stop it with Ctrl-C.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check before printing the banner so a refused address does not
			// first announce a URL that will never answer.
			if err := web.CheckAddr(addr); err != nil {
				return fmt.Errorf("%w (got %q; try --addr 127.0.0.1:7777)", err, addr)
			}
			fmt.Fprintf(os.Stderr, "idpdoctor web: http://%s (local only; redaction: default; persistence: none)\n", addr)
			return web.New().ListenAndServe(cmd.Context(), addr)
		},
	}
	cmd.Flags().StringVar(&addr, "addr", "127.0.0.1:7777", "loopback host:port to listen on")
	return cmd
}
