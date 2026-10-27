// SPDX-License-Identifier: Apache-2.0

// Command gen renders docs/TAXONOMY.md from the finding catalog. It is run by
// `go generate ./...` (see the directive in codes.go) and by CI, which fails
// if the committed file differs from the rendered one.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

func main() {
	out := flag.String("out", "", "path to write (stdout if empty)")
	flag.Parse()

	md := finding.RenderTaxonomy()
	if *out == "" {
		fmt.Print(md)
		return
	}
	if err := os.WriteFile(*out, []byte(md), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}
