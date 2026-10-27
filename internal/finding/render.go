// SPDX-License-Identifier: Apache-2.0

package finding

import (
	"fmt"
	"strings"
)

// RenderTaxonomy renders the catalog as the markdown published at
// docs/TAXONOMY.md. It lives in the package (not only in the generator) so
// codes_test.go can assert the committed file is in sync.
func RenderTaxonomy() string {
	var b strings.Builder
	b.WriteString("# idpdoctor failure taxonomy\n\n")
	b.WriteString("Generated from `internal/finding/codes.go` by `go generate ./...`; do not edit by hand.\n\n")
	b.WriteString("Kind: **D** = deterministic from the artifact alone; **D+C** = deterministic once the expected value is supplied; ")
	b.WriteString("**C** = needs config or symptom context. Mutator names the `internal/fixture` function that produces the class ")
	b.WriteString("(blank = not yet covered by a fixture).\n\n")

	b.WriteString("## Failure classes (lane: fault)\n\n")
	b.WriteString("| # | Code | Proto | Kind | Tier | Signal | Fix | Merged from | Mutator |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|---|\n")
	for _, s := range Catalog {
		if s.Lane != LaneFault {
			continue
		}
		fmt.Fprintf(&b, "| %d | `%s` | %s | %s | %s | %s | %s | %s | %s |\n",
			s.Number, s.Code, s.Protocol, s.Kind, s.Tier, cell(s.Signal), cell(s.Fix), cell(strings.Join(s.MergedFrom, "; ")), mutatorCell(s.Mutator))
	}

	b.WriteString("\n## Security-posture codes (lane: posture)\n\n")
	b.WriteString("These fire when the artifact validates (or would under the SP settings in `expected`) yet exhibits an unsafe property.\n\n")
	b.WriteString("| Code | Proto | Tier | Signal | Fix | Source | Mutator |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, s := range Catalog {
		if s.Lane != LanePosture {
			continue
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s |\n",
			s.Code, s.Protocol, s.Tier, cell(s.Signal), cell(s.Fix), cell(strings.Join(s.MergedFrom, "; ")), mutatorCell(s.Mutator))
	}

	b.WriteString("\n## References\n\n")
	for _, s := range Catalog {
		if len(s.Refs) == 0 {
			continue
		}
		fmt.Fprintf(&b, "- `%s`:", s.Code)
		for i, r := range s.Refs {
			if i > 0 {
				b.WriteString(" ,")
			}
			fmt.Fprintf(&b, " %s", r)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// cell escapes pipes so free text cannot break the markdown table.
func cell(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func mutatorCell(m string) string {
	if m == "" {
		return ""
	}
	return "`" + m + "`"
}
