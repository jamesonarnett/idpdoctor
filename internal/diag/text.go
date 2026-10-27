// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"fmt"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// Text renders a Report for humans and for the text content of an MCP
// result. It is the only place findings are turned into prose, so the CLI
// and every tool read the same way. Everything it prints came from the
// (already redacted) Report.
func Text(r *finding.Report, top *finding.Finding) string {
	var b strings.Builder
	faults, postures := 0, 0
	for _, f := range r.Findings {
		if f.Lane == finding.LanePosture {
			postures++
		} else {
			faults++
		}
	}
	switch {
	case r.OK() && postures == 0:
		fmt.Fprintf(&b, "%s: OK, %d checks passed, no findings.\n", r.ArtifactKind, countStatus(r, finding.CheckPass))
	case r.OK():
		fmt.Fprintf(&b, "%s: validates, but %d posture finding(s) (works, unsafe).\n", r.ArtifactKind, postures)
	default:
		fmt.Fprintf(&b, "%s: %d fault finding(s), %d posture finding(s).", r.ArtifactKind, faults, postures)
		if top != nil {
			fmt.Fprintf(&b, " Top cause: %s.", top.Code)
		}
		b.WriteString("\n")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "  [%s/%s] %s: %s\n", f.Lane, f.Severity, f.Code, f.Title)
		for _, e := range f.Evidence {
			fmt.Fprintf(&b, "      %s", e.Path)
			if e.Actual != "" {
				fmt.Fprintf(&b, "  actual=%q", e.Actual)
			}
			if e.Expected != "" {
				fmt.Fprintf(&b, "  expected=%q", e.Expected)
			}
			if e.Note != "" {
				fmt.Fprintf(&b, "  (%s)", e.Note)
			}
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "      fix: %s\n", f.Fix)
	}
	if len(r.Checks) > 0 {
		b.WriteString("Checks:")
		for _, c := range r.Checks {
			fmt.Fprintf(&b, " %s=%s", c.Name, c.Status)
		}
		b.WriteString("\n")
	}
	if len(r.Needs) > 0 {
		fmt.Fprintf(&b, "Supply to unskip checks: %s\n", strings.Join(r.Needs, ", "))
	}
	return b.String()
}

func countStatus(r *finding.Report, st finding.CheckStatus) int {
	n := 0
	for _, c := range r.Checks {
		if c.Status == st {
			n++
		}
	}
	return n
}
