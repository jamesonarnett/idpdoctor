// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"sort"
	"strings"
	"time"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// withCitablePaths appends the evidence paths a report's findings carry to
// a tool's text result, on one labelled line, so a model reading the result
// sees exactly the strings it may put in evidence[].path. The paths are
// already in the structured findings; this repeats them where a model
// actually looks (prompt v2).
func withCitablePaths(text string, r *finding.Report) string {
	seen := map[string]bool{}
	var paths []string
	for _, f := range r.Findings {
		for _, e := range f.Evidence {
			if !seen[e.Path] {
				seen[e.Path] = true
				paths = append(paths, e.Path)
			}
		}
	}
	if len(paths) == 0 {
		return text
	}
	return text + "Evidence paths (cite verbatim in evidence[].path): " + strings.Join(paths, ", ") + "\n"
}

// s0 is the zero time; jwt.Decode only uses now for exp_in_seconds, which
// the stash preview does not show.
var s0 time.Time

func sortStrings(s []string) { sort.Strings(s) }
