// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"sort"
	"time"
)

// s0 is the zero time; jwt.Decode only uses now for exp_in_seconds, which
// the stash preview does not show.
var s0 time.Time

func sortStrings(s []string) { sort.Strings(s) }
