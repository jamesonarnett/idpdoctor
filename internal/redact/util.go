// SPDX-License-Identifier: Apache-2.0

package redact

import "encoding/json"

// fmtAny renders an arbitrary JSON-ish value for hashing. json.Marshal is
// deterministic for maps (sorted keys), which fmt's %v is not.
func fmtAny(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "?"
	}
	return string(b)
}

// Truncate caps a string at max bytes with an explicit marker so an agent
// can tell the output was cut rather than guess. It never splits a mask.
func Truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "\n...[truncated]"
}
