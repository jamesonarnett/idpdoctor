// SPDX-License-Identifier: Apache-2.0

// Package agenttest installs a fake `claude` executable on PATH so tests of
// the agent and eval packages never contact the real CLI. The script prints
// canned envelopes selected by FAKE_CLAUDE_MODE and records what it was
// given (argv, stdin, banned env vars) for assertions.
package agenttest

import (
	_ "embed"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed fake-claude.sh
var script []byte

// Modes the script understands.
const (
	ModeSuccess      = "success"      // SAML_AUDIENCE_MISMATCH with one real and one made-up citation
	ModeHealthy      = "healthy"      // HEALTHY with a posture code
	ModeMalformed    = "malformed"    // prose on stdout, exit 1 (not logged in)
	ModeDenial       = "denial"       // permission_denials non-empty
	ModeError        = "error"        // is_error true, error_max_turns
	ModeNoStructured = "nostructured" // success without structured_output
	ModeTimeout      = "timeout"      // sleeps 30s
	ModeJudge        = "judge"        // a judge verdict envelope
)

// Install writes the script into a temp dir, puts that dir first on PATH
// and sets FAKE_CLAUDE_MODE. It returns the path of the record file the
// script writes (argv, env, stdin). Uses t.Setenv, so the test must not be
// parallel.
func Install(t testing.TB, mode string) (record string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "claude")
	if err := os.WriteFile(bin, script, 0o755); err != nil {
		t.Fatal(err)
	}
	record = filepath.Join(dir, "record.txt")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_CLAUDE_MODE", mode)
	t.Setenv("FAKE_CLAUDE_RECORD", record)
	return record
}

// Record reads what the fake saw, split into the labelled lines.
func Record(t testing.TB, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fake claude record: %v", err)
	}
	out := map[string]string{}
	var key string
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		switch {
		case ok && (k == "ARGS" || k == "KEY" || k == "TOKEN" || k == "CWD" || k == "STDIN"):
			key = k
			out[key] = v
		case key != "":
			out[key] += "\n" + line
		}
	}
	return out
}
