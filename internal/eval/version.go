// SPDX-License-Identifier: Apache-2.0

package eval

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// claudeVersion records the CLI version in the manifest (README pins it).
// `claude --version` makes no model call. Missing CLI is an empty string.
func claudeVersion(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "claude", "--version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
