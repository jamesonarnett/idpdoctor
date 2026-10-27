// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// tracer appends one JSON line per tool call to a file. It exists for the
// eval harness, which counts tool calls per case and wants to know which
// codes each call surfaced. It never records inputs or outputs (BUILD_PLAN
// 2.7: "$IDPDOCTOR_TRACE records tool names, durations and finding codes,
// never inputs"). A nil tracer is a no-op so the hot path has one branch.
type tracer struct {
	mu   sync.Mutex
	path string
}

// traceLine is the on-disk record. Codes are the finding codes the tool
// returned, when its output carries findings.
type traceLine struct {
	Time       string   `json:"time"`
	Tool       string   `json:"tool"`
	DurationMS int64    `json:"duration_ms"`
	IsError    bool     `json:"is_error"`
	Codes      []string `json:"codes,omitempty"`
}

func (t *tracer) record(line traceLine) {
	if t == nil {
		return
	}
	b, err := json.Marshal(line)
	if err != nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// O_APPEND so several server processes can share one file; a lost line
	// under contention is acceptable for a count, a corrupted one is not.
	f, err := os.OpenFile(t.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// codesOf pulls finding codes out of any tool output by a JSON round trip.
// It is reflection-free and tolerant: outputs without findings yield nil.
func codesOf(out any) []string {
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	var v struct {
		Findings []struct {
			Code string `json:"code"`
		} `json:"findings"`
	}
	if json.Unmarshal(b, &v) != nil || len(v.Findings) == 0 {
		return nil
	}
	codes := make([]string, 0, len(v.Findings))
	for _, f := range v.Findings {
		codes = append(codes, f.Code)
	}
	return codes
}

// traced wraps a typed handler so every call is timed and recorded. It is
// generic for the same reason mcp.AddTool is: the SDK needs the concrete
// In/Out types to build schemas, and the wrapper must preserve them.
func traced[In, Out any](t *tracer, name string, h mcp.ToolHandlerFor[In, Out]) mcp.ToolHandlerFor[In, Out] {
	if t == nil {
		return h
	}
	return func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		start := time.Now()
		res, out, err := h(ctx, req, in)
		t.record(traceLine{
			Time: start.UTC().Format(time.RFC3339), Tool: name, DurationMS: time.Since(start).Milliseconds(),
			IsError: err != nil, Codes: codesOf(out),
		})
		return res, out, err
	}
}
