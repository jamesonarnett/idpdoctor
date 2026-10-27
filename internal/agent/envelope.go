// SPDX-License-Identifier: Apache-2.0

package agent

import "encoding/json"

// Envelope is the JSON object `claude -p --output-format json` prints.
// Field names follow the CLI (camelCase for modelUsage, snake_case for the
// rest) as verified locally in BUILD_PLAN 5.2. Unknown fields are ignored,
// so a newer CLI adding keys does not break parsing; Raw keeps everything
// for the eval cache.
type Envelope struct {
	Type              string                `json:"type"`
	Subtype           string                `json:"subtype"`
	IsError           bool                  `json:"is_error"`
	Result            string                `json:"result"`
	StructuredOutput  json.RawMessage       `json:"structured_output"`
	SessionID         string                `json:"session_id"`
	StopReason        string                `json:"stop_reason"`
	NumTurns          int                   `json:"num_turns"`
	DurationMS        int64                 `json:"duration_ms"`
	DurationAPIMS     int64                 `json:"duration_api_ms"`
	TotalCostUSD      float64               `json:"total_cost_usd"`
	Usage             Usage                 `json:"usage"`
	ModelUsage        map[string]ModelUsage `json:"modelUsage"`
	PermissionDenials []PermissionDenial    `json:"permission_denials"`
	Raw               json.RawMessage       `json:"-"`
}

// Usage is the token accounting for the whole run. Cache tokens are kept
// separate so "tokens per case" can be reported as in / cached / out.
type Usage struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
}

// ModelUsage is the per-model breakdown. CostBasis is "list" on a
// subscription: the CLI reports what the tokens would cost at list price,
// which is exactly the "list-price equivalent" the README table wants.
type ModelUsage struct {
	InputTokens              int64   `json:"inputTokens"`
	OutputTokens             int64   `json:"outputTokens"`
	CacheReadInputTokens     int64   `json:"cacheReadInputTokens"`
	CacheCreationInputTokens int64   `json:"cacheCreationInputTokens"`
	CostUSD                  float64 `json:"costUSD"`
	CostBasis                string  `json:"costBasis"`
}

// PermissionDenial records a tool call the CLI refused. The harness treats
// any denial as a failed run: it means the allow-list or the prompt is
// wrong, and a diagnosis produced after a denial is not comparable.
type PermissionDenial struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// TotalInputTokens is every token the model read, cached or not.
func (u Usage) TotalInputTokens() int64 {
	return u.InputTokens + u.CacheCreationInputTokens + u.CacheReadInputTokens
}

// parseEnvelope decodes stdout. The CLI prints exactly one object in json
// mode; anything else (a stack trace, an empty string, a login prompt) is
// ErrMalformed with the first bytes attached for the human.
func parseEnvelope(stdout []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(stdout, &env); err != nil {
		return nil, &MalformedError{Head: head(stdout, 200), Err: err}
	}
	if env.Type == "" && env.Subtype == "" && env.StructuredOutput == nil && env.Result == "" {
		return nil, &MalformedError{Head: head(stdout, 200), Err: ErrMalformed}
	}
	env.Raw = append(json.RawMessage(nil), stdout...)
	return &env, nil
}

func head(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}
