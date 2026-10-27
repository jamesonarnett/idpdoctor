// SPDX-License-Identifier: Apache-2.0

// Package mcpserver exposes the internal validators as MCP tools over
// stdio using the official go-sdk. It is an adapter: every handler decodes
// its input, calls internal/*, and shapes the output. Nothing here is
// clever on purpose; the interesting code is one import away.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jamesonarnett/idpdoctor/internal/redact"
)

// Version is stamped by the CLI; tests leave it as dev.
var Version = "dev"

// MaxToolOutput caps any single text payload (pretty XML) so a hostile or
// merely huge artifact cannot flood the agent's context.
const MaxToolOutput = 32 << 10

// Server holds per-process state: the artifact handle store and an HTTP
// client for the one tool that may fetch (jwt_validate with jwks_url).
type Server struct {
	store  *redact.Store
	client *http.Client
	now    func() time.Time
	mcp    *mcp.Server
	trace  *tracer
	// preload are files registered under deterministic handles at start,
	// so a host (idpdoctor diagnose --explain, the eval harness) can hand
	// an agent a handle to an artifact the agent never sees.
	preload []string
}

// Option configures New.
type Option func(*Server)

// WithHTTPClient injects the client used for jwks_url (httptest in tests).
func WithHTTPClient(c *http.Client) Option { return func(s *Server) { s.client = c } }

// WithNow pins the clock (tests pass fixture.FixedNow).
func WithNow(f func() time.Time) Option { return func(s *Server) { s.now = f } }

// WithTrace appends one JSON line per tool call (name, duration, finding
// codes; never inputs) to path. The CLI sets it from $IDPDOCTOR_TRACE.
func WithTrace(path string) Option {
	return func(s *Server) {
		if path != "" {
			s.trace = &tracer{path: path}
		}
	}
}

// WithPreload registers the file's bytes under redact.RefFor(bytes) before
// the first request, so the handle can be computed by the host ahead of
// time and placed in the agent's prompt.
func WithPreload(paths ...string) Option {
	return func(s *Server) { s.preload = append(s.preload, paths...) }
}

// New builds the server with every tool registered. It returns an error
// only when a preload file cannot be read.
func New(opts ...Option) *Server {
	s, err := NewE(opts...)
	if err != nil {
		panic("mcpserver: " + err.Error())
	}
	return s
}

// NewE is New with the preload error surfaced instead of panicking; the
// CLI uses it because a missing file is a user error, not a bug.
func NewE(opts ...Option) (*Server, error) {
	s := &Server{
		store:  redact.NewStore(),
		client: &http.Client{Timeout: 10 * time.Second},
		now:    time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	for _, p := range s.preload {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("preload %s: %w", p, err)
		}
		s.store.PutRef(redact.RefFor(data), data)
	}
	s.mcp = mcp.NewServer(&mcp.Implementation{Name: "idpdoctor", Version: Version}, &mcp.ServerOptions{
		Instructions: instructions,
	})
	s.registerTools()
	return s, nil
}

// MCP returns the underlying go-sdk server (tests connect it in-memory).
func (s *Server) MCP() *mcp.Server { return s.mcp }

// Store returns the handle store so a host (the CLI) can pre-register an
// artifact before the agent connects.
func (s *Server) Store() *redact.Store { return s.store }

// Run serves over stdio until ctx is cancelled or stdin closes.
func (s *Server) Run(ctx context.Context) error {
	return s.mcp.Run(ctx, &mcp.StdioTransport{})
}

const instructions = `idpdoctor decodes and validates SAML responses, JWTs and X.509 certificates
locally. All outputs are redacted (NameID, attribute values and PII claims
are replaced by [REDACTED:kind:hash]); there is no way to turn that off.
Prefer stash_file + input_ref over pasting an assertion: the raw artifact
then never enters this conversation. Every check that lacks its expected
value reports status "skip" with a "needs" field: ask the user for that
value rather than guessing. Start with diagnose for an overall ranking.`

// errInput is returned when neither input nor input_ref was given.
var errInput = errors.New("provide either input or input_ref")

// resolve returns the artifact bytes from an inline string or a handle.
func (s *Server) resolve(inline, ref string) (string, error) {
	switch {
	case ref != "":
		b, err := s.store.Get(ref)
		if err != nil {
			return "", fmt.Errorf("%w: %s (call stash_file first; handles live only for this server process)", err, ref)
		}
		return string(b), nil
	case inline != "":
		return inline, nil
	}
	return "", errInput
}

// textResult wraps a prose summary as the unstructured content. The typed
// Out value becomes structuredContent automatically.
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}
