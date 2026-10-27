// SPDX-License-Identifier: Apache-2.0

// Package web serves one local-only HTML page in front of diag.Run, for
// people who would rather paste into a form than type flags. It holds to
// the same threat model as the CLI and the MCP server: it binds loopback
// only, writes no logs (not even net/http's own error lines), sets no
// cookies, keeps no sessions and touches no files. Every byte it returns
// came from the already-redacted Report. Never deploy this.
package web

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/jwt"
)

//go:embed index.html
var indexHTML []byte

// MaxBody caps a diagnose request. Real SAML responses are tens of KB; 4 MiB
// leaves room for a fat signed+encrypted capture and nothing silly.
const MaxBody = 4 << 20

// ErrNotLoopback is returned before any socket is opened when asked to bind
// anything other than a loopback address.
var ErrNotLoopback = errors.New("web: refusing to bind a non-loopback address; this page is local-only")

// pageCSP allows only the inline script and style the page ships with and
// fetches back to this origin. No CDN, no images, no frames, no forms
// posting elsewhere.
const pageCSP = "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'"

// redactionDefault documents a property of the output, not a setting.
const redactionDefault = "default"

// Server holds the injectable clock and the HTTP client used only when a
// caller supplies keys.jwks_url. It has no other state on purpose.
type Server struct {
	client *http.Client
	now    func() time.Time
}

// Option configures New.
type Option func(*Server)

// WithHTTPClient injects the client used for jwks_url (httptest in tests).
func WithHTTPClient(c *http.Client) Option { return func(s *Server) { s.client = c } }

// WithNow pins the clock (tests pass fixture.FixedNow).
func WithNow(f func() time.Time) Option { return func(s *Server) { s.now = f } }

// New builds a Server with a 10s-timeout client and the wall clock.
func New(opts ...Option) *Server {
	s := &Server{client: &http.Client{Timeout: 10 * time.Second}, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Handler routes GET / to the page and POST /api/diagnose to the pipeline.
// The method-qualified patterns give 405 for a wrong method and 404 for
// any other path without extra code.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.page)
	mux.HandleFunc("POST /api/diagnose", s.diagnose)
	return guard(mux)
}

// guard sets the headers every response carries and rejects requests whose
// Host is not a loopback name. Binding loopback stops other machines; the
// Host check stops a DNS-rebinding page in the user's own browser from
// driving the endpoint (and its one outbound fetch, jwks_url).
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		if !loopbackHost(r.Host) {
			writeError(w, http.StatusMisdirectedRequest, "host is not a loopback address; this page is local-only")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) page(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", pageCSP)
	h.Set("X-Frame-Options", "DENY")
	_, _ = w.Write(indexHTML)
}

// diagnoseRequest mirrors the MCP diagnose input minus input_ref: there is
// no handle store here because there is no persistence at all.
type diagnoseRequest struct {
	Artifact     string            `json:"artifact"`
	ArtifactKind string            `json:"artifact_kind,omitempty"`
	Symptom      string            `json:"symptom,omitempty"`
	Expected     expected.Expected `json:"expected,omitempty"`
	Keys         jwt.Keys          `json:"keys,omitempty"`
}

// diagnoseResponse is the same shape the MCP diagnose tool returns, so the
// page, the CLI's --json and an agent all read one vocabulary.
type diagnoseResponse struct {
	ArtifactKind string            `json:"artifact_kind"`
	Findings     []finding.Finding `json:"findings"`
	TopCause     *finding.Finding  `json:"top_cause"`
	Checks       []finding.Check   `json:"checks"`
	Needs        []string          `json:"needs"`
	Text         string            `json:"text"`
	Redaction    string            `json:"redaction"`
}

func (s *Server) diagnose(w http.ResponseWriter, r *http.Request) {
	// Requiring a JSON content type means a cross-site page cannot send this
	// as a "simple" request: the browser must preflight, and we never answer
	// a preflight, so the POST never happens.
	if mt := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(mt), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
	var req diagnoseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds 4 MiB")
			return
		}
		// A fixed message: decoder errors can quote a fragment of the body.
		writeError(w, http.StatusBadRequest, "request body is not valid JSON")
		return
	}
	if strings.TrimSpace(req.Artifact) == "" {
		writeError(w, http.StatusBadRequest, "artifact is required")
		return
	}
	res, err := diag.Run(r.Context(), diag.Input{
		Artifact: req.Artifact, Kind: diag.Kind(req.ArtifactKind), Symptom: req.Symptom,
		Expected: req.Expected, Keys: req.Keys, Client: s.client, Now: s.now(),
	})
	if err != nil {
		// diag errors describe the failure (kind, decode step), never the
		// artifact bytes, so they are safe to show.
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, diagnoseResponse{
		ArtifactKind: string(res.Kind), Findings: res.Report.Findings, TopCause: res.TopCause,
		Checks: res.Report.Checks, Needs: res.Report.Needs,
		Text: diag.Text(res.Report, res.TopCause), Redaction: redactionDefault,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// CheckAddr accepts host:port only when host is localhost or a loopback IP.
// An empty host (":8080") means every interface, so it is refused too.
func CheckAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ErrNotLoopback
	}
	if !isLoopback(host) {
		return ErrNotLoopback
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// loopbackHost checks a request Host header, which may or may not carry a
// port and may be a bracketed IPv6 literal.
func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return isLoopback(strings.Trim(host, "[]"))
}

// ListenAndServe refuses non-loopback addresses before opening a socket,
// then serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	if err := CheckAddr(addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Serve serves on ln until ctx is cancelled, then shuts down with a 5s
// grace period. It does not re-check ln's address: callers that build their
// own listener (tests on port 0) own that decision.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// net/http logs some errors on its own (TLS handshakes, panics,
		// malformed requests). Discard them so nothing request-derived can
		// ever reach a terminal or a log file.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(sctx)
		case <-done:
		}
	}()
	err := srv.Serve(ln)
	close(done)
	<-stopped // let an in-progress Shutdown drain before returning
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
