// SPDX-License-Identifier: Apache-2.0

package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jamesonarnett/idpdoctor/internal/fixture"
	"github.com/jamesonarnett/idpdoctor/internal/web"
)

func newServer() *web.Server {
	return web.New(web.WithNow(func() time.Time { return fixture.FixedNow }))
}

// mintAudienceMismatch returns a signed SAML response whose Audience is
// wrong, and the JSON body that diagnoses it against the real SP entity ID.
func mintAudienceMismatch(t *testing.T) []byte {
	t.Helper()
	k, err := fixture.TestKeys()
	if err != nil {
		t.Fatal(err)
	}
	m, ok := fixture.SAMLMutator("audience_mismatch")
	if !ok {
		t.Fatal("audience_mismatch mutator missing")
	}
	minted, err := fixture.MintSAML(fixture.DefaultParams(), k, m)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{
		"artifact": string(minted.XML),
		"expected": map[string]string{
			"sp_entity_id": fixture.DefaultParams().SPEntityID,
			"now":          "2026-01-15T12:00:00Z",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func post(t *testing.T, url string, body []byte) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Post(url+"/api/diagnose", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

func TestCheckAddrRejectsNonLoopback(t *testing.T) {
	cases := []struct {
		addr string
		ok   bool
	}{
		{"127.0.0.1:0", true},
		{"localhost:0", true},
		{"[::1]:0", true},
		{"127.0.0.2:7777", true}, // all of 127/8 is loopback
		{"0.0.0.0:8080", false},
		{":8080", false}, // empty host means every interface
		{"192.168.1.5:8080", false},
		{"example.com:80", false},
		{"[::]:8080", false},
		{"garbage", false},
	}
	for _, c := range cases {
		err := web.CheckAddr(c.addr)
		if c.ok && err != nil {
			t.Errorf("CheckAddr(%q) = %v, want nil", c.addr, err)
		}
		if !c.ok && !errors.Is(err, web.ErrNotLoopback) {
			t.Errorf("CheckAddr(%q) = %v, want ErrNotLoopback", c.addr, err)
		}
	}

	// The refusal must happen before net.Listen, so it returns immediately
	// even with a context that is never cancelled.
	err := newServer().ListenAndServe(context.Background(), "0.0.0.0:0")
	if !errors.Is(err, web.ErrNotLoopback) {
		t.Fatalf("ListenAndServe(0.0.0.0:0) = %v, want ErrNotLoopback", err)
	}
}

func TestDiagnoseEndpoint(t *testing.T) {
	ts := httptest.NewServer(newServer().Handler())
	defer ts.Close()

	resp, body := post(t, ts.URL, mintAudienceMismatch(t))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	var out struct {
		ArtifactKind string `json:"artifact_kind"`
		TopCause     *struct {
			Code string `json:"code"`
		} `json:"top_cause"`
		Findings  []json.RawMessage `json:"findings"`
		Text      string            `json:"text"`
		Redaction string            `json:"redaction"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("response is not JSON: %v: %s", err, body)
	}
	if out.TopCause == nil || out.TopCause.Code != "SAML_AUDIENCE_MISMATCH" {
		t.Errorf("top_cause = %+v, want SAML_AUDIENCE_MISMATCH", out.TopCause)
	}
	if out.Redaction != "default" {
		t.Errorf("redaction = %q", out.Redaction)
	}
	if out.ArtifactKind == "" || out.Text == "" || len(out.Findings) == 0 {
		t.Errorf("incomplete response: %s", body)
	}
	// The no-leak rule: PII from the assertion never leaves the process.
	for _, secret := range []string{"alice@example.com", "Alice", "Admins"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Errorf("response leaks %q: %s", secret, body)
		}
	}
}

func TestPageServed(t *testing.T) {
	ts := httptest.NewServer(newServer().Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	if !bytes.Contains(page, []byte("Never deploy")) {
		t.Error("page is missing the never-deploy banner")
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "connect-src 'self'") {
		t.Errorf("CSP = %q", csp)
	}
	// The page must make no external requests: no absolute URLs at all.
	for _, ext := range []string{"http://", "https://", "//cdn"} {
		if bytes.Contains(page, []byte(ext)) {
			t.Errorf("page references %q", ext)
		}
	}

	for _, c := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/nope", http.StatusNotFound},
		{http.MethodGet, "/api/diagnose", http.StatusMethodNotAllowed},
		{http.MethodPost, "/", http.StatusMethodNotAllowed},
	} {
		req, _ := http.NewRequest(c.method, ts.URL+c.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s %s = %d, want %d", c.method, c.path, resp.StatusCode, c.want)
		}
	}
}

func TestBadRequests(t *testing.T) {
	ts := httptest.NewServer(newServer().Handler())
	defer ts.Close()

	huge := append([]byte(`{"artifact":"`), bytes.Repeat([]byte("A"), web.MaxBody+1)...)
	huge = append(huge, `"}`...)

	cases := []struct {
		name string
		body []byte
		want []int
	}{
		{"invalid json", []byte(`{"artifact":`), []int{http.StatusBadRequest}},
		{"undecodable artifact", []byte(`{"artifact":"hello"}`), []int{http.StatusBadRequest}},
		{"missing artifact", []byte(`{}`), []int{http.StatusBadRequest}},
		{"oversized", huge, []int{http.StatusRequestEntityTooLarge, http.StatusBadRequest}},
	}
	for _, c := range cases {
		resp, body := post(t, ts.URL, c.body)
		okStatus := false
		for _, w := range c.want {
			okStatus = okStatus || resp.StatusCode == w
		}
		if !okStatus {
			t.Errorf("%s: status = %d, want one of %v", c.name, resp.StatusCode, c.want)
		}
		var e struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &e); err != nil || e.Error == "" {
			t.Errorf("%s: want an error field, got %s", c.name, body)
		}
		if bytes.Contains(body, []byte("hello")) {
			t.Errorf("%s: error echoes the artifact: %s", c.name, body)
		}
	}

	// A cross-site "simple" POST (text/plain) is refused outright.
	resp, err := http.Post(ts.URL+"/api/diagnose", "text/plain", strings.NewReader(`{"artifact":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain POST = %d, want 415", resp.StatusCode)
	}

	// A non-loopback Host (DNS rebinding) is refused.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "attacker.example:7777"
	rec := httptest.NewRecorder()
	newServer().Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("non-loopback Host = %d, want 421", rec.Code)
	}
}

// TestNothingLogged runs real traffic through Serve (the production path,
// with its discard ErrorLog) and checks the standard logger saw nothing.
func TestNothingLogged(t *testing.T) {
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- newServer().Serve(ctx, ln) }()
	url := "http://" + ln.Addr().String()

	if resp, body := post(t, url, mintAudienceMismatch(t)); resp.StatusCode != http.StatusOK {
		t.Fatalf("diagnose status = %d: %s", resp.StatusCode, body)
	}
	if resp, _ := post(t, url, []byte(`not json`)); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad request status = %d", resp.StatusCode)
	}
	// A malformed request line makes net/http write its own error; it must
	// go to the discard logger, not the standard one.
	if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
		_, _ = c.Write([]byte("BOGUS\r\n\r\n"))
		_, _ = io.ReadAll(c)
		c.Close()
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v after cancel", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not stop after ctx cancel")
	}
	if buf.Len() != 0 {
		t.Fatalf("standard logger received output: %q", buf.String())
	}
}
