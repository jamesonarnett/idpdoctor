// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jamesonarnett/idpdoctor/internal/fixture"
)

// TestMCPOverStdio is the real thing: it builds the binary, launches
// `idpdoctor mcp` as a subprocess exactly as Claude Code would, and talks
// JSON-RPC over its stdin/stdout. It needs the go toolchain on PATH, which
// every environment that runs `go test` has.
func TestMCPOverStdio(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "idpdoctor")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "mcp")
	cmd.Stderr = os.Stderr
	client := mcp.NewClient(&mcp.Implementation{Name: "idpdoctor-e2e-test", Version: "0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 9 {
		t.Errorf("want 9 tools, got %d", len(tools.Tools))
	}

	k, err := fixture.TestKeys()
	if err != nil {
		t.Fatal(err)
	}
	p := fixture.DefaultParams()
	p.Dialect = "okta"
	minted, err := fixture.MintSAML(p, k)
	if err != nil {
		t.Fatal(err)
	}
	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "saml_decode", Arguments: map[string]any{"input": string(minted.XML)}})
	if err != nil {
		t.Fatalf("saml_decode: %v", err)
	}
	if res.IsError {
		t.Fatalf("saml_decode returned a tool error: %+v", res.Content)
	}
	raw, _ := json.Marshal(res.StructuredContent)
	var out struct {
		Binding   string `json:"binding_detected"`
		Redaction string `json:"redaction"`
		Summary   struct {
			Issuer    string `json:"issuer"`
			Assertion struct {
				Subject struct {
					NameID string `json:"name_id"`
				} `json:"subject"`
			} `json:"assertion"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.Binding != "xml" || out.Redaction != "default" || out.Summary.Issuer != p.IdPEntityID {
		t.Errorf("unexpected output: %s", raw)
	}
	if !strings.HasPrefix(out.Summary.Assertion.Subject.NameID, "[REDACTED:nameid:") || strings.Contains(string(raw), p.NameID) {
		t.Errorf("NameID leaked over stdio: %s", raw)
	}
	var text string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text += tc.Text
		}
	}
	if !strings.Contains(text, "SAML Response via xml binding") {
		t.Errorf("text content: %q", text)
	}
}
