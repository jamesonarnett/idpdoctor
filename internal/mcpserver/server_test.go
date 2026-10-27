// SPDX-License-Identifier: Apache-2.0

package mcpserver_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/fixture"
	"github.com/jamesonarnett/idpdoctor/internal/mcpserver"
)

// connect wires a client to the server over in-memory pipes: the same
// JSON-RPC framing as stdio, with no subprocess.
func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	srv := mcpserver.New(mcpserver.WithNow(func() time.Time { return fixture.FixedNow }))
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.MCP().Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	return res
}

func structured(t *testing.T, res *mcp.CallToolResult) map[string]any {
	t.Helper()
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("structured content is not an object: %s", b)
	}
	return m
}

func textOf(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

func TestToolList(t *testing.T) {
	cs := connect(t)
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"saml_decode": true, "saml_validate": true, "jwt_decode": true, "jwt_validate": true, "cert_inspect": true, "diagnose": true, "stash_file": true,
		"oidc_discovery_check": true, "oauth_error_explain": true}
	for _, tool := range res.Tools {
		if !want[tool.Name] {
			t.Errorf("unexpected tool %s", tool.Name)
		}
		delete(want, tool.Name)
		if tool.OutputSchema == nil {
			t.Errorf("%s has no output schema", tool.Name)
		}
	}
	if len(want) != 0 {
		t.Errorf("missing tools: %v", want)
	}
}

func TestSAMLToolsEndToEnd(t *testing.T) {
	cs := connect(t)
	k, _ := fixture.TestKeys()
	m, _ := fixture.SAMLMutator("audience_mismatch")
	minted, err := fixture.MintSAML(fixture.DefaultParams(), k, m)
	if err != nil {
		t.Fatal(err)
	}
	p := minted.Params

	dec := call(t, cs, "saml_decode", map[string]any{"input": string(minted.XML)})
	if dec.IsError {
		t.Fatalf("saml_decode error: %s", textOf(dec))
	}
	out := structured(t, dec)
	if out["binding_detected"] != "xml" || out["redaction"] != "default" {
		t.Errorf("decode out = %v", out)
	}
	if !strings.Contains(textOf(dec), p.IdPEntityID) {
		t.Errorf("text summary should name the issuer: %s", textOf(dec))
	}

	val := call(t, cs, "saml_validate", map[string]any{
		"input":    string(minted.XML),
		"expected": expected.Expected{SPEntityID: p.SPEntityID, ACSURL: p.ACSURL, IdPCertPEM: k.CertPEM()},
	})
	if val.IsError {
		t.Fatalf("saml_validate error: %s", textOf(val))
	}
	vout := structured(t, val)
	if vout["ok"] != false {
		t.Errorf("expected ok=false: %v", vout)
	}
	if !strings.Contains(textOf(val), "SAML_AUDIENCE_MISMATCH") {
		t.Errorf("text: %s", textOf(val))
	}
	needs, _ := vout["needs"].([]any)
	if len(needs) == 0 {
		t.Error("needs should list idp_entity_id, request_id, ...")
	}

	diag := call(t, cs, "diagnose", map[string]any{"artifact": string(minted.XML), "expected": map[string]any{"sp_entity_id": p.SPEntityID}})
	dout := structured(t, diag)
	top, _ := dout["top_cause"].(map[string]any)
	if top == nil || top["code"] != "SAML_AUDIENCE_MISMATCH" {
		t.Errorf("top_cause = %v", dout["top_cause"])
	}
	if dout["artifact_kind"] != "saml_response" {
		t.Errorf("kind = %v", dout["artifact_kind"])
	}
	// The text result names the citable paths on one labelled line, so a
	// model copies them instead of a check name.
	if !strings.Contains(textOf(diag), "Evidence paths (cite verbatim in evidence[].path): /Response/Assertion/Conditions/AudienceRestriction/Audience") {
		t.Errorf("diagnose text lacks the citable-paths line:\n%s", textOf(diag))
	}
	if !strings.Contains(textOf(val), "Evidence paths (cite verbatim in evidence[].path): ") {
		t.Errorf("saml_validate text lacks the citable-paths line:\n%s", textOf(val))
	}
}

func TestStashFileHandleFlow(t *testing.T) {
	cs := connect(t)
	k, _ := fixture.TestKeys()
	minted, _ := fixture.MintSAML(fixture.DefaultParams(), k)
	path := filepath.Join(t.TempDir(), "capture.txt")
	if err := os.WriteFile(path, minted.XML, 0o600); err != nil {
		t.Fatal(err)
	}
	st := call(t, cs, "stash_file", map[string]any{"path": path})
	if st.IsError {
		t.Fatalf("stash_file: %s", textOf(st))
	}
	sout := structured(t, st)
	ref, _ := sout["input_ref"].(string)
	if !strings.HasPrefix(ref, "art_") || sout["artifact_kind"] != "saml_response" {
		t.Fatalf("stash out = %v", sout)
	}
	prev, _ := sout["redacted_preview"].(string)
	if strings.Contains(prev, "alice") || !strings.Contains(prev, "Response") {
		t.Errorf("preview = %q", prev)
	}

	val := call(t, cs, "saml_validate", map[string]any{"input_ref": ref, "expected": map[string]any{"sp_entity_id": minted.Params.SPEntityID}})
	if val.IsError {
		t.Fatalf("validate via ref: %s", textOf(val))
	}
	if structured(t, val)["ok"] != true {
		t.Errorf("healthy via ref not ok: %s", textOf(val))
	}

	bad := call(t, cs, "saml_validate", map[string]any{"input_ref": "art_doesnotexist"})
	if !bad.IsError || !strings.Contains(textOf(bad), "unknown input_ref") {
		t.Errorf("unknown ref should be a tool error: %v %s", bad.IsError, textOf(bad))
	}
	none := call(t, cs, "saml_decode", map[string]any{})
	if !none.IsError {
		t.Error("no input and no ref must be a tool error")
	}
}

func TestJWTAndCertTools(t *testing.T) {
	cs := connect(t)
	k, _ := fixture.TestKeys()
	p := fixture.DefaultJWTParams()
	tok, _, _ := fixture.MintJWT(p, k.Key)
	jwks := fixture.JWKS(fixture.RSAJWK(p.KID, &k.Key.PublicKey))

	dec := structured(t, call(t, cs, "jwt_decode", map[string]any{"token": tok}))
	if dec["kind_guess"] != "id_token" {
		t.Errorf("decode = %v", dec)
	}
	claims, _ := dec["claims"].(map[string]any)
	if claims["sub"] == p.Subject || claims["iss"] != p.Issuer {
		t.Errorf("claims not redacted correctly: %v", claims)
	}

	val := structured(t, call(t, cs, "jwt_validate", map[string]any{
		"token": tok, "expected": map[string]any{"issuer": p.Issuer, "client_id": p.Audience}, "keys": map[string]any{"jwks_json": jwks},
	}))
	if val["ok"] != true {
		t.Errorf("validate = %v", val)
	}

	ci := structured(t, call(t, cs, "cert_inspect", map[string]any{"cert": k.CertPEM(), "now": "2026-01-15T12:00:00Z"}))
	if ci["key_bits"] != float64(2048) || ci["self_signed"] != true {
		t.Errorf("cert_inspect = %v", ci)
	}
}

// TestNoFixtureSecretLeaksFromAnyTool runs every tool over every fixture
// and scans the entire serialised MCP result, text and structured alike.
func TestNoFixtureSecretLeaksFromAnyTool(t *testing.T) {
	cs := connect(t)
	k, _ := fixture.TestKeys()
	secrets := []string{"alice@example.com", "Alice", "Admins", "Everyone", "Mallory", fixture.DefaultJWTParams().Subject}
	scan := func(name string, res *mcp.CallToolResult) {
		b, _ := json.Marshal(res)
		for _, s := range secrets {
			if strings.Contains(string(b), s) {
				t.Errorf("%s leaked %q", name, s)
			}
		}
	}
	p := fixture.DefaultParams()
	exp := expected.Expected{SPEntityID: p.SPEntityID, ACSURL: p.ACSURL, IdPEntityID: p.IdPEntityID, IdPCertPEM: k.CertPEM(), RequestID: p.RequestID, RequiredAttributes: []string{"email", "nope"}}
	cases := [][]fixture.Mutator{nil}
	for _, m := range fixture.SAMLMutators() {
		cases = append(cases, []fixture.Mutator{m})
	}
	for _, ms := range cases {
		minted, err := fixture.MintSAML(p, k, ms...)
		if err != nil {
			t.Fatal(err)
		}
		name := "healthy"
		if len(ms) > 0 {
			name = ms[0].Name
		}
		scan(name+"/saml_decode", call(t, cs, "saml_decode", map[string]any{"input": string(minted.XML)}))
		scan(name+"/saml_validate", call(t, cs, "saml_validate", map[string]any{"input": string(minted.XML), "expected": exp}))
		scan(name+"/diagnose", call(t, cs, "diagnose", map[string]any{"artifact": string(minted.XML), "expected": exp}))
		path := filepath.Join(t.TempDir(), "r.xml")
		if err := os.WriteFile(path, minted.XML, 0o600); err != nil {
			t.Fatal(err)
		}
		scan(name+"/stash_file", call(t, cs, "stash_file", map[string]any{"path": path}))
	}
	jp := fixture.DefaultJWTParams()
	jwks := fixture.JWKS(fixture.RSAJWK(jp.KID, &k.Key.PublicKey))
	jcases := []*fixture.JWTMutator{nil}
	for _, m := range fixture.JWTMutators() {
		m := m
		jcases = append(jcases, &m)
	}
	for _, m := range jcases {
		var muts []fixture.JWTMutator
		name := "healthy"
		if m != nil {
			muts = append(muts, *m)
			name = m.Name
		}
		tok, _, err := fixture.MintJWT(jp, k.Key, muts...)
		if err != nil {
			t.Fatal(err)
		}
		scan(name+"/jwt_decode", call(t, cs, "jwt_decode", map[string]any{"token": tok}))
		scan(name+"/jwt_validate", call(t, cs, "jwt_validate", map[string]any{"token": tok, "expected": map[string]any{"issuer": jp.Issuer, "client_id": jp.Audience, "nonce": jp.Nonce}, "keys": map[string]any{"jwks_json": jwks}}))
		scan(name+"/diagnose", call(t, cs, "diagnose", map[string]any{"artifact": tok, "keys": map[string]any{"jwks_json": jwks}}))
	}
	// OAuth: the authorization code and PKCE verifier are the secrets.
	op := fixture.DefaultOAuthParams()
	secrets = append(secrets, op.Code, op.CodeVerifier)
	ocases := []*fixture.OAuthMutator{nil}
	for _, m := range fixture.OAuthMutators() {
		m := m
		ocases = append(ocases, &m)
	}
	for _, m := range ocases {
		var muts []fixture.OAuthMutator
		name := "healthy"
		if m != nil {
			muts = append(muts, *m)
			name = m.Name
		}
		art, exp, _, err := fixture.MintOAuth(op, muts...)
		if err != nil {
			t.Fatal(err)
		}
		scan(name+"/oauth_error_explain", call(t, cs, "oauth_error_explain", map[string]any{"redirect_url": art, "request": exp}))
		scan(name+"/diagnose", call(t, cs, "diagnose", map[string]any{"artifact": art, "expected": exp}))
	}
	_, dp := fixture.DefaultDiscovery()
	for _, m := range fixture.DiscoveryMutators() {
		doc, _, err := fixture.MintDiscovery(dp, m)
		if err != nil {
			t.Fatal(err)
		}
		scan(m.Name+"/oidc_discovery_check", call(t, cs, "oidc_discovery_check", map[string]any{"document_json": string(doc), "expected_issuer": dp.Issuer}))
		scan(m.Name+"/diagnose", call(t, cs, "diagnose", map[string]any{"artifact": string(doc), "expected": map[string]any{"issuer": dp.Issuer}}))
	}
}

func TestV1Tools(t *testing.T) {
	cs := connect(t)
	doc, dp := fixture.DefaultDiscovery()
	raw, _ := json.Marshal(doc)
	out := structured(t, call(t, cs, "oidc_discovery_check", map[string]any{"document_json": string(raw), "expected_issuer": dp.Issuer}))
	if out["ok"] != true || out["redaction"] != "default" {
		t.Errorf("healthy discovery: %v", out)
	}
	m, _ := fixture.DiscoveryMutatorByName("discovery_missing_jwks_uri")
	bad, _, _ := fixture.MintDiscovery(dp, m)
	res := call(t, cs, "oidc_discovery_check", map[string]any{"document_json": string(bad)})
	if !strings.Contains(textOf(res), "OIDC_DISCOVERY_DOC_INVALID") {
		t.Errorf("missing jwks_uri not reported: %s", textOf(res))
	}

	om, _ := fixture.OAuthMutatorByName("oauth_redirect_uri_mismatch")
	art, exp, _, err := fixture.MintOAuth(fixture.DefaultOAuthParams(), om)
	if err != nil {
		t.Fatal(err)
	}
	oout := structured(t, call(t, cs, "oauth_error_explain", map[string]any{"redirect_url": art, "request": exp}))
	if oout["vendor"] != "entra" || oout["vendor_code"] != "AADSTS50011" || oout["ok"] != false {
		t.Errorf("oauth explain: %v", oout)
	}
	// diagnose sniffs the same artifact without being told the kind.
	d := structured(t, call(t, cs, "diagnose", map[string]any{"artifact": art, "expected": exp}))
	if top, _ := d["top_cause"].(map[string]any); d["artifact_kind"] != "oauth_redirect" || top == nil || top["code"] != "OAUTH_REDIRECT_URI_MISMATCH" {
		t.Errorf("diagnose on redirect: %v", d)
	}
	none := call(t, cs, "oauth_error_explain", map[string]any{})
	if !none.IsError {
		t.Error("no input must be a tool error")
	}
}
