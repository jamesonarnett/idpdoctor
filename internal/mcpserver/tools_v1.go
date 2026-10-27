// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/oauth"
	"github.com/jamesonarnett/idpdoctor/internal/oidc"
)

// --- oidc_discovery_check ------------------------------------------------

type oidcDiscoveryIn struct {
	DocumentJSON   string `json:"document_json,omitempty" jsonschema:"the discovery document as pasted"`
	InputRef       string `json:"input_ref,omitempty" jsonschema:"handle from stash_file"`
	IssuerURL      string `json:"issuer_url,omitempty" jsonschema:"fetch <issuer_url>/.well-known/openid-configuration instead of pasting; the only network call this tool makes"`
	ExpectedIssuer string `json:"expected_issuer,omitempty" jsonschema:"the issuer the SP is configured with"`
}

type oidcDiscoveryOut struct {
	OK        bool              `json:"ok"`
	Summary   oidc.Summary      `json:"summary"`
	Checks    []finding.Check   `json:"checks"`
	Findings  []finding.Finding `json:"findings"`
	Needs     []string          `json:"needs"`
	Text      string            `json:"text"`
	Redaction string            `json:"redaction"`
}

func (s *Server) oidcDiscoveryCheck(ctx context.Context, _ *mcp.CallToolRequest, in oidcDiscoveryIn) (*mcp.CallToolResult, oidcDiscoveryOut, error) {
	var doc []byte
	var opts oidc.Options
	switch {
	case in.IssuerURL != "":
		var err error
		doc, opts, err = oidc.Fetch(ctx, s.client, in.IssuerURL)
		if err != nil {
			return nil, oidcDiscoveryOut{}, err
		}
	default:
		raw, err := s.resolve(in.DocumentJSON, in.InputRef)
		if err != nil {
			return nil, oidcDiscoveryOut{}, fmt.Errorf("%w, or issuer_url", err)
		}
		doc = []byte(raw)
	}
	opts.ExpectedIssuer = in.ExpectedIssuer
	res, err := oidc.Check(doc, opts)
	if err != nil {
		return nil, oidcDiscoveryOut{}, err
	}
	top := topCause(res.Report)
	out := oidcDiscoveryOut{
		OK: res.Report.OK(), Summary: res.Summary, Checks: res.Report.Checks, Findings: res.Report.Findings,
		Needs: res.Report.Needs, Text: diag.Text(res.Report, top), Redaction: redactionDefault,
	}
	return textResult(out.Text), out, nil
}

// --- oauth_error_explain -------------------------------------------------

type oauthExplainIn struct {
	RedirectURL   string            `json:"redirect_url,omitempty" jsonschema:"the full redirect URL the browser landed on (error=... in query or fragment), or a bare query string"`
	ErrorBodyJSON string            `json:"error_body_json,omitempty" jsonschema:"the token endpoint's JSON error body"`
	InputRef      string            `json:"input_ref,omitempty" jsonschema:"handle from stash_file holding either form"`
	Request       expected.Expected `json:"request,omitempty" jsonschema:"what the client sent: redirect_uri, registered_redirect_uris, code_verifier, code_challenge, code_challenge_method, scopes, response_type, grant_type, client_type"`
}

type oauthExplainOut struct {
	OK               bool              `json:"ok"`
	Error            string            `json:"error"`
	ErrorDescription string            `json:"error_description,omitempty"`
	VendorCode       string            `json:"vendor_code,omitempty"`
	Vendor           string            `json:"vendor"`
	Summary          oauth.Summary     `json:"summary"`
	Checks           []finding.Check   `json:"checks"`
	Findings         []finding.Finding `json:"findings"`
	Needs            []string          `json:"needs"`
	Text             string            `json:"text"`
	Redaction        string            `json:"redaction"`
}

func (s *Server) oauthErrorExplain(_ context.Context, _ *mcp.CallToolRequest, in oauthExplainIn) (*mcp.CallToolResult, oauthExplainOut, error) {
	inline := in.RedirectURL
	if inline == "" {
		inline = in.ErrorBodyJSON
	}
	raw, err := s.resolve(inline, in.InputRef)
	if err != nil {
		return nil, oauthExplainOut{}, errors.New("provide redirect_url, error_body_json or input_ref")
	}
	res, err := oauth.Explain(raw, in.Request)
	if err != nil {
		return nil, oauthExplainOut{}, err
	}
	top := topCause(res.Report)
	out := oauthExplainOut{
		OK: res.Report.OK(), Error: res.Summary.Error, ErrorDescription: res.Summary.ErrorDescription, VendorCode: res.Summary.VendorCode,
		Vendor: res.Summary.Vendor, Summary: res.Summary, Checks: res.Report.Checks, Findings: res.Report.Findings,
		Needs: res.Report.Needs, Text: diag.Text(res.Report, top), Redaction: redactionDefault,
	}
	return textResult(out.Text), out, nil
}

// topCause mirrors diag.finish for reports produced outside the pipeline.
func topCause(r *finding.Report) *finding.Finding {
	for i := range r.Findings {
		f := &r.Findings[i]
		if f.Lane == finding.LaneFault && f.Severity == finding.SeverityError {
			return f
		}
	}
	return nil
}

func (s *Server) registerV1Tools() {
	mcp.AddTool(s.mcp, &mcp.Tool{Name: "oidc_discovery_check", Description: "Check an OpenID Connect discovery document (pasted, or fetched from issuer_url) for the REQUIRED fields, issuer match (Discovery 4.3), https-only endpoints, RS256 support, endpoint hosts and a token_endpoint for the code flow. " + strings.TrimSpace("Fetching is the only network call and happens only when issuer_url is given.")}, traced(s.trace, "oidc_discovery_check", s.oidcDiscoveryCheck))
	mcp.AddTool(s.mcp, &mcp.Tool{Name: "oauth_error_explain", Description: "Explain an OAuth 2.0 / OIDC error: a redirect URL carrying error=..., or a token endpoint's JSON error body. Maps the error (and AADSTS / Okta vendor codes) to a catalog class, compares redirect_uri against the registered list, verifies PKCE (S256 / plain) from the code_verifier and code_challenge, and flags public clients without S256. Codes and verifiers are never echoed."}, traced(s.trace, "oauth_error_explain", s.oauthErrorExplain))
}
