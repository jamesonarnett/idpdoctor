// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/jamesonarnett/idpdoctor/internal/cert"
	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/jwt"
	"github.com/jamesonarnett/idpdoctor/internal/redact"
	"github.com/jamesonarnett/idpdoctor/internal/saml"
)

// Every output carries Redaction = "default": a statement about the output,
// not a setting. Slices are initialised so JSON renders [] rather than null
// (the output schema says array).
const redactionDefault = "default"

// --- saml_decode ---------------------------------------------------------

type samlDecodeIn struct {
	Input    string `json:"input,omitempty" jsonschema:"the captured response: base64 POST payload, deflate+base64 redirect payload, raw XML, a full form body, or a full URL"`
	InputRef string `json:"input_ref,omitempty" jsonschema:"handle returned by stash_file; use instead of input so the assertion never enters the conversation"`
	Binding  string `json:"binding,omitempty" jsonschema:"auto (default), post, redirect or xml; forcing one makes a mismatch an error"`
}

type samlDecodeOut struct {
	BindingDetected string            `json:"binding_detected"`
	XMLPretty       string            `json:"xml_pretty"`
	Summary         *saml.Summary     `json:"summary"`
	Findings        []finding.Finding `json:"findings"`
	Text            string            `json:"text"`
	Redaction       string            `json:"redaction"`
}

func (s *Server) samlDecode(_ context.Context, _ *mcp.CallToolRequest, in samlDecodeIn) (*mcp.CallToolResult, samlDecodeOut, error) {
	raw, err := s.resolve(in.Input, in.InputRef)
	if err != nil {
		return nil, samlDecodeOut{}, err
	}
	dec, err := saml.Decode(raw, saml.Binding(strings.ToLower(in.Binding)))
	if err != nil {
		return nil, samlDecodeOut{}, err
	}
	p, err := saml.Parse(dec.XML)
	if err != nil {
		return nil, samlDecodeOut{}, err
	}
	p.Summary.RelayState = dec.RelayState
	out := samlDecodeOut{
		BindingDetected: string(dec.Binding),
		XMLPretty:       p.PrettyXML(MaxToolOutput),
		Summary:         &p.Summary,
		Findings:        p.Findings,
		Redaction:       redactionDefault,
	}
	out.Text = describeSummary(&p.Summary, dec.Binding)
	return textResult(out.Text), out, nil
}

// describeSummary is the one-paragraph prose for saml_decode.
func describeSummary(sm *saml.Summary, b saml.Binding) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "SAML Response via %s binding from issuer %s", b, sm.Issuer)
	if sm.Dialect != "" {
		fmt.Fprintf(&sb, " (%s dialect)", sm.Dialect)
	}
	fmt.Fprintf(&sb, ", status %s", lastSeg(sm.Status.Code))
	if sm.Status.SubCode != "" {
		fmt.Fprintf(&sb, "/%s", lastSeg(sm.Status.SubCode))
	}
	if sm.Destination != "" {
		fmt.Fprintf(&sb, ", destination %s", sm.Destination)
	}
	if sm.InResponseTo != "" {
		fmt.Fprintf(&sb, ", in response to %s", sm.InResponseTo)
	} else {
		sb.WriteString(", unsolicited (no InResponseTo)")
	}
	fmt.Fprintf(&sb, ". %d assertion(s), encrypted=%v, %d signature(s)", sm.AssertionCount, sm.Encrypted, len(sm.Signatures))
	for _, sig := range sm.Signatures {
		fmt.Fprintf(&sb, " [%s: %s, cert %s]", sig.On, lastSeg(sig.SigAlg), shortFP(sig.CertSHA256))
	}
	if a := sm.Assertion; a != nil {
		fmt.Fprintf(&sb, ". Audience %s; NameID %s format %s; window %s to %s; %d attribute(s): %s.",
			strings.Join(a.Conditions.Audiences, ", "), presence(a.Subject.NameIDPresent), lastSeg(a.Subject.NameIDFormat),
			a.Conditions.NotBefore, a.Conditions.NotOnOrAfter, len(a.Attributes), strings.Join(attrNames(a.Attributes), ", "))
	} else {
		sb.WriteString(".")
	}
	sb.WriteString(" Values are redacted.")
	return sb.String()
}

func presence(b bool) string {
	if b {
		return "present"
	}
	return "absent"
}

func lastSeg(s string) string {
	for _, sep := range []string{"#", ":"} {
		if i := strings.LastIndex(s, sep); i >= 0 && i < len(s)-1 {
			return s[i+1:]
		}
	}
	return s
}

func shortFP(fp string) string {
	if len(fp) > 11 {
		return fp[:11] + "..."
	}
	return fp
}

func attrNames(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// --- saml_validate -------------------------------------------------------

type samlValidateIn struct {
	Input    string            `json:"input,omitempty" jsonschema:"the captured response (any binding)"`
	InputRef string            `json:"input_ref,omitempty" jsonschema:"handle from stash_file"`
	Expected expected.Expected `json:"expected,omitempty" jsonschema:"what the SP is configured for; every field optional, missing ones skip their check"`
}

type samlValidateOut struct {
	OK        bool              `json:"ok"`
	Checks    []finding.Check   `json:"checks"`
	Findings  []finding.Finding `json:"findings"`
	Needs     []string          `json:"needs"`
	Summary   *saml.Summary     `json:"summary"`
	Text      string            `json:"text"`
	Redaction string            `json:"redaction"`
}

func (s *Server) samlValidate(ctx context.Context, _ *mcp.CallToolRequest, in samlValidateIn) (*mcp.CallToolResult, samlValidateOut, error) {
	raw, err := s.resolve(in.Input, in.InputRef)
	if err != nil {
		return nil, samlValidateOut{}, err
	}
	res, err := diag.Run(ctx, diag.Input{Artifact: raw, Kind: diag.KindSAMLResponse, Expected: in.Expected, Now: s.now()})
	if err != nil {
		return nil, samlValidateOut{}, err
	}
	out := samlValidateOut{
		OK: res.Report.OK(), Checks: res.Report.Checks, Findings: res.Report.Findings, Needs: res.Report.Needs,
		Summary: res.SAML, Text: withCitablePaths(diag.Text(res.Report, res.TopCause), res.Report), Redaction: redactionDefault,
	}
	return textResult(out.Text), out, nil
}

// --- jwt_decode ----------------------------------------------------------

type jwtDecodeIn struct {
	Token    string `json:"token,omitempty" jsonschema:"the compact JWT (a leading 'Bearer ' is tolerated)"`
	InputRef string `json:"input_ref,omitempty" jsonschema:"handle from stash_file"`
}

type jwtDecodeOut struct {
	Header       map[string]any    `json:"header"`
	Claims       jwt.Claims        `json:"claims"`
	KindGuess    string            `json:"kind_guess"`
	ExpInSeconds int64             `json:"exp_in_seconds"`
	Findings     []finding.Finding `json:"findings"`
	Text         string            `json:"text"`
	Redaction    string            `json:"redaction"`
}

func (s *Server) jwtDecode(_ context.Context, _ *mcp.CallToolRequest, in jwtDecodeIn) (*mcp.CallToolResult, jwtDecodeOut, error) {
	raw, err := s.resolve(in.Token, in.InputRef)
	if err != nil {
		return nil, jwtDecodeOut{}, err
	}
	d, err := jwt.Decode(raw, s.now())
	if err != nil {
		return nil, jwtDecodeOut{}, err
	}
	out := jwtDecodeOut{
		Header: d.Header, Claims: d.Claims, KindGuess: d.KindGuess, ExpInSeconds: d.ExpInSeconds,
		Findings: d.Findings, Redaction: redactionDefault,
	}
	iss, _ := d.Claims["iss"].(string)
	out.Text = fmt.Sprintf("JWT alg=%s kid=%s, looks like %s, iss=%s, aud=%v, exp in %ds; %d header finding(s). Claims are redacted.",
		d.Alg, d.KID, d.KindGuess, iss, d.Claims["aud"], d.ExpInSeconds, len(d.Findings))
	return textResult(out.Text), out, nil
}

// --- jwt_validate --------------------------------------------------------

type jwtValidateIn struct {
	Token    string            `json:"token,omitempty" jsonschema:"the compact JWT"`
	InputRef string            `json:"input_ref,omitempty" jsonschema:"handle from stash_file"`
	Expected expected.Expected `json:"expected,omitempty" jsonschema:"issuer, client_id/audience, nonce, allowed_algs, now, clock_skew_seconds"`
	Keys     jwt.Keys          `json:"keys,omitempty" jsonschema:"where verification keys come from: jwks_json, jwks_url (the only network call) or pem"`
}

type jwtValidateOut struct {
	OK        bool              `json:"ok"`
	Checks    []finding.Check   `json:"checks"`
	Findings  []finding.Finding `json:"findings"`
	Needs     []string          `json:"needs"`
	Header    map[string]any    `json:"header"`
	Claims    jwt.Claims        `json:"claims"`
	Text      string            `json:"text"`
	Redaction string            `json:"redaction"`
}

func (s *Server) jwtValidate(ctx context.Context, _ *mcp.CallToolRequest, in jwtValidateIn) (*mcp.CallToolResult, jwtValidateOut, error) {
	raw, err := s.resolve(in.Token, in.InputRef)
	if err != nil {
		return nil, jwtValidateOut{}, err
	}
	res, err := diag.Run(ctx, diag.Input{Artifact: raw, Kind: diag.KindJWT, Expected: in.Expected, Keys: in.Keys, Client: s.client, Now: s.now()})
	if err != nil {
		return nil, jwtValidateOut{}, err
	}
	out := jwtValidateOut{
		OK: res.Report.OK(), Checks: res.Report.Checks, Findings: res.Report.Findings, Needs: res.Report.Needs,
		Header: res.JWT.Header, Claims: res.JWT.Claims, Text: withCitablePaths(diag.Text(res.Report, res.TopCause), res.Report), Redaction: redactionDefault,
	}
	return textResult(out.Text), out, nil
}

// --- cert_inspect --------------------------------------------------------

type certInspectIn struct {
	Cert string `json:"cert" jsonschema:"PEM certificate or bare base64 DER as found in metadata X509Certificate"`
	Now  string `json:"now,omitempty" jsonschema:"RFC 3339 time to evaluate validity at"`
}

type certInspectOut struct {
	cert.Info
	Text      string `json:"text"`
	Redaction string `json:"redaction"`
}

func (s *Server) certInspect(_ context.Context, _ *mcp.CallToolRequest, in certInspectIn) (*mcp.CallToolResult, certInspectOut, error) {
	now, err := (expected.Expected{Now: in.Now}).NowOr(s.now())
	if err != nil {
		return nil, certInspectOut{}, err
	}
	c, err := cert.Parse(in.Cert)
	if err != nil {
		return nil, certInspectOut{}, err
	}
	info := cert.Inspect(c, now)
	out := certInspectOut{Info: info, Redaction: redactionDefault}
	out.Text = fmt.Sprintf("Certificate %s, issued by %s, %s %d-bit, %s, valid %s to %s (%d days remaining), sha256 %s; %d finding(s).",
		info.Subject, info.Issuer, info.KeyAlg, info.KeyBits, info.SigAlg, info.NotBefore, info.NotAfter, info.DaysRemaining, shortFP(info.SHA256), len(info.Findings))
	return textResult(out.Text), out, nil
}

// --- diagnose ------------------------------------------------------------

type diagnoseIn struct {
	Artifact     string            `json:"artifact,omitempty" jsonschema:"the artifact text (SAML response in any binding, JWT, or certificate)"`
	InputRef     string            `json:"input_ref,omitempty" jsonschema:"handle from stash_file"`
	ArtifactKind string            `json:"artifact_kind,omitempty" jsonschema:"auto (default), saml_response, jwt or cert"`
	Symptom      string            `json:"symptom,omitempty" jsonschema:"the error the developer sees; recorded, not interpreted by this deterministic tool"`
	Expected     expected.Expected `json:"expected,omitempty" jsonschema:"what the SP is configured for"`
	Keys         jwt.Keys          `json:"keys,omitempty" jsonschema:"JWT verification keys"`
}

type diagnoseOut struct {
	ArtifactKind string            `json:"artifact_kind"`
	Findings     []finding.Finding `json:"findings"`
	TopCause     *finding.Finding  `json:"top_cause"`
	Checks       []finding.Check   `json:"checks"`
	Needs        []string          `json:"needs"`
	Text         string            `json:"text"`
	Redaction    string            `json:"redaction"`
}

func (s *Server) diagnose(ctx context.Context, _ *mcp.CallToolRequest, in diagnoseIn) (*mcp.CallToolResult, diagnoseOut, error) {
	raw, err := s.resolve(in.Artifact, in.InputRef)
	if err != nil {
		return nil, diagnoseOut{}, err
	}
	res, err := diag.Run(ctx, diag.Input{
		Artifact: raw, Kind: diag.Kind(in.ArtifactKind), Symptom: in.Symptom,
		Expected: in.Expected, Keys: in.Keys, Client: s.client, Now: s.now(),
	})
	if err != nil {
		return nil, diagnoseOut{}, err
	}
	out := diagnoseOut{
		ArtifactKind: string(res.Kind), Findings: res.Report.Findings, TopCause: res.TopCause,
		Checks: res.Report.Checks, Needs: res.Report.Needs, Text: withCitablePaths(diag.Text(res.Report, res.TopCause), res.Report), Redaction: redactionDefault,
	}
	return textResult(out.Text), out, nil
}

// --- stash_file ----------------------------------------------------------

type stashFileIn struct {
	Path string `json:"path" jsonschema:"local path of the file the developer saved the capture to"`
}

type stashFileOut struct {
	InputRef        string `json:"input_ref"`
	ArtifactKind    string `json:"artifact_kind"`
	Bytes           int    `json:"bytes"`
	RedactedPreview string `json:"redacted_preview"`
	Redaction       string `json:"redaction"`
}

// maxStash bounds what stash_file will read; matches saml.MaxInput.
const maxStash = saml.MaxInput

func (s *Server) stashFile(_ context.Context, _ *mcp.CallToolRequest, in stashFileIn) (*mcp.CallToolResult, stashFileOut, error) {
	st, err := os.Stat(in.Path)
	if err != nil {
		return nil, stashFileOut{}, err
	}
	if st.IsDir() || st.Size() > maxStash {
		return nil, stashFileOut{}, fmt.Errorf("stash_file: %s is a directory or larger than %d bytes", in.Path, maxStash)
	}
	data, err := os.ReadFile(in.Path)
	if err != nil {
		return nil, stashFileOut{}, err
	}
	ref := s.store.Put(data)
	kind := diag.Sniff(string(data))
	out := stashFileOut{InputRef: ref, ArtifactKind: string(kind), Bytes: len(data), RedactedPreview: preview(kind, data), Redaction: redactionDefault}
	text := fmt.Sprintf("Stashed %d bytes as %s (looks like %s). Pass input_ref=%q to saml_decode, saml_validate, jwt_decode, jwt_validate or diagnose. Preview: %s",
		len(data), ref, kind, ref, out.RedactedPreview)
	return textResult(text), out, nil
}

// preview is a short, redacted glimpse so the agent can confirm it stashed
// the right file. For a SAML response that is the redacted pretty XML head;
// for a JWT the header only; anything else just its kind.
func preview(kind diag.Kind, data []byte) string {
	const n = 300
	switch kind {
	case diag.KindSAMLResponse:
		dec, err := saml.Decode(string(data), saml.BindingAuto)
		if err != nil {
			return "undecodable SAML payload: " + err.Error()
		}
		p, err := saml.Parse(dec.XML)
		if err != nil {
			return "unparsable XML: " + err.Error()
		}
		return redact.Truncate(p.PrettyXML(n), n)
	case diag.KindJWT:
		d, err := jwt.Decode(string(data), s0)
		if err != nil {
			return "unparsable JWT"
		}
		h, _ := json.Marshal(d.Header)
		return "header " + string(h)
	}
	return string(kind)
}

func (s *Server) registerTools() {
	mcp.AddTool(s.mcp, &mcp.Tool{Name: "saml_decode", Description: "Decode a SAML Response from any binding and summarise it (issuer, status, audience, NameID presence/format, conditions, signatures, attribute names). Values are redacted."}, traced(s.trace, "saml_decode", s.samlDecode))
	mcp.AddTool(s.mcp, &mcp.Tool{Name: "saml_validate", Description: "Run every SAML check (status, issuer, destination, in_response_to, signatures, cert, audience, recipient, time window, NameID, attributes, structure) against the SP's expected values. Reports pass/fail/skip per check and findings with evidence paths and fixes. Never stops at the first failure."}, traced(s.trace, "saml_validate", s.samlValidate))
	mcp.AddTool(s.mcp, &mcp.Tool{Name: "jwt_decode", Description: "Decode a JWT without verifying: header, redacted claims, kind guess, time to expiry, header red flags (alg none, jku/jwk/x5u)."}, traced(s.trace, "jwt_decode", s.jwtDecode))
	mcp.AddTool(s.mcp, &mcp.Tool{Name: "jwt_validate", Description: "Validate a JWT against a JWKS (inline or URL) or PEM key with an algorithm allow-list, then check iss, aud/azp, exp/nbf/iat, nonce and at_hash individually."}, traced(s.trace, "jwt_validate", s.jwtValidate))
	mcp.AddTool(s.mcp, &mcp.Tool{Name: "cert_inspect", Description: "Inspect an X.509 certificate (PEM or metadata base64): subject, validity, key size, fingerprints, expiry and weakness findings."}, traced(s.trace, "cert_inspect", s.certInspect))
	mcp.AddTool(s.mcp, &mcp.Tool{Name: "diagnose", Description: "Sniff the artifact kind (SAML response, JWT, certificate, OIDC discovery document, OAuth error redirect or token-endpoint error body), run every applicable check, and return ranked findings with a top cause. Deterministic; the best first call."}, traced(s.trace, "diagnose", s.diagnose))
	mcp.AddTool(s.mcp, &mcp.Tool{Name: "stash_file", Description: "Read a local capture file into server memory and return an opaque input_ref plus a redacted preview, so the raw assertion or token never has to be pasted into this conversation."}, traced(s.trace, "stash_file", s.stashFile))
	s.registerV1Tools()
}
