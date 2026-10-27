// SPDX-License-Identifier: Apache-2.0

package oauth

import (
	"net"
	"net/url"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// explainer is the per-run state. Every check appends and returns; nothing
// short-circuits, so a redirect mismatch and a PKCE posture problem are both
// reported.
type explainer struct {
	s   Summary
	exp expected.Expected
	r   *finding.Report
}

// Explain parses the artifact and runs every check against the request
// context in exp.
func Explain(artifact string, exp expected.Expected) (*Result, error) {
	s, err := Parse(artifact)
	if err != nil {
		return nil, err
	}
	e := &explainer{s: s, exp: exp, r: finding.NewReport(ArtifactKind)}

	e.checkErrorClass()
	e.checkRedirectURI()
	e.checkPKCE()
	e.checkPKCEPosture()
	e.checkClientConfig()

	finding.Sort(e.r.Findings)
	return &Result{Summary: s, Report: e.r}, nil
}

func (e *explainer) add(name string, st finding.CheckStatus, detail, needs string) {
	e.r.AddCheck(finding.Check{Name: name, Status: st, Detail: detail, Needs: needs})
}

// --- error_class -------------------------------------------------------------

func (e *explainer) checkErrorClass() {
	if e.s.Error == "" {
		e.add("error_class", finding.CheckPass, "no error: success redirect carrying an authorization code", "")
		return
	}
	r, by, ok := classify(e.s)
	if !ok {
		// server_error, temporarily_unavailable or an unexplained
		// invalid_request: real, but no catalog class fits, and validators
		// never invent codes.
		e.add("error_class", finding.CheckWarn, "error="+e.s.Error+" does not map to a catalog class", "")
		return
	}
	ev := []finding.Evidence{{Path: PathError, Actual: e.s.Error, Note: "classified by " + by}}
	if e.s.ErrorDescription != "" {
		ev = append(ev, finding.Evidence{Path: PathErrorDescription, Actual: e.s.ErrorDescription, Note: e.classNote(r.code)})
	}
	f := finding.New(r.code, ev...)
	f.Confidence = r.confidence
	if e.s.VendorCode != "" {
		f.Title += " (" + e.s.VendorCode + ")"
	}
	e.r.Add(f)
	e.add("error_class", finding.CheckFail, string(r.code)+" by "+by, "")
}

// classNote adds the one hint per class that the description alone hides.
func (e *explainer) classNote(code finding.Code) string {
	d := strings.ToLower(e.s.ErrorDescription)
	switch {
	case code == finding.OAuthInvalidGrantCode && (strings.Contains(d, "redeemed") || strings.Contains(d, "reused") || strings.Contains(d, "already used")):
		return "the code was exchanged twice; a common cause is a double-fired callback effect (React StrictMode in development) or a retried request"
	case code == finding.OAuthInvalidGrantCode && strings.Contains(d, "expired"):
		return "codes live about 10 minutes or less; exchange immediately after the redirect"
	case code == finding.IdPPolicyRefusal:
		return "the IdP refused for a tenant policy reason; the exact cause needs the IdP admin's view"
	}
	return ""
}

// --- redirect_uri ------------------------------------------------------------

func (e *explainer) checkRedirectURI() {
	if len(e.exp.RegisteredRedirectURIs) == 0 {
		e.add("redirect_uri", finding.CheckSkip, "registered redirect URIs not supplied", "registered_redirect_uris")
		return
	}
	sent := e.exp.RedirectURI
	if sent == "" {
		e.add("redirect_uri", finding.CheckSkip, "redirect_uri sent in the request not supplied", "redirect_uri")
		return
	}
	// RFC 6749 3.1.2.3 and OAuth 2.1: simple string comparison, no
	// normalisation. That strictness is the whole class.
	for _, reg := range e.exp.RegisteredRedirectURIs {
		if sent == reg {
			e.add("redirect_uri", finding.CheckPass, "exact match with a registered URI", "")
			return
		}
	}
	closest, note := nearestRedirect(sent, e.exp.RegisteredRedirectURIs)
	e.r.Add(finding.New(finding.OAuthRedirectURIMismatch,
		finding.Evidence{Path: PathRequestRedirectURI, Actual: sent, Expected: closest, Note: note},
		finding.Evidence{Path: PathRequestRegisteredRedirectURIs, Actual: strings.Join(e.exp.RegisteredRedirectURIs, " ")}))
	detail := "not registered (exact string compare)"
	if note != "" {
		detail += ": " + note
	}
	e.add("redirect_uri", finding.CheckFail, detail, "")
}

// nearestRedirect returns the registered URI with a recognisable near-miss
// and names it; otherwise the first registered URI and a generic note.
func nearestRedirect(sent string, registered []string) (string, string) {
	for _, reg := range registered {
		if n := redirectDiff(sent, reg); n != "" {
			return reg, n
		}
	}
	return registered[0], "no registered URI is a near miss; register this exact URI or send a registered one"
}

// redirectDiff names the single difference between two URIs, or "".
func redirectDiff(sent, reg string) string {
	switch {
	case strings.TrimSuffix(sent, "/") == strings.TrimSuffix(reg, "/"):
		return "differs only by trailing slash"
	case strings.EqualFold(sent, reg):
		return "differs only by case (paths are case-sensitive)"
	}
	a, err1 := url.Parse(sent)
	b, err2 := url.Parse(reg)
	if err1 != nil || err2 != nil {
		return ""
	}
	samePathQuery := a.Path == b.Path && a.RawQuery == b.RawQuery
	switch {
	case samePathQuery && a.Host == b.Host && a.Scheme != b.Scheme:
		return "differs only by scheme (" + a.Scheme + " vs " + b.Scheme + ")"
	case samePathQuery && a.Scheme == b.Scheme && a.Hostname() == b.Hostname() && a.Port() != b.Port():
		n := "differs only by port (" + portOrDefault(a) + " vs " + portOrDefault(b) + ")"
		if isLoopback(a.Hostname()) {
			n += "; RFC 8252 7.3 lets native apps use any loopback port, but only if the AS implements it"
		}
		return n
	case samePathQuery && a.Scheme == b.Scheme && a.Port() == b.Port() && isLoopback(a.Hostname()) && isLoopback(b.Hostname()):
		return "localhost vs 127.0.0.1: different strings to the AS (RFC 8252 7.3 recommends 127.0.0.1)"
	case a.Scheme == b.Scheme && a.Host == b.Host && a.Path == b.Path && a.RawQuery != b.RawQuery:
		return "differs only by query string"
	case a.Scheme == b.Scheme && a.Host == b.Host && strings.EqualFold(a.Path, b.Path):
		return "differs only by path case"
	}
	return ""
}

func portOrDefault(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return "default"
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// --- client_config -----------------------------------------------------------

func (e *explainer) checkClientConfig() {
	ct, gt := e.exp.ClientType, e.exp.GrantType
	if ct == "" || gt == "" {
		e.add("client_config", finding.CheckSkip, "needs both client_type and grant_type to compare", "")
		return
	}
	if ct == "public" && gt == "client_credentials" {
		e.r.Add(finding.New(finding.OAuthClientConfigRejected,
			finding.Evidence{Path: PathRequestGrantType, Actual: gt, Expected: "authorization_code (with PKCE)",
				Note: "client_credentials requires a client secret or assertion, which a public client cannot hold (RFC 6749 4.4)"},
			finding.Evidence{Path: PathRequestClientType, Actual: ct}))
		e.add("client_config", finding.CheckFail, "public client using client_credentials", "")
		return
	}
	e.add("client_config", finding.CheckPass, ct+" client with grant_type "+gt, "")
}
