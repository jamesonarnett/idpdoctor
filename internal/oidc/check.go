// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// wellKnown is the suffix Discovery 4.1 appends to the issuer.
const wellKnown = "/.well-known/openid-configuration"

// requiredFields are the OP metadata values OIDC Discovery 3 marks REQUIRED.
// token_endpoint is REQUIRED only when the code flow is supported, so it has
// its own check.
var requiredFields = []string{
	"issuer",
	"authorization_endpoint",
	"jwks_uri",
	"response_types_supported",
	"subject_types_supported",
	"id_token_signing_alg_values_supported",
}

// offHostConfidence is lower than 1.0 because a few real OPs (Google) serve
// endpoints from a sibling domain on purpose; the finding is a prompt to
// confirm, not proof of compromise.
const offHostConfidence = 0.6

// checker is the per-run state. Every check appends and returns; nothing
// short-circuits.
type checker struct {
	m    map[string]any // nil when the body was not a JSON object
	opts Options
	s    Summary
	r    *finding.Report
}

// Check runs every discovery check. A body that is not JSON is an error
// unless it was fetched, in which case the content_type check explains it
// (a 404 HTML page is the usual cause) and the document checks skip.
func Check(doc []byte, opts Options) (*Result, error) {
	m, err := Parse(doc)
	if err != nil && !fetched(opts) {
		return nil, err
	}
	c := &checker{m: m, opts: opts, s: summarise(m, opts), r: finding.NewReport(ArtifactKind)}

	c.checkRequired()
	c.checkIssuer()
	c.checkHTTPS()
	c.checkRS256()
	c.checkEndpointHosts()
	c.checkTokenEndpoint()
	c.checkContentType()

	finding.Sort(c.r.Findings)
	return &Result{Summary: c.s, Report: c.r}, nil
}

// fetched reports whether the caller supplied HTTP metadata for the
// document. FetchedFrom alone (a doc saved by hand from a known URL)
// enables the issuer check but not the content_type check.
func fetched(o Options) bool { return o.FetchStatus != 0 || o.ContentType != "" }

func (c *checker) add(name string, st finding.CheckStatus, detail, needs string) {
	c.r.AddCheck(finding.Check{Name: name, Status: st, Detail: detail, Needs: needs})
}

// noDoc reports (and records a skip) when the body did not parse.
func (c *checker) noDoc(name string) bool {
	if c.m != nil {
		return false
	}
	c.add(name, finding.CheckSkip, "document is not a JSON object (see content_type)", "")
	return true
}

func invalid(path, actual, expected, note string) finding.Finding {
	return finding.New(finding.OIDCDiscoveryDocInvalid, finding.Evidence{Path: path, Actual: actual, Expected: expected, Note: note})
}

// --- required_fields ---------------------------------------------------------

// present treats an empty string or empty array as absent: an RP cannot use
// either.
func (c *checker) present(k string) bool {
	switch v := c.m[k].(type) {
	case string:
		return v != ""
	case []any:
		return len(v) > 0
	case nil:
		return false
	}
	return true
}

func (c *checker) checkRequired() {
	if c.noDoc("required_fields") {
		return
	}
	var missing []string
	for _, k := range requiredFields {
		if !c.present(k) {
			missing = append(missing, k)
			c.r.Add(invalid(PathDiscoveryField(k), "", "present", "REQUIRED by OIDC Discovery 3"))
		}
	}
	if len(missing) > 0 {
		c.add("required_fields", finding.CheckFail, "missing: "+strings.Join(missing, ", "), "")
		return
	}
	c.add("required_fields", finding.CheckPass, "all REQUIRED fields present", "")
}

// --- issuer_match ------------------------------------------------------------

func (c *checker) checkIssuer() {
	if c.noDoc("issuer_match") {
		return
	}
	if c.opts.ExpectedIssuer == "" && c.opts.FetchedFrom == "" {
		c.add("issuer_match", finding.CheckSkip, "issuer is "+orAbsent(c.s.Issuer), "issuer")
		return
	}
	got := c.s.Issuer
	if got == "" {
		c.add("issuer_match", finding.CheckSkip, "issuer absent (see required_fields)", "")
		return
	}
	var problems []string
	if want := c.opts.ExpectedIssuer; want != "" && got != want {
		problems = append(problems, "does not match expected issuer")
		c.r.Add(finding.New(finding.OIDCIssuerMismatch, finding.Evidence{Path: PathDiscoveryIssuer, Actual: got, Expected: want, Note: diffNote(got, want)}))
	}
	if from := c.opts.FetchedFrom; from != "" {
		prefix := strings.TrimSuffix(from, wellKnown)
		// Discovery 4.1 strips a terminating "/" before appending the
		// well-known path, so issuer "https://op/t/" is fetched from
		// "https://op/t/.well-known/..." and is still conformant.
		if got != prefix && got != prefix+"/" {
			problems = append(problems, "does not match the URL it was fetched from")
			c.r.Add(finding.New(finding.OIDCIssuerMismatch, finding.Evidence{Path: PathDiscoveryIssuer, Actual: got, Expected: prefix,
				Note: "OIDC Discovery 4.3: issuer must equal the URL the document was fetched from, minus " + wellKnown}))
		}
	}
	if len(problems) > 0 {
		c.add("issuer_match", finding.CheckFail, "issuer "+strings.Join(problems, "; "), "")
		return
	}
	c.add("issuer_match", finding.CheckPass, "issuer matches", "")
}

// diffNote names the usual near-miss so the fix is obvious.
func diffNote(got, want string) string {
	switch {
	case strings.TrimSuffix(got, "/") == strings.TrimSuffix(want, "/"):
		return "differs only by trailing slash"
	case strings.EqualFold(got, want):
		return "differs only by case"
	case strings.Contains(got, "sts.windows.net") != strings.Contains(want, "sts.windows.net"):
		return "Entra v1 (sts.windows.net) vs v2 (login.microsoftonline.com/.../v2.0) issuer"
	case strings.Contains(got, "{tenantid}"):
		return "unresolved {tenantid} placeholder: the multi-tenant /common document was used"
	}
	return ""
}

func orAbsent(s string) string {
	if s == "" {
		return "absent"
	}
	return s
}

// --- https_only --------------------------------------------------------------

// urlKeys returns issuer plus every endpoint key, sorted for stable output.
func (c *checker) urlKeys() []string {
	keys := []string{}
	for _, k := range c.s.Keys {
		if k == "issuer" || isEndpointKey(k) {
			if str(c.m, k) != "" {
				keys = append(keys, k)
			}
		}
	}
	return keys
}

func (c *checker) checkHTTPS() {
	if c.noDoc("https_only") {
		return
	}
	var bad, loopback []string
	for _, k := range c.urlKeys() {
		u, err := url.Parse(str(c.m, k))
		if err == nil && u.Scheme == "https" {
			continue
		}
		if err == nil && u.Scheme == "http" && isLoopback(u.Hostname()) {
			// A local Keycloak/dev OP is fine; production is not.
			loopback = append(loopback, k)
			continue
		}
		bad = append(bad, k)
		c.r.Add(invalid(PathDiscoveryField(k), str(c.m, k), "an https:// URL", "OIDC Discovery 3 requires https for the issuer and endpoints"))
	}
	switch {
	case len(bad) > 0:
		c.add("https_only", finding.CheckFail, "not https: "+strings.Join(bad, ", "), "")
	case len(loopback) > 0:
		c.add("https_only", finding.CheckWarn, "http on loopback (development only): "+strings.Join(loopback, ", "), "")
	default:
		c.add("https_only", finding.CheckPass, "every endpoint is https", "")
	}
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// --- rs256_present -----------------------------------------------------------

func (c *checker) checkRS256() {
	if c.noDoc("rs256_present") {
		return
	}
	if !c.present("id_token_signing_alg_values_supported") {
		c.add("rs256_present", finding.CheckSkip, "id_token_signing_alg_values_supported absent (see required_fields)", "")
		return
	}
	for _, a := range c.s.IDTokenAlgs {
		if a == "RS256" {
			c.add("rs256_present", finding.CheckPass, "RS256 supported", "")
			return
		}
	}
	c.add("rs256_present", finding.CheckFail, "RS256 not in id_token_signing_alg_values_supported", "")
	c.r.Add(invalid(PathDiscoveryField("id_token_signing_alg_values_supported"), strings.Join(c.s.IDTokenAlgs, " "), "includes RS256",
		"OIDC Discovery 3: RS256 MUST be included so every RP can validate id_tokens"))
}

// --- endpoint_hosts ----------------------------------------------------------

func (c *checker) checkEndpointHosts() {
	if c.noDoc("endpoint_hosts") {
		return
	}
	iss, err := url.Parse(c.s.Issuer)
	if c.s.Issuer == "" || err != nil || iss.Hostname() == "" {
		c.add("endpoint_hosts", finding.CheckSkip, "no usable issuer host to compare against", "")
		return
	}
	issHost := strings.ToLower(iss.Hostname())
	keys := make([]string, 0, len(c.s.Endpoints))
	for k := range c.s.Endpoints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var off, sibling []string
	for _, k := range keys {
		u, err := url.Parse(c.s.Endpoints[k])
		if err != nil {
			continue // https_only already reports unparsable URLs
		}
		h := strings.ToLower(u.Hostname())
		switch {
		case h == issHost:
		case baseDomain(h) == baseDomain(issHost):
			// login.x.com issuer with keys.x.com: same operator, just a CDN.
			sibling = append(sibling, k)
		default:
			off = append(off, k)
			f := invalid(PathDiscoveryField(k), h, issHost,
				"endpoint is served from a different domain than the issuer; confirm it is the OP's own infrastructure before trusting keys or tokens from it")
			f.Confidence = offHostConfidence
			c.r.Add(f)
		}
	}
	switch {
	case len(off) > 0:
		c.add("endpoint_hosts", finding.CheckFail, "off-host: "+strings.Join(off, ", "), "")
	case len(sibling) > 0:
		c.add("endpoint_hosts", finding.CheckWarn, "different subdomain of the issuer's domain: "+strings.Join(sibling, ", "), "")
	default:
		c.add("endpoint_hosts", finding.CheckPass, "every endpoint is on "+issHost, "")
	}
}

// baseDomain is the last two DNS labels. It is deliberately naive (no public
// suffix list, stdlib only); it only decides between warn and fail.
func baseDomain(h string) string {
	if net.ParseIP(h) != nil {
		return h
	}
	parts := strings.Split(h, ".")
	if len(parts) <= 2 {
		return h
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// --- token_endpoint ----------------------------------------------------------

func (c *checker) checkTokenEndpoint() {
	if c.noDoc("token_endpoint") {
		return
	}
	if !c.present("response_types_supported") {
		c.add("token_endpoint", finding.CheckSkip, "response_types_supported absent (see required_fields)", "")
		return
	}
	code := false
	for _, rt := range c.s.ResponseTypes {
		for _, part := range strings.Fields(rt) {
			if part == "code" {
				code = true
			}
		}
	}
	switch {
	case !code:
		c.add("token_endpoint", finding.CheckPass, "implicit-only OP; token_endpoint not required", "")
	case c.present("token_endpoint"):
		c.add("token_endpoint", finding.CheckPass, "present for the code flow", "")
	default:
		c.add("token_endpoint", finding.CheckFail, "code flow advertised but no token_endpoint", "")
		c.r.Add(invalid(PathDiscoveryField("token_endpoint"), "", "present",
			"response_types_supported includes code, so the RP must exchange codes at a token_endpoint"))
	}
}

// --- content_type ------------------------------------------------------------

func (c *checker) checkContentType() {
	if !fetched(c.opts) {
		c.add("content_type", finding.CheckSkip, "no fetch status or content type supplied (document was not fetched)", "")
		return
	}
	var problems []string
	if st := c.opts.FetchStatus; st != 0 && st != http.StatusOK {
		problems = append(problems, "HTTP "+strconv.Itoa(st))
		c.r.Add(invalid(PathDiscovery, "HTTP "+strconv.Itoa(st), "HTTP 200",
			"the discovery URL did not return the document; check the tenant segment and that the issuer URL is the OP's, not the app's"))
	}
	mt, _, err := mime.ParseMediaType(c.opts.ContentType)
	if err != nil || (mt != "application/json" && !strings.HasSuffix(mt, "+json")) {
		problems = append(problems, "content-type "+orAbsent(c.opts.ContentType))
		c.r.Add(invalid(PathDiscovery, orAbsent(c.opts.ContentType), "application/json",
			"OIDC Discovery 4.2 returns application/json; text/html usually means a login or error page was fetched instead"))
	}
	if c.m == nil {
		problems = append(problems, "body is not a JSON object")
		c.r.Add(invalid(PathDiscovery, "not JSON", "a JSON object", "the response body is not a discovery document"))
	}
	if len(problems) > 0 {
		c.add("content_type", finding.CheckFail, strings.Join(problems, "; "), "")
		return
	}
	c.add("content_type", finding.CheckPass, "HTTP 200 application/json", "")
}
