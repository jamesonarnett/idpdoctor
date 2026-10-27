// SPDX-License-Identifier: Apache-2.0

package saml

import (
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jamesonarnett/idpdoctor/internal/cert"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
)

// ArtifactKind is the Report label for SAML Responses.
const ArtifactKind = "saml_response"

// Posture thresholds (BUILD_PLAN 3.1).
const (
	maxAssertionWindow = 10 * time.Minute
	maxSessionLength   = 24 * time.Hour
	minAssertionWindow = 2 * time.Minute
)

// validator is the per-run state. Every check appends to the report and
// returns; nothing short-circuits, because the product is "explain every
// failure separately".
type validator struct {
	p    *Parsed
	exp  expected.Expected
	now  time.Time
	skew time.Duration
	r    *finding.Report
}

// Validate runs every applicable check against the parsed Response and
// returns a Report. now is the wall clock unless exp.Now overrides it.
func Validate(p *Parsed, exp expected.Expected, now time.Time) (*finding.Report, error) {
	effective, err := exp.NowOr(now)
	if err != nil {
		return nil, err
	}
	v := &validator{p: p, exp: exp, now: effective, skew: exp.Skew(), r: finding.NewReport(ArtifactKind)}

	// Parse-level findings (DOCTYPE, comments, multi-assertion) come first.
	for _, f := range p.Findings {
		v.r.Add(f)
	}

	v.checkStatus()
	v.checkIssuer()
	v.checkDestination()
	v.checkInResponseTo()
	v.checkSignatures() // presence, placement, verify, cert_validity
	v.checkAudience()
	v.checkRecipient()
	v.checkTimeWindow()
	v.checkNameID()
	v.checkAttributes()
	v.checkStructure()

	finding.Sort(v.r.Findings)
	return v.r, nil
}

func (v *validator) pass(name, detail string) {
	v.r.AddCheck(finding.Check{Name: name, Status: finding.CheckPass, Detail: detail})
}

func (v *validator) fail(name, detail string) {
	v.r.AddCheck(finding.Check{Name: name, Status: finding.CheckFail, Detail: detail})
}

func (v *validator) warn(name, detail string) {
	v.r.AddCheck(finding.Check{Name: name, Status: finding.CheckWarn, Detail: detail})
}

func (v *validator) skip(name, needs, detail string) {
	v.r.AddCheck(finding.Check{Name: name, Status: finding.CheckSkip, Needs: needs, Detail: detail})
}

func (v *validator) assertion() *Assertion { return v.p.Summary.Assertion }

// --- status ---------------------------------------------------------------

func (v *validator) checkStatus() {
	st := v.p.Summary.Status
	if st.Code == StatusSuccess {
		v.pass("status", "Success")
		return
	}
	if st.Code == "" {
		v.fail("status", "no StatusCode")
		v.r.Add(finding.New(finding.SAMLStructureInvalid, finding.Evidence{Path: PathStatusCode, Actual: "", Expected: StatusSuccess}))
		return
	}
	v.fail("status", shortURN(st.Code)+subcodeSuffix(st.SubCode))
	ev := []finding.Evidence{{Path: PathStatusCode, Actual: st.Code, Expected: StatusSuccess}}
	if st.SubCode != "" {
		ev = append(ev, finding.Evidence{Path: PathStatusSubCode, Actual: st.SubCode})
	}
	if st.Message != "" {
		ev = append(ev, finding.Evidence{Path: PathStatusMessage, Actual: st.Message})
	}
	f := finding.New(finding.SAMLStatusNotSuccess, ev...)
	f.Title = "IdP returned " + shortURN(st.Code) + subcodeSuffix(st.SubCode)
	v.r.Add(f)
}

func subcodeSuffix(sub string) string {
	if sub == "" {
		return ""
	}
	return " / " + shortURN(sub)
}

// shortURN keeps the last segment of a SAML status URN for humans.
func shortURN(u string) string {
	if i := strings.LastIndex(u, ":"); i >= 0 && i < len(u)-1 {
		return u[i+1:]
	}
	return u
}

// --- issuer ---------------------------------------------------------------

func (v *validator) checkIssuer() {
	want := v.exp.IdPEntityID
	if want == "" {
		v.skip("issuer", "idp_entity_id", "Issuer is "+v.p.Summary.Issuer)
		return
	}
	ok := true
	if got := v.p.Summary.Issuer; got != want {
		ok = false
		v.r.Add(finding.New(finding.SAMLIssuerMismatch, finding.Evidence{Path: PathResponseIssuer, Actual: got, Expected: want, Note: diffNote(got, want)}))
	}
	if a := v.assertion(); a != nil && a.Issuer != "" && a.Issuer != want && a.Issuer != v.p.Summary.Issuer {
		ok = false
		v.r.Add(finding.New(finding.SAMLIssuerMismatch, finding.Evidence{Path: PathAssertionIssuer, Actual: a.Issuer, Expected: want, Note: diffNote(a.Issuer, want)}))
	}
	if ok {
		v.pass("issuer", "matches idp_entity_id")
	} else {
		v.fail("issuer", "does not match idp_entity_id")
	}
}

// diffNote names the usual near-miss so the fix is obvious.
func diffNote(got, want string) string {
	switch {
	case got == "":
		return "value absent"
	case strings.TrimSuffix(got, "/") == strings.TrimSuffix(want, "/"):
		return "differs only by trailing slash"
	case strings.EqualFold(got, want):
		return "differs only by case"
	case strings.TrimPrefix(strings.TrimPrefix(got, "https://"), "http://") == strings.TrimPrefix(strings.TrimPrefix(want, "https://"), "http://"):
		return "differs only by scheme (http vs https)"
	case strings.Contains(got, "staging") || strings.Contains(got, "dev") || strings.Contains(got, "test"):
		return "looks like a different environment"
	}
	return ""
}

// --- destination / recipient -----------------------------------------------

func (v *validator) checkDestination() {
	want := v.exp.ACSURL
	got := v.p.Summary.Destination
	if want == "" {
		v.skip("destination", "acs_url", "Destination is "+orAbsent(got))
		return
	}
	switch {
	case got == want:
		v.pass("destination", "matches acs_url")
	case got == "" && v.responseSigned():
		// SAML core 3.2.2: Destination is required when the Response is signed.
		v.fail("destination", "absent on a signed Response")
		v.r.Add(finding.New(finding.SAMLDestinationOrRecipientMismatch, finding.Evidence{Path: PathResponseDestination, Actual: "", Expected: want, Note: "Destination is required on a signed Response"}))
	case got == "":
		v.warn("destination", "absent (allowed on an unsigned Response)")
	default:
		v.fail("destination", "does not match acs_url")
		v.r.Add(finding.New(finding.SAMLDestinationOrRecipientMismatch, finding.Evidence{Path: PathResponseDestination, Actual: got, Expected: want, Note: diffNote(got, want)}))
	}
}

func (v *validator) checkRecipient() {
	a := v.assertion()
	if a == nil {
		v.skip("recipient", "", "no assertion")
		return
	}
	want := v.exp.ACSURL
	got := a.SubjectConfirmation.Recipient
	if want == "" {
		v.skip("recipient", "acs_url", "Recipient is "+orAbsent(got))
		return
	}
	if got == "" {
		v.warn("recipient", "SubjectConfirmationData has no Recipient")
		return
	}
	if got != want {
		v.fail("recipient", "does not match acs_url")
		v.r.Add(finding.New(finding.SAMLDestinationOrRecipientMismatch, finding.Evidence{Path: PathRecipient, Actual: got, Expected: want, Note: diffNote(got, want)}))
		return
	}
	v.pass("recipient", "matches acs_url")
}

func orAbsent(s string) string {
	if s == "" {
		return "absent"
	}
	return s
}

// --- InResponseTo -----------------------------------------------------------

func (v *validator) checkInResponseTo() {
	got := v.p.Summary.InResponseTo
	want := v.exp.RequestID
	if want == "" {
		detail := "InResponseTo is " + orAbsent(got)
		if got == "" {
			detail += " (IdP-initiated); supply request_id if the SP sent an AuthnRequest"
		}
		v.skip("in_response_to", "request_id", detail)
		return
	}
	switch {
	case got == "":
		v.fail("in_response_to", "absent: unsolicited response but the SP sent a request")
		v.r.Add(finding.New(finding.SAMLInResponseToMismatch, finding.Evidence{Path: PathResponseInResponseTo, Actual: "", Expected: want, Note: "IdP-initiated response received by an SP that started an SP-initiated flow"}))
	case got != want:
		v.fail("in_response_to", "does not match request_id")
		v.r.Add(finding.New(finding.SAMLInResponseToMismatch, finding.Evidence{Path: PathResponseInResponseTo, Actual: got, Expected: want, Note: "stale or cross-tab request; the SP must look the ID up in its own session"}))
	default:
		if a := v.assertion(); a != nil && a.SubjectConfirmation.InResponseTo != "" && a.SubjectConfirmation.InResponseTo != want {
			v.fail("in_response_to", "SubjectConfirmationData/@InResponseTo does not match request_id")
			v.r.Add(finding.New(finding.SAMLInResponseToMismatch, finding.Evidence{Path: PathSCDInResponseTo, Actual: a.SubjectConfirmation.InResponseTo, Expected: want}))
			return
		}
		v.pass("in_response_to", "matches request_id")
	}
}

// --- signatures -------------------------------------------------------------

func (v *validator) responseSigned() bool {
	for _, s := range v.p.Summary.Signatures {
		if s.On == "response" {
			return true
		}
	}
	return false
}

func (v *validator) assertionSigned() bool {
	for _, s := range v.p.Summary.Signatures {
		if s.On == "assertion" {
			return true
		}
	}
	return false
}

func (v *validator) checkSignatures() {
	rs, as := v.responseSigned(), v.assertionSigned()
	hasAssertion := len(v.p.Assertions) > 0

	// Presence.
	switch {
	case !rs && !as && !hasAssertion:
		// Error responses are routinely unsigned; status already failed.
		v.skip("signature_present", "", "no signature; error response without assertion")
	case !rs && !as:
		v.fail("signature_present", "neither Response nor Assertion is signed")
		v.r.Add(finding.New(finding.SAMLNotSignedOrWrongElementSigned, finding.Evidence{Path: PathAssertionSignature, Actual: "no signature", Expected: "signed Assertion (and/or Response)"}))
	default:
		v.pass("signature_present", describeSigned(rs, as))
	}

	// Placement against SP requirements.
	reqA := expected.Bool(v.exp.RequireSignedAssertion, false)
	reqR := expected.Bool(v.exp.RequireSignedResponse, false)
	switch {
	case !rs && !as:
		v.skip("signature_placement", "", "nothing signed")
	case reqA && !as:
		v.fail("signature_placement", "SP requires a signed Assertion; only the Response is signed")
		v.r.Add(finding.New(finding.SAMLNotSignedOrWrongElementSigned, finding.Evidence{Path: PathAssertionSignature, Actual: "Response signed, Assertion unsigned", Expected: "signed Assertion"}))
	case reqR && !rs:
		v.fail("signature_placement", "SP requires a signed Response; only the Assertion is signed")
		v.r.Add(finding.New(finding.SAMLNotSignedOrWrongElementSigned, finding.Evidence{Path: PathResponseSignature, Actual: "Assertion signed, Response unsigned", Expected: "signed Response"}))
	case !as && hasAssertion && v.exp.RequireSignedAssertion == nil:
		// Works, but only safely if the SP consumes nothing outside the signed Response.
		v.warn("signature_placement", "Assertion unsigned inside a signed Response; SP must not require it")
		v.r.Add(finding.New(finding.PostureUnsignedAssertionAccepted, finding.Evidence{Path: PathAssertionSignature, Actual: "unsigned", Note: "only the Response is signed and require_signed_assertion was not stated"}))
	case !as && hasAssertion && !reqA:
		v.warn("signature_placement", "SP accepts an unsigned Assertion")
		v.r.Add(finding.New(finding.PostureUnsignedAssertionAccepted, finding.Evidence{Path: PathAssertionSignature, Actual: "unsigned", Expected: "signed", Note: "require_signed_assertion is false"}))
	default:
		v.pass("signature_placement", describeSigned(rs, as))
	}

	// Algorithms (posture lane regardless of verification outcome).
	for _, s := range v.p.Summary.Signatures {
		if isSHA1Alg(s.SigAlg) || isSHA1Alg(s.DigestAlg) {
			v.r.Add(finding.New(finding.PostureWeakAlgorithm, finding.Evidence{Path: "/" + sigPathPrefix(s.On) + PathSignatureMethod, Actual: firstNonEmpty(sha1Of(s.SigAlg), sha1Of(s.DigestAlg)), Expected: "RSA-SHA256 / SHA-256"}))
		}
	}

	v.verifySignatures(rs, as)
}

func describeSigned(rs, as bool) string {
	switch {
	case rs && as:
		return "Response and Assertion signed"
	case rs:
		return "Response signed"
	case as:
		return "Assertion signed"
	}
	return "unsigned"
}

func sigPathPrefix(on string) string {
	if on == "assertion" {
		return "Response/Assertion"
	}
	return "Response"
}

func sha1Of(alg string) string {
	if isSHA1Alg(alg) {
		return alg
	}
	return ""
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// verifySignatures does the cryptographic check against the configured
// cert, or falls back to a self-consistency check against the embedded one.
func (v *validator) verifySignatures(rs, as bool) {
	if !rs && !as {
		v.skip("signature_verify", "", "nothing to verify")
		v.skip("cert_validity", "", "no signing certificate")
		return
	}

	var trusted *x509.Certificate
	if v.exp.IdPCertPEM != "" {
		c, err := cert.Parse(v.exp.IdPCertPEM)
		if err != nil {
			v.fail("signature_verify", "idp_cert_pem could not be parsed: "+err.Error())
			v.r.Add(finding.New(finding.CertExpiredOrWeak, finding.Evidence{Path: "/expected/idp_cert_pem", Note: err.Error()}))
			return
		}
		trusted = c
	}

	embedded := v.firstEmbeddedCert()
	if trusted == nil {
		// Self-consistency only: proves the bytes were not altered after
		// signing, proves nothing about who signed.
		if embedded == nil {
			v.skip("signature_verify", "idp_cert_pem", "no certificate configured and none embedded in KeyInfo")
			v.skip("cert_validity", "idp_cert_pem", "")
			return
		}
		v.r.Add(finding.New(finding.PostureEmbeddedKeyTrust, finding.Evidence{Path: PathKeyInfoCertificate, Actual: cert.FingerprintSHA256(embedded), Note: "no idp_cert_pem supplied; only the sender's embedded certificate is available"}))
		res := v.verifyAll(rs, as, embedded)
		if res.Err != nil {
			v.fail("signature_verify", "does not verify even against its own embedded certificate: content was altered after signing")
			v.r.Add(finding.New(finding.SAMLSignatureInvalid, finding.Evidence{Path: v.sigPath(rs, as), Actual: "digest or signature mismatch against embedded KeyInfo cert", Note: "tampered or re-serialised after signing"}))
		} else {
			v.skip("signature_verify", "idp_cert_pem", "self-consistent against embedded certificate; supply idp_cert_pem to verify trust")
		}
		v.checkCertValidity(embedded, res)
		return
	}

	// Trusted cert supplied.
	if embedded != nil && cert.FingerprintSHA256(embedded) != cert.FingerprintSHA256(trusted) {
		v.r.Add(finding.New(finding.SAMLSignatureInvalid, finding.Evidence{
			Path: PathKeyInfoCertificate, Actual: cert.FingerprintSHA256(embedded), Expected: cert.FingerprintSHA256(trusted),
			Note: "KeyInfo certificate differs from the configured IdP certificate; the IdP rotated keys or this is a different IdP",
		}))
	}
	res := v.verifyAll(rs, as, trusted)
	switch {
	case res.Err == nil:
		v.pass("signature_verify", "verified against idp_cert_pem")
	case errors.Is(res.Err, ErrSigUntrusted):
		v.fail("signature_verify", "signed by a certificate other than idp_cert_pem")
		if embedded == nil {
			v.r.Add(finding.New(finding.SAMLSignatureInvalid, finding.Evidence{Path: v.sigPath(rs, as), Actual: "untrusted signer", Expected: cert.FingerprintSHA256(trusted)}))
		}
	default:
		v.fail("signature_verify", "signature invalid: "+res.Err.Error())
		v.r.Add(finding.New(finding.SAMLSignatureInvalid, finding.Evidence{Path: v.sigPath(rs, as), Actual: "digest or signature mismatch", Expected: "verifies with " + cert.FingerprintSHA256(trusted)}))
	}
	v.checkCertValidity(trusted, res)
}

// verifyAll verifies every signed element; the first error wins but the
// Response and each Assertion are all attempted.
func (v *validator) verifyAll(rs, as bool, c *x509.Certificate) VerifyResult {
	var out VerifyResult
	if rs {
		out = verifyElement(v.p.Response, c, v.now)
		if out.Err != nil {
			return out
		}
	}
	if as {
		for _, a := range v.p.Assertions {
			if child(a, NSDSig, "Signature") == nil {
				continue
			}
			r := verifyElement(a, c, v.now)
			if r.Err != nil {
				return r
			}
			out = r
		}
	}
	return out
}

func (v *validator) sigPath(rs, as bool) string {
	if as {
		return PathAssertionSignature
	}
	return PathResponseSignature
}

func (v *validator) firstEmbeddedCert() *x509.Certificate {
	for _, s := range v.p.Summary.Signatures {
		if s.Cert != nil {
			return s.Cert
		}
	}
	return nil
}

// checkCertValidity reports expiry/weakness of the signing cert at now and,
// when the signature nonetheless verified, the posture finding.
func (v *validator) checkCertValidity(c *x509.Certificate, res VerifyResult) {
	info := cert.Inspect(c, v.now)
	if len(info.Findings) == 0 {
		v.pass("cert_validity", fmt.Sprintf("valid until %s (%d days)", info.NotAfter, info.DaysRemaining))
		return
	}
	v.fail("cert_validity", "signing certificate expired, not yet valid or weak")
	for _, f := range info.Findings {
		for i := range f.Evidence {
			f.Evidence[i].Path = PathKeyInfoCertificate + strings.TrimPrefix(f.Evidence[i].Path, "/Certificate")
		}
		if res.CertExpiredAtNow && res.Err == nil {
			// The crypto checks out; whether the SP rejects an expired cert is
			// policy. That is the posture lane's job, so the fault is a warning.
			f.Severity = finding.SeverityWarn
		}
		v.r.Add(f)
	}
	if res.CertExpiredAtNow && res.Err == nil {
		v.r.Add(finding.New(finding.PostureExpiredCertAccepted, finding.Evidence{Path: PathKeyInfoCertificate + "/NotAfter", Actual: info.NotAfter, Expected: "> " + v.now.UTC().Format(time.RFC3339), Note: "signature verifies; an SP that accepts this is trusting an expired key"}))
	}
}

// --- audience ---------------------------------------------------------------

func (v *validator) checkAudience() {
	a := v.assertion()
	if a == nil {
		v.skip("audience", "", "no assertion")
		return
	}
	want := v.exp.SPEntityID
	auds := a.Conditions.Audiences
	if want == "" {
		v.skip("audience", "sp_entity_id", "audiences: "+strings.Join(auds, ", "))
		return
	}
	if len(auds) == 0 {
		v.fail("audience", "no AudienceRestriction")
		v.r.Add(finding.New(finding.SAMLAudienceMismatch, finding.Evidence{Path: PathAudience, Actual: "", Expected: want, Note: "no Audience element"}))
		return
	}
	for _, got := range auds {
		if got == want {
			v.pass("audience", "matches sp_entity_id")
			return
		}
	}
	v.fail("audience", "does not match sp_entity_id")
	v.r.Add(finding.New(finding.SAMLAudienceMismatch, finding.Evidence{Path: PathAudience, Actual: strings.Join(auds, ", "), Expected: want, Note: diffNote(auds[0], want)}))
}

// --- time window ------------------------------------------------------------

func (v *validator) checkTimeWindow() {
	a := v.assertion()
	if a == nil {
		v.skip("time_window", "", "no assertion")
		return
	}
	nb, nbErr := parseSAMLTime(a.Conditions.NotBefore)
	noa, noaErr := parseSAMLTime(a.Conditions.NotOnOrAfter)
	scd, scdErr := parseSAMLTime(a.SubjectConfirmation.NotOnOrAfter)
	ok := true
	nowStr := v.now.UTC().Format(time.RFC3339)

	if a.Conditions.NotBefore != "" && nbErr != nil {
		ok = false
		v.r.Add(finding.New(finding.SAMLTimeWindowInvalid, finding.Evidence{Path: PathConditionsNotBefore, Actual: a.Conditions.NotBefore, Note: "unparsable timestamp"}))
	}
	if nbErr == nil && a.Conditions.NotBefore != "" && nb.After(v.now.Add(v.skew)) {
		ok = false
		v.r.Add(finding.New(finding.SAMLTimeWindowInvalid, finding.Evidence{Path: PathConditionsNotBefore, Actual: a.Conditions.NotBefore, Expected: "<= " + nowStr + " + skew " + v.skew.String(), Note: "assertion not yet valid: IdP clock ahead, or the capture is being replayed from before it was issued"}))
	}
	if noaErr == nil && a.Conditions.NotOnOrAfter != "" && !noa.After(v.now.Add(-v.skew)) {
		ok = false
		v.r.Add(finding.New(finding.SAMLTimeWindowInvalid, finding.Evidence{Path: PathConditionsNotOnOrAfter, Actual: a.Conditions.NotOnOrAfter, Expected: "> " + nowStr + " - skew " + v.skew.String(), Note: "assertion expired " + v.now.Sub(noa).Round(time.Second).String() + " before now"}))
	}
	if scdErr == nil && a.SubjectConfirmation.NotOnOrAfter != "" && !scd.After(v.now.Add(-v.skew)) {
		ok = false
		v.r.Add(finding.New(finding.SAMLTimeWindowInvalid, finding.Evidence{Path: PathSCDNotOnOrAfter, Actual: a.SubjectConfirmation.NotOnOrAfter, Expected: "> " + nowStr + " - skew " + v.skew.String()}))
	}
	if !ok {
		v.fail("time_window", "outside validity window at "+nowStr)
	} else if a.Conditions.NotOnOrAfter == "" && a.SubjectConfirmation.NotOnOrAfter == "" {
		v.warn("time_window", "no NotOnOrAfter anywhere; assertion never expires")
		v.r.Add(finding.New(finding.PostureValidityWindowTooLong, finding.Evidence{Path: PathConditionsNotOnOrAfter, Actual: "", Expected: "<= " + maxAssertionWindow.String()}))
	} else {
		v.pass("time_window", "valid at "+nowStr)
	}

	// Posture: window length and session length.
	if nbErr == nil && noaErr == nil && a.Conditions.NotBefore != "" && a.Conditions.NotOnOrAfter != "" {
		window := noa.Sub(nb)
		if window > maxAssertionWindow {
			v.r.Add(finding.New(finding.PostureValidityWindowTooLong, finding.Evidence{Path: PathConditionsNotOnOrAfter, Actual: window.String(), Expected: "<= " + maxAssertionWindow.String(), Note: "long windows widen the replay surface"}))
		} else if window < minAssertionWindow && ok {
			v.warn("time_window", "window is only "+window.String()+"; small clock drift will break logins")
		}
	}
	if a.SessionNotOnOrAfter != "" {
		if sess, err := parseSAMLTime(a.SessionNotOnOrAfter); err == nil && sess.Sub(v.now) > maxSessionLength {
			v.r.Add(finding.New(finding.PostureValidityWindowTooLong, finding.Evidence{Path: PathSessionNotOnOrAfter, Actual: a.SessionNotOnOrAfter, Expected: "<= now + " + maxSessionLength.String()}))
		}
	}
}

// parseSAMLTime accepts xs:dateTime with or without fractional seconds.
func parseSAMLTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("empty")
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparsable time %q", s)
}

// --- NameID -----------------------------------------------------------------

func (v *validator) checkNameID() {
	a := v.assertion()
	if a == nil {
		v.skip("name_id", "", "no assertion")
		return
	}
	switch {
	case !a.Subject.NameIDPresent:
		v.fail("name_id", "NameID absent")
		v.r.Add(finding.New(finding.SAMLNameIDMissingOrFormatMismatch, finding.Evidence{Path: PathNameID, Actual: "", Expected: "a stable user identifier", Note: "no NameID element in Subject"}))
		return
	case a.Subject.NameID == "":
		v.fail("name_id", "NameID empty")
		v.r.Add(finding.New(finding.SAMLNameIDMissingOrFormatMismatch, finding.Evidence{Path: PathNameID, Actual: "", Expected: "non-empty", Note: "NameID element present but empty"}))
		return
	}
	if want := v.exp.NameIDFormat; want != "" && a.Subject.NameIDFormat != want {
		v.fail("name_id", "Format does not match name_id_format")
		v.r.Add(finding.New(finding.SAMLNameIDMissingOrFormatMismatch, finding.Evidence{Path: PathNameIDFormat, Actual: orAbsent(a.Subject.NameIDFormat), Expected: want}))
		return
	}
	detail := "present, format " + orAbsent(shortURN(a.Subject.NameIDFormat))
	if strings.HasSuffix(a.Subject.NameIDFormat, ":transient") {
		detail += " (transient: changes per login; SP must not key users on it)"
	}
	v.pass("name_id", detail)
}

// --- attributes -------------------------------------------------------------

func (v *validator) checkAttributes() {
	a := v.assertion()
	if a == nil {
		v.skip("attributes", "", "no assertion")
		return
	}
	names := sortedNames(a.Attributes)
	if len(v.exp.RequiredAttributes) == 0 {
		v.skip("attributes", "required_attributes", fmt.Sprintf("%d attributes present: %s", len(names), strings.Join(names, ", ")))
		return
	}
	if !a.AttributeStatementPresent {
		v.fail("attributes", "no AttributeStatement")
		v.r.Add(finding.New(finding.SAMLRequiredAttributeMissing, finding.Evidence{Path: PathAttributeStatement, Actual: "", Expected: strings.Join(v.exp.RequiredAttributes, ", "), Note: "no AttributeStatement at all"}))
		return
	}
	missing := 0
	for _, want := range v.exp.RequiredAttributes {
		vals, ok := a.Attributes[want]
		switch {
		case !ok:
			missing++
			v.r.Add(finding.New(finding.SAMLRequiredAttributeMissing, finding.Evidence{Path: PathAttribute(want), Actual: "", Expected: want, Note: nearMiss(want, names)}))
		case allEmpty(vals):
			missing++
			v.r.Add(finding.New(finding.SAMLRequiredAttributeMissing, finding.Evidence{Path: PathAttribute(want), Actual: "(empty)", Expected: "non-empty value", Note: "attribute present but every value is empty"}))
		}
	}
	if missing > 0 {
		v.fail("attributes", fmt.Sprintf("%d of %d required attributes missing or empty", missing, len(v.exp.RequiredAttributes)))
		return
	}
	v.pass("attributes", "all required attributes present")
}

// nearMiss points at a case- or namespace-variant of the missing name.
func nearMiss(want string, present []string) string {
	for _, p := range present {
		if strings.EqualFold(p, want) {
			return "present as " + p + " (case differs)"
		}
		if strings.HasSuffix(strings.ToLower(p), "/"+strings.ToLower(want)) {
			return "present as " + p + " (namespaced claim URI; SP expects the short name)"
		}
	}
	return "absent; present attributes: " + strings.Join(present, ", ")
}

func allEmpty(vals []string) bool {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return false
		}
	}
	return true
}

func sortedNames(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- structure ---------------------------------------------------------------

func (v *validator) checkStructure() {
	s := v.p.Summary
	switch {
	case s.Encrypted && !v.responseSigned():
		v.warn("structure", "EncryptedAssertion inside an unsigned Response (decryption not supported in v0)")
		v.r.Add(finding.New(finding.PostureDecryptBeforeVerify, finding.Evidence{Path: PathAssertion, Actual: "EncryptedAssertion, Response unsigned", Expected: "signed Response or signed-then-encrypted Assertion"}))
	case s.Encrypted:
		v.warn("structure", "EncryptedAssertion present; decryption is not supported in v0")
	case s.AssertionCount > 1:
		v.fail("structure", fmt.Sprintf("%d assertions", s.AssertionCount))
	case s.AssertionCount == 0 && s.Status.Code == StatusSuccess:
		v.fail("structure", "Success status but no Assertion")
		v.r.Add(finding.New(finding.SAMLStructureInvalid, finding.Evidence{Path: PathAssertion, Actual: "0 assertions", Expected: "1", Note: "Success without an Assertion"}))
	case s.Version != "" && s.Version != "2.0":
		v.fail("structure", "Version "+s.Version)
		v.r.Add(finding.New(finding.SAMLStructureInvalid, finding.Evidence{Path: "/Response/@Version", Actual: s.Version, Expected: "2.0"}))
	case len(v.p.Findings) > 0:
		v.warn("structure", fmt.Sprintf("%d parse-level findings", len(v.p.Findings)))
	default:
		v.pass("structure", "single Assertion, SAML 2.0")
	}
}
