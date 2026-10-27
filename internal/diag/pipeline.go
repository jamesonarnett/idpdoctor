// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jamesonarnett/idpdoctor/internal/cert"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/jwt"
	"github.com/jamesonarnett/idpdoctor/internal/saml"
)

// Pipeline errors.
var (
	ErrUnknownKind     = errors.New("diag: could not determine artifact kind")
	ErrUnsupportedKind = errors.New("diag: artifact kind not supported in v0")
)

// Input is everything the pipeline may use. Symptom is carried through for
// the future explain layer; the deterministic pipeline does not read it.
type Input struct {
	Artifact string
	Kind     Kind
	Symptom  string
	Expected expected.Expected
	Keys     jwt.Keys
	Client   *http.Client
	Now      time.Time
}

// Result is the ranked Report plus the parsed view that produced it.
type Result struct {
	Kind   Kind
	Report *finding.Report
	// TopCause is the highest-ranked fault-lane error, or nil when the
	// artifact validates (posture findings do not count).
	TopCause *finding.Finding
	// Exactly one of these is set, matching Kind.
	SAML *saml.Summary
	JWT  *jwt.Decoded
	Cert *cert.Info
	// SAMLParsed keeps the tree for callers that need the redacted pretty
	// XML (the tools-off explain mode, the redacted bundle).
	SAMLParsed *saml.Parsed
	// Binding is set for SAML.
	Binding saml.Binding
	// extraPaths and extraText are filled by kinds whose summary type does
	// not live in this package's Result (discovery, OAuth); see known.go.
	extraPaths []string
	extraText  string
}

// Run executes sniff -> decode -> parse -> validate -> rank.
func Run(ctx context.Context, in Input) (*Result, error) {
	kind := in.Kind
	if kind == "" || kind == KindAuto {
		kind = Sniff(in.Artifact)
	}
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	switch kind {
	case KindSAMLResponse:
		return runSAML(in)
	case KindJWT:
		return runJWT(ctx, in)
	case KindCert:
		return runCert(in)
	case KindUnknown:
		return nil, ErrUnknownKind
	}
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedKind, kind)
}

func runSAML(in Input) (*Result, error) {
	dec, err := saml.Decode(in.Artifact, saml.BindingAuto)
	if err != nil {
		return nil, err
	}
	p, err := saml.Parse(dec.XML)
	if err != nil {
		return nil, err
	}
	p.Summary.RelayState = dec.RelayState
	r, err := saml.Validate(p, in.Expected, in.Now)
	if err != nil {
		return nil, err
	}
	return finish(&Result{Kind: KindSAMLResponse, Report: r, SAML: &p.Summary, SAMLParsed: p, Binding: dec.Binding}), nil
}

func runJWT(ctx context.Context, in Input) (*Result, error) {
	now, err := in.Expected.NowOr(in.Now)
	if err != nil {
		return nil, err
	}
	d, err := jwt.Decode(in.Artifact, now)
	if err != nil {
		return nil, err
	}
	res, err := jwt.Validate(ctx, d, in.Expected, jwt.Options{Keys: in.Keys, Client: in.Client}, in.Now)
	if err != nil {
		return nil, err
	}
	return finish(&Result{Kind: KindJWT, Report: res.Report, JWT: d}), nil
}

func runCert(in Input) (*Result, error) {
	now, err := in.Expected.NowOr(in.Now)
	if err != nil {
		return nil, err
	}
	c, err := cert.Parse(in.Artifact)
	if err != nil {
		return nil, err
	}
	info := cert.Inspect(c, now)
	r := finding.NewReport(string(KindCert))
	for _, f := range info.Findings {
		r.Add(f)
	}
	status := finding.CheckPass
	if len(info.Findings) > 0 {
		status = finding.CheckFail
	}
	r.AddCheck(finding.Check{Name: "cert_validity", Status: status, Detail: fmt.Sprintf("%s, %d days remaining", info.SigAlg, info.DaysRemaining)})
	return finish(&Result{Kind: KindCert, Report: r, Cert: &info}), nil
}

// finish ranks and picks the top cause. finding.Sort already encodes the
// rules-only ranking (lane, severity, confidence, catalog prior).
func finish(res *Result) *Result {
	finding.Sort(res.Report.Findings)
	for i := range res.Report.Findings {
		f := &res.Report.Findings[i]
		if f.Lane == finding.LaneFault && f.Severity == finding.SeverityError {
			res.TopCause = f
			break
		}
	}
	return res
}
