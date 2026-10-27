// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jamesonarnett/idpdoctor/internal/diag"
	"github.com/jamesonarnett/idpdoctor/internal/expected"
	"github.com/jamesonarnett/idpdoctor/internal/finding"
	"github.com/jamesonarnett/idpdoctor/internal/jwt"
	"github.com/jamesonarnett/idpdoctor/internal/redact"
)

// Mode is the ablation arm (BUILD_PLAN 5.4).
type Mode string

const (
	// ModeToolsOn gives the model idpdoctor's MCP tools and a handle to the
	// artifact; it never sees the artifact itself.
	ModeToolsOn Mode = "tools-on"
	// ModeToolsOff gives the model the redacted structure of the artifact
	// and no tools. This is the only mode in which any artifact text enters
	// a transcript, and that text is redacted.
	ModeToolsOff Mode = "tools-off"
)

// ToolsOnPlannedCalls is the tool-call budget in tools-on mode; --max-turns
// is this plus StructuredOutputTurns.
const ToolsOnPlannedCalls = 6

// PromptVersion is bumped whenever SystemPrompt, the user turns or the
// schema change in a way that makes cached eval results incomparable. The
// eval runner stamps it into every result and re-runs a cached case whose
// version differs, so a results directory never silently mixes prompts.
//
//	1: v1 smoke run (evals/results/smoke).
//	2: allowed-path list in the user turn, evidence[].path enum in the
//	   schema, verbatim-copy rule with examples, check-name normaliser.
const PromptVersion = 2

// SystemPrompt is the diagnoser's role and rules. It is generated from the
// catalog so the code list can never drift from codes.go.
func SystemPrompt(mode Mode) string {
	var b strings.Builder
	b.WriteString(`You are an enterprise SSO integration engineer on the service-provider side, diagnosing one captured SAML / OIDC / OAuth artifact for a developer. Deterministic validators have already run or are available as tools; your job is to pick the single root cause, cite evidence, and give a vendor-neutral fix.

Rules:
1. Every evidence item's path must be copied verbatim from the "Allowed evidence paths" list in the task (the paths the validators returned and the structure of the artifact). A check name such as "audience" or "checks/signature_verify" is not a path; a paraphrased or shortened path is not a path. If nothing on the list supports a point, leave it out of evidence rather than inventing a path or a value.
2. Exactly one root_cause_code. HEALTHY when the artifact validates (posture warnings alone are HEALTHY plus posture_codes). UNKNOWN only when nothing supports a class.
3. If a check skipped because an expected value is missing, do not guess: name the value in questions (e.g. "sp_entity_id") and keep confidence low.
4. Prefer the deterministic top cause unless the symptom text clearly contradicts it; put runners-up in alternatives with why_not.
5. The fix must never weaken security: never disable or skip signature validation, accept unsigned or expired material, raise clock skew above 5 minutes, downgrade algorithms, or trust the certificate embedded in the message.
6. Never echo NameIDs, attribute values, tokens, codes or secrets. Values you see are already redacted as [REDACTED:kind:hash]; keep them that way.
`)
	if mode == ModeToolsOn {
		b.WriteString(`7. You have the idpdoctor MCP tools. Start with diagnose using the input_ref handle and the expected values you were given; call saml_validate, jwt_validate, oidc_discovery_check, oauth_error_explain, saml_decode or cert_inspect only when you need more detail. Do not call stash_file: the artifact is already stashed.
`)
	}
	b.WriteString("\nCatalog (code: what it means):\n")
	for _, s := range finding.Catalog {
		fmt.Fprintf(&b, "- %s [%s]: %s\n", s.Code, s.Lane, s.Title)
	}
	b.WriteString("- HEALTHY: the artifact validates under the expected values\n- UNKNOWN: no class is supported by the evidence\n")
	return b.String()
}

// Allowed carries the citation vocabulary for one artifact: the paths the
// model may put in evidence[].path (diag.KnownPaths: validator evidence plus
// structure, which is also every path a tool can return for this artifact)
// and, for the worked example, one path a finding actually cited.
type Allowed struct {
	Paths []string
	// Example is a path from the deterministic findings when there is one,
	// else the first allowed path; "" when nothing is allowed.
	Example string
}

// NewAllowed builds the list from the deterministic result.
func NewAllowed(res *diag.Result) Allowed {
	a := Allowed{Paths: diag.KnownPaths(res)}
	if res.TopCause != nil && len(res.TopCause.Evidence) > 0 {
		a.Example = res.TopCause.Evidence[0].Path
	} else if len(a.Paths) > 0 {
		a.Example = a.Paths[0]
	}
	return a
}

// ToolsOnPrompt is the user turn for ModeToolsOn: a handle, never bytes.
func ToolsOnPrompt(handle, kind, symptom string, exp expected.Expected, keys jwt.Keys, allowed Allowed) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Artifact handle (input_ref): %s\nArtifact kind: %s\n", handle, kind)
	writeSymptomAndExpected(&b, symptom, exp, keys)
	writeAllowedPaths(&b, allowed)
	b.WriteString("\nCall diagnose with this input_ref, these expected values (and keys, if given) first, then answer. The tool results print the evidence paths they found; those are on the list above.\n")
	return b.String()
}

// ToolsOffPrompt is the user turn for ModeToolsOff: the redacted structure.
func ToolsOffPrompt(redactedText, kind, symptom string, exp expected.Expected, keys jwt.Keys, allowed Allowed) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Artifact kind: %s\n", kind)
	writeSymptomAndExpected(&b, symptom, exp, keys)
	fmt.Fprintf(&b, "\nRedacted artifact (identity values masked, structure intact):\n```\n%s\n```\n", redactedText)
	writeAllowedPaths(&b, allowed)
	b.WriteString("\nYou have no tools. Diagnose from the redacted artifact, the symptom and the expected values alone.\n")
	return b.String()
}

// writeAllowedPaths enumerates the citation vocabulary with one correct and
// two incorrect examples, so "copy verbatim" is concrete.
func writeAllowedPaths(b *strings.Builder, a Allowed) {
	b.WriteString("\nAllowed evidence paths for this artifact (evidence[].path must be one of these, copied verbatim; the output schema rejects anything else):\n")
	for _, p := range a.Paths {
		fmt.Fprintf(b, "  %s\n", p)
	}
	if a.Example == "" {
		b.WriteString("  (none: cite no evidence)\n")
		return
	}
	fmt.Fprintf(b, "Correct:   {\"path\": %q, ...}\n", a.Example)
	fmt.Fprintf(b, "Incorrect: {\"path\": %q, ...}  (a check name, not a path)\n", "checks/"+exampleCheckName(a.Example))
	fmt.Fprintf(b, "Incorrect: {\"path\": %q, ...}  (paraphrased: not on the list)\n", paraphrase(a.Example))
}

// exampleCheckName turns a path into the kind of check-name citation the
// model must not produce: its last plain segment, lower-cased.
func exampleCheckName(path string) string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	last := segs[len(segs)-1]
	last = strings.TrimPrefix(last, "@")
	if i := strings.Index(last, "["); i > 0 {
		last = last[:i]
	}
	return strings.ToLower(last)
}

// paraphrase drops a middle segment from a multi-segment path (the usual
// shortening), or appends "/value" to a short one, to make a wrong example.
func paraphrase(path string) string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) >= 3 {
		segs = append(segs[:1], segs[2:]...)
		return "/" + strings.Join(segs, "/")
	}
	return path + "/value"
}

func writeSymptomAndExpected(b *strings.Builder, symptom string, exp expected.Expected, keys jwt.Keys) {
	if strings.TrimSpace(symptom) == "" {
		b.WriteString("Symptom: (none given)\n")
	} else {
		fmt.Fprintf(b, "Symptom reported by the developer: %s\n", strings.TrimSpace(symptom))
	}
	fmt.Fprintf(b, "Expected (what the SP is configured for; missing fields mean the developer did not say):\n%s\n", ExpectedJSON(exp))
	if !keys.Empty() {
		// Public key material only (a JWKS or PEM public key); the model
		// passes it to jwt_validate / diagnose as "keys".
		kb, _ := json.MarshalIndent(keys, "", "  ")
		fmt.Fprintf(b, "Keys (the OP's public verification material; pass as keys):\n%s\n", kb)
	}
}

// ExpectedJSON renders expected for a prompt with its one true secret
// masked: access_token is a bearer credential and the at_hash check it
// feeds runs server-side anyway. PKCE values stay in clear because they are
// single-use, carry no identity, and the model needs them to reason about
// a PKCE mismatch. idp_cert_pem is public key material.
func ExpectedJSON(exp expected.Expected) string {
	exp.AccessToken = redact.Value("access_token", exp.AccessToken)
	b, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}
