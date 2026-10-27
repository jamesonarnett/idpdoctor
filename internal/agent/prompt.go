// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"encoding/json"
	"fmt"
	"strings"

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

// SystemPrompt is the diagnoser's role and rules. It is generated from the
// catalog so the code list can never drift from codes.go.
func SystemPrompt(mode Mode) string {
	var b strings.Builder
	b.WriteString(`You are an enterprise SSO integration engineer on the service-provider side, diagnosing one captured SAML / OIDC / OAuth artifact for a developer. Deterministic validators have already run or are available as tools; your job is to pick the single root cause, cite evidence, and give a vendor-neutral fix.

Rules:
1. Cite only evidence paths that a tool returned or that appear in the redacted artifact you were given. Never invent a path or a value.
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

// ToolsOnPrompt is the user turn for ModeToolsOn: a handle, never bytes.
func ToolsOnPrompt(handle, kind, symptom string, exp expected.Expected, keys jwt.Keys) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Artifact handle (input_ref): %s\nArtifact kind: %s\n", handle, kind)
	writeSymptomAndExpected(&b, symptom, exp, keys)
	b.WriteString("\nCall diagnose with this input_ref, these expected values (and keys, if given) first, then answer.\n")
	return b.String()
}

// ToolsOffPrompt is the user turn for ModeToolsOff: the redacted structure.
func ToolsOffPrompt(redactedText, kind, symptom string, exp expected.Expected, keys jwt.Keys) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Artifact kind: %s\n", kind)
	writeSymptomAndExpected(&b, symptom, exp, keys)
	fmt.Fprintf(&b, "\nRedacted artifact (identity values masked, structure intact):\n```\n%s\n```\n", redactedText)
	b.WriteString("\nYou have no tools. Diagnose from the redacted artifact, the symptom and the expected values alone.\n")
	return b.String()
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
