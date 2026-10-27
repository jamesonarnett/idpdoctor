// SPDX-License-Identifier: Apache-2.0

// Package expected holds the caller-supplied "what the SP is configured
// for" values shared by every tool. Every field is optional: a check whose
// expected value is missing reports status skip and names the field, so an
// agent knows what to ask the human for instead of guessing.
package expected

import (
	"errors"
	"fmt"
	"time"
)

// DefaultClockSkew is the tolerance applied to every time comparison when
// clock_skew_seconds is not given. 3 minutes is what most SP libraries ship.
const DefaultClockSkew = 180 * time.Second

// MaxClockSkew caps caller-supplied skew; widening it further is the classic
// bad fix and the tool refuses to model it.
const MaxClockSkew = 5 * time.Minute

// ErrBadNow reports an unparsable now override.
var ErrBadNow = errors.New("expected: now must be RFC 3339")

// Expected mirrors the JSON object in BUILD_PLAN 2.3. Pointers on the
// booleans distinguish "not stated" from false.
type Expected struct {
	// SAML
	SPEntityID             string   `json:"sp_entity_id,omitempty" jsonschema:"the SP entity ID the assertion audience must equal"`
	ACSURL                 string   `json:"acs_url,omitempty" jsonschema:"the SP assertion consumer URL Destination and Recipient must equal"`
	IdPEntityID            string   `json:"idp_entity_id,omitempty" jsonschema:"the IdP entityID the Issuer must equal"`
	IdPCertPEM             string   `json:"idp_cert_pem,omitempty" jsonschema:"the IdP signing certificate (PEM or bare base64 DER) to verify signatures against"`
	RequestID              string   `json:"request_id,omitempty" jsonschema:"the AuthnRequest ID InResponseTo must echo; omit for IdP-initiated flows"`
	NameIDFormat           string   `json:"name_id_format,omitempty" jsonschema:"the NameID Format URN the SP expects"`
	RequiredAttributes     []string `json:"required_attributes,omitempty" jsonschema:"attribute Names the SP needs, exact case"`
	RequireSignedAssertion *bool    `json:"require_signed_assertion,omitempty" jsonschema:"whether the SP requires the Assertion to be signed"`
	RequireSignedResponse  *bool    `json:"require_signed_response,omitempty" jsonschema:"whether the SP requires the Response to be signed"`

	// JWT / OIDC
	Issuer      string   `json:"issuer,omitempty" jsonschema:"the exact iss value the OP publishes"`
	Audience    string   `json:"audience,omitempty" jsonschema:"the audience the token must contain (defaults to client_id)"`
	ClientID    string   `json:"client_id,omitempty" jsonschema:"this relying party's client_id"`
	Nonce       string   `json:"nonce,omitempty" jsonschema:"the nonce sent in the authorization request"`
	AllowedAlgs []string `json:"allowed_algs,omitempty" jsonschema:"signing algorithms the SP accepts; default RS256 ES256 PS256 families"`

	// Clock
	Now              string `json:"now,omitempty" jsonschema:"RFC 3339 time to validate against instead of wall-clock, for replaying captures"`
	ClockSkewSeconds int    `json:"clock_skew_seconds,omitempty" jsonschema:"tolerance for time comparisons; default 180, capped at 300"`
}

// NowOr returns the override if set, else fallback.
func (e Expected) NowOr(fallback time.Time) (time.Time, error) {
	if e.Now == "" {
		return fallback, nil
	}
	t, err := time.Parse(time.RFC3339, e.Now)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %v", ErrBadNow, err)
	}
	return t, nil
}

// Skew returns the effective clock tolerance.
func (e Expected) Skew() time.Duration {
	if e.ClockSkewSeconds <= 0 {
		return DefaultClockSkew
	}
	d := time.Duration(e.ClockSkewSeconds) * time.Second
	if d > MaxClockSkew {
		return MaxClockSkew
	}
	return d
}

// Bool dereferences an optional bool with a default.
func Bool(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}
