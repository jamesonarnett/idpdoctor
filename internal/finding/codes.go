// SPDX-License-Identifier: Apache-2.0

package finding

//go:generate go run ./gen -out ../../docs/TAXONOMY.md

// Spec is one catalog entry. The catalog is data on purpose: validators,
// the fixture mutators, the eval generator and docs/TAXONOMY.md all read it,
// so a class cannot exist in one place and not the others.
type Spec struct {
	Code     Code
	Number   int    // position in the published taxonomy; 0 for posture codes
	Protocol string // SAML, JWT, OIDC, OAuth, CERT (may be combined with /)
	Lane     Lane
	Severity Severity
	// Kind says how detectable the class is: "D" from the artifact alone,
	// "D+C" once the expected value is supplied, "C" needs config/symptom
	// context (LLM territory; validators can at most flag "suspicious").
	Kind  string
	Tier  string // v0, v1, v2
	Title string // <= 80 chars, human
	// Signal is what the validator checks, in one line; it is the docs' column.
	Signal string
	// Fix is imperative and vendor-neutral. It must never recommend a security
	// regression (disable signature checks, accept unsigned, widen skew > 5 min);
	// codes_test.go enforces the banned phrases.
	Fix  string
	Refs []string
	// MergedFrom lists the vendor error codes/strings this class absorbs
	// (LANDSCAPE R1 provenance column).
	MergedFrom []string
	// Mutator is the name of the internal/fixture mutator that produces this
	// class; empty until one exists so the docs show coverage honestly.
	Mutator string
}

// Catalog codes. Keep these in taxonomy order; Sort uses that order as the
// "catalog prior" tie-breaker.
const (
	SAMLAudienceMismatch                Code = "SAML_AUDIENCE_MISMATCH"
	SAMLSignatureInvalid                Code = "SAML_SIGNATURE_INVALID"
	SAMLNotSignedOrWrongElementSigned   Code = "SAML_NOT_SIGNED_OR_WRONG_ELEMENT_SIGNED"
	SAMLDestinationOrRecipientMismatch  Code = "SAML_DESTINATION_OR_RECIPIENT_MISMATCH"
	SAMLTimeWindowInvalid               Code = "SAML_TIME_WINDOW_INVALID"
	SAMLIssuerMismatch                  Code = "SAML_ISSUER_MISMATCH"
	SAMLInResponseToMismatch            Code = "SAML_INRESPONSETO_MISMATCH_OR_UNSOLICITED"
	SAMLNameIDMissingOrFormatMismatch   Code = "SAML_NAMEID_MISSING_OR_FORMAT_MISMATCH"
	SAMLRequiredAttributeMissing        Code = "SAML_REQUIRED_ATTRIBUTE_MISSING"
	SAMLStatusNotSuccess                Code = "SAML_STATUS_NOT_SUCCESS"
	CertExpiredOrWeak                   Code = "CERT_EXPIRED_OR_WEAK"
	SAMLStructureInvalid                Code = "SAML_STRUCTURE_INVALID"
	SAMLEncryptedAssertionUndecryptable Code = "SAML_ENCRYPTED_ASSERTION_UNDECRYPTABLE"
	JWTExpiredOrNotYetValid             Code = "JWT_EXPIRED_OR_NOT_YET_VALID"
	JWTAudOrAzpMismatch                 Code = "JWT_AUD_OR_AZP_MISMATCH"
	OIDCIssuerMismatch                  Code = "OIDC_ISSUER_MISMATCH"
	JWTKidNotFoundInJWKS                Code = "JWT_KID_NOT_FOUND_IN_JWKS"
	JWTAlgNoneOrConfusion               Code = "JWT_ALG_NONE_OR_CONFUSION"
	OIDCRequestBindingMismatch          Code = "OIDC_REQUEST_BINDING_MISMATCH"
	OIDCDiscoveryDocInvalid             Code = "OIDC_DISCOVERY_DOC_INVALID"
	OAuthRedirectURIMismatch            Code = "OAUTH_REDIRECT_URI_MISMATCH"
	OAuthPKCEVerifierMismatch           Code = "OAUTH_PKCE_VERIFIER_MISMATCH"
	OAuthInvalidGrantCode               Code = "OAUTH_INVALID_GRANT_CODE"
	OAuthClientConfigRejected           Code = "OAUTH_CLIENT_CONFIG_REJECTED"
	IdPPolicyRefusal                    Code = "IDP_POLICY_REFUSAL"

	PostureUnsignedAssertionAccepted  Code = "POSTURE_UNSIGNED_ASSERTION_ACCEPTED"
	PostureEmbeddedKeyTrust           Code = "POSTURE_EMBEDDED_KEY_TRUST"
	PostureExpiredCertAccepted        Code = "POSTURE_EXPIRED_CERT_ACCEPTED"
	PostureDecryptBeforeVerify        Code = "POSTURE_DECRYPT_BEFORE_VERIFY"
	PostureParserDifferentialExposure Code = "POSTURE_PARSER_DIFFERENTIAL_EXPOSURE"
	PostureWeakAlgorithm              Code = "POSTURE_WEAK_ALGORITHM"
	PostureValidityWindowTooLong      Code = "POSTURE_VALIDITY_WINDOW_TOO_LONG"
	PosturePKCEPlainOrAbsent          Code = "POSTURE_PKCE_PLAIN_OR_ABSENT"
)

// Catalog is the published taxonomy: 25 failure classes then 8 posture codes.
var Catalog = []Spec{
	{
		Code: SAMLAudienceMismatch, Number: 1, Protocol: "SAML", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v0",
		Title:  "Assertion audience does not match the SP entity ID",
		Signal: "Conditions/AudienceRestriction/Audience != sp_entity_id (trailing slash, scheme, case, environment); zero or more than one Audience",
		Fix:    "Set the IdP application's Audience URI (SP entity ID) to exactly the SP's configured entity ID, including scheme and trailing slash.",
		Refs: []string{
			"https://support.okta.com/help/s/article/invalid-audience-with-gitlab-saml-integration",
			"https://docs.snowflake.com/user-guide/errors-saml",
			"https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes",
		},
		MergedFrom: []string{"Okta 'Invalid audience'", "Snowflake 390169 SAML_RESPONSE_INVALID_AUDIENCE", "GitHub 'Audience is invalid'", "Entra AADSTS50010"},
		Mutator:    "audience_mismatch",
	},
	{
		Code: SAMLSignatureInvalid, Number: 2, Protocol: "SAML/CERT", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v0",
		Title:  "Signature does not verify against the configured IdP certificate",
		Signal: "XML-DSig verification fails against idp_cert_pem / metadata cert; KeyInfo cert fingerprint != configured; digest mismatch",
		Fix:    "Download the current signing certificate from the IdP's metadata and replace the SP's configured IdP certificate; if the IdP rotated keys, update before the old cert expires.",
		Refs: []string{
			"https://support.okta.com/help/s/article/The-digital-signature-in-the-SAML-response-did-not-validate-with-the-Identity-Providers-certificate",
			"https://docs.gitlab.com/user/group/saml_sso/troubleshooting/",
			"https://docs.scalekit.com/sso/reference/sso-integration-errors/",
		},
		MergedFrom: []string{"Okta 'digital signature ... did not validate'", "GitLab 'Fingerprint mismatch' / 'Digest mismatch'", "Snowflake 390165", "Scalekit signature_validation_failed"},
		Mutator:    "signature_tampered",
	},
	{
		Code: SAMLNotSignedOrWrongElementSigned, Number: 3, Protocol: "SAML", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v0",
		Title:  "Required signature missing or on the wrong element",
		Signal: "Count of ds:Signature under Response vs Assertion against require_signed_response / require_signed_assertion",
		Fix:    "Enable signing of the element the SP requires (assertion, response, or both) in the IdP application's signing options; the SP's requirement is correct and should stay.",
		Refs: []string{
			"https://support.auth0.com/center/s/article/SAML-Errors-Occur-When-Both-Assertion-and-Response-Signing-Are-Required-by-the-Service-Provider",
			"https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/application-sign-in-problem-application-error",
		},
		MergedFrom: []string{"GitHub 'SAML Response is not signed or has been modified'", "Auth0 'SAML Response not signed' / 'SAML assertion not signed'", "Entra 'Signing Option'"},
		Mutator:    "unsigned",
	},
	{
		Code: SAMLDestinationOrRecipientMismatch, Number: 4, Protocol: "SAML", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v0",
		Title:  "Destination or Recipient does not match the ACS URL",
		Signal: "Response/@Destination != acs_url; SubjectConfirmationData/@Recipient != acs_url; Destination absent on a signed Response",
		Fix:    "Set the IdP application's ACS / Reply URL to exactly the SP's assertion consumer URL (scheme, host, port, path).",
		Refs: []string{
			"https://knowledge.workspace.google.com/admin/apps/saml-app-error-messages",
			"https://docs.snowflake.com/user-guide/errors-saml",
		},
		MergedFrom: []string{"Snowflake 390168 / 390171", "Google 'ACS URL in request doesn't match'", "GitHub 'Recipient in the SAML response was not valid'", "Scalekit invalid_acs_url"},
		Mutator:    "destination_mismatch",
	},
	{
		Code: SAMLTimeWindowInvalid, Number: 5, Protocol: "SAML", Lane: LaneFault, Severity: SeverityError, Kind: "D", Tier: "v0",
		Title:  "Assertion is outside its validity window",
		Signal: "NotBefore > now+skew or NotOnOrAfter <= now-skew on Conditions or SubjectConfirmationData; window shorter than 2 minutes is a warning",
		Fix:    "Synchronise clocks on both sides with NTP and keep SP clock skew tolerance at or below 3 minutes; if the capture is old, replay it with its capture time via the now parameter.",
		Refs: []string{
			"https://workos.com/guide/common-saml-errors",
			"https://docs.scalekit.com/sso/reference/sso-integration-errors/",
		},
		MergedFrom: []string{"Snowflake 390172 / 390173", "GitHub 'Current time is earlier than NotBefore condition'", "WorkOS 'Expired Response Error'", "Scalekit assertion_expired"},
		Mutator:    "expired",
	},
	{
		Code: SAMLIssuerMismatch, Number: 6, Protocol: "SAML", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v0",
		Title:  "Issuer does not match the configured IdP entity ID",
		Signal: "Response/Issuer or Assertion/Issuer != idp_entity_id (classic: Entra issuer trailing slash)",
		Fix:    "Copy the entityID from the IdP metadata verbatim into the SP's IdP issuer setting; watch for a trailing slash or tenant-specific issuer.",
		Refs: []string{
			"https://support.okta.com/help/s/article/Making-Azure-AD-as-an-identity-provider-returns-400-general-non-success-error",
		},
		MergedFrom: []string{"Okta 'The Issuer in the SAML response did not match the Issuer configured'", "Snowflake 390184", "Google app_not_configured_for_user"},
		Mutator:    "issuer_mismatch",
	},
	{
		Code: SAMLInResponseToMismatch, Number: 7, Protocol: "SAML", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v0",
		Title:  "InResponseTo does not match the request, or the response was unsolicited",
		Signal: "@InResponseTo != request_id; absent while the SP disallows IdP-initiated; present when the flow was IdP-initiated; RelayState missing or > 80 bytes",
		Fix:    "Ensure the SP keeps the AuthnRequest ID across the round trip (cookie or session) and that the IdP echoes it; if IdP-initiated SSO is intended, enable it explicitly on the SP.",
		Refs: []string{
			"https://support.okta.com/help/s/article/explanation-of-suspicious-activity-events-single-sign-on",
			"https://support.auth0.com/center/s/article/troubleshoot-auth0-saml-configurations",
			"https://workos.com/docs/reference/sso/get-authorization-url/error-codes",
		},
		MergedFrom: []string{"Okta 'InResponseTo=... does not match the ID of a SAML authentication request'", "Auth0 'IdP-Initiated login is not enabled for connection'", "Snowflake 390170", "WorkOS idp_initiated_sso_disabled"},
		Mutator:    "in_response_to_mismatch",
	},
	{
		Code: SAMLNameIDMissingOrFormatMismatch, Number: 8, Protocol: "SAML", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v0",
		Title:  "NameID missing, empty, or in the wrong format",
		Signal: "Subject/NameID absent or empty; @Format != name_id_format; transient format when the SP persists identity",
		Fix:    "Map a stable user identifier to NameID in the IdP application and set its format to what the SP expects (typically emailAddress or persistent).",
		Refs: []string{
			"https://docs.gitlab.com/user/group/saml_sso/troubleshooting/",
			"https://support.okta.com/help/s/article/subsequent-inbound-saml-login-attempts-fail-following-an-initial-successful-login",
		},
		MergedFrom: []string{"GitLab 'SAML NameID is missing from your SAML response'", "GitLab 'Extern uid has already been taken'", "Google saml_invalid_user_id_mapping", "Entra AADSTS75016"},
		Mutator:    "nameid_missing",
	},
	{
		Code: SAMLRequiredAttributeMissing, Number: 9, Protocol: "SAML", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v0",
		Title:  "A required attribute is missing or empty",
		Signal: "AttributeStatement absent; required attribute names missing (case-sensitive; Entra claim URIs vs plain names); empty values",
		Fix:    "Add the missing attribute claim to the IdP application's attribute statements using the exact name the SP expects, and confirm the user's profile has a value for it.",
		Refs: []string{
			"https://workos.com/docs/sso/attributes",
			"https://docs.scalekit.com/sso/reference/sso-integration-errors/",
		},
		MergedFrom: []string{"GitLab 'Email can't be blank'", "WorkOS required id/email", "Scalekit mandatory_attribute_missing"},
		Mutator:    "attribute_missing",
	},
	{
		Code: SAMLStatusNotSuccess, Number: 10, Protocol: "SAML", Lane: LaneFault, Severity: SeverityError, Kind: "D detect / C cause", Tier: "v0",
		Title:  "IdP returned a non-Success status",
		Signal: "Status/StatusCode/@Value != urn:oasis:names:tc:SAML:2.0:status:Success; nested sub-code; StatusMessage",
		Fix:    "Read the StatusCode sub-code and StatusMessage: Responder means the IdP refused (check signing algorithm, user assignment, request signature); Requester means the AuthnRequest was malformed for this IdP.",
		Refs: []string{
			"https://docs.scalekit.com/sso/reference/sso-integration-errors/",
			"https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes",
		},
		MergedFrom: []string{"Auth0: ADFS Responder = signature-alg mismatch", "Scalekit invalid_status", "Entra AADSTS75005 / 75016"},
		Mutator:    "status_responder",
	},
	{
		Code: CertExpiredOrWeak, Number: 11, Protocol: "CERT", Lane: LaneFault, Severity: SeverityError, Kind: "D", Tier: "v0",
		Title:  "Signing certificate is expired, not yet valid, weak or unparsable",
		Signal: "notAfter < now; notBefore > now; RSA key < 2048 bits; SHA-1 SignatureMethod/DigestMethod; cert in response != cert in metadata; parse failure",
		Fix:    "Rotate the IdP signing certificate (generate a new one in the IdP, publish updated metadata, install it on the SP before activating) and use RSA-2048+ with SHA-256.",
		Refs: []string{
			"https://workos.com/docs/sso/signing-certificates",
			"https://docs.snowflake.com/user-guide/errors-saml",
		},
		MergedFrom: []string{"Scalekit 'Certificate Expired'", "Snowflake 390177 SAML_RESPONSE_INVALID_BAD_CERT, 390166 / 390167", "Entra 'expects the SHA-1 signing algorithm'", "WorkOS certificate rotation"},
		Mutator:    "cert_expired",
	},
	{
		Code: SAMLStructureInvalid, Number: 12, Protocol: "SAML", Lane: LaneFault, Severity: SeverityError, Kind: "D", Tier: "v1",
		Title:  "Response structure is invalid or looks like signature wrapping",
		Signal: "More than one Assertion; ds:Reference/@URI != '#'+ID of the consumed element; duplicate IDs; Signature not a direct child; XML comment inside NameID/AttributeValue; bad base64/deflate; non-Response root; wrong binding",
		Fix:    "Treat the response as hostile unless the IdP is known to emit this shape: consume only the element whose signature verified, and ask the IdP to emit a single assertion with the Signature as a direct child of the signed element.",
		Refs: []string{
			"https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html",
			"https://duo.com/labs/psa/duo-psa-2017-003",
			"https://github.com/crewjam/saml/security/advisories",
		},
		MergedFrom: []string{"OWASP SAML cheat sheet", "Duo PSA-2017-003 comment injection", "crewjam CVE-2022-41912 multi-assertion", "Entra AADSTS75003 binding"},
	},
	{
		Code: SAMLEncryptedAssertionUndecryptable, Number: 13, Protocol: "SAML", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v2",
		Title:  "Encrypted assertion cannot be decrypted with the SP key",
		Signal: "EncryptedAssertion present and no SP private key given, or the key does not match EncryptedKey; SP requires encryption but the assertion is plain",
		Fix:    "Install the SP's current encryption private key and publish the matching public cert in SP metadata; if encryption is not required, disable assertion encryption in the IdP application.",
		Refs: []string{
			"https://github.com/SAML-Toolkits/python3-saml/blob/master/src/onelogin/saml2/response.py",
			"https://workos.com/docs/sso/saml-security",
		},
		MergedFrom: []string{"python3-saml 'No private key available to decrypt the assertion'", "Scalekit 'Unable to Decrypt Assertion'", "WorkOS encrypted attributes unsupported"},
	},
	{
		Code: JWTExpiredOrNotYetValid, Number: 14, Protocol: "JWT", Lane: LaneFault, Severity: SeverityError, Kind: "D", Tier: "v0",
		Title:  "Token is expired, not yet valid, or has no expiry",
		Signal: "exp <= now-skew; nbf > now+skew; iat in the future; exp absent",
		Fix:    "Refresh the token (or re-run the login) and synchronise clocks with NTP; keep validation leeway at or below 3 minutes and never cache tokens past exp.",
		Refs: []string{
			"https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/blob/dev/src/Microsoft.IdentityModel.Tokens/LogMessages.cs",
			"https://github.com/coreos/go-oidc/blob/v3/oidc/verify.go",
		},
		MergedFrom: []string{"IdentityModel IDX10223", "go-oidc 'token is expired'", "Entra AADSTS500133"},
		Mutator:    "jwt_expired",
	},
	{
		Code: JWTAudOrAzpMismatch, Number: 15, Protocol: "JWT/OIDC", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v0",
		Title:  "Audience (or azp) does not include this client",
		Signal: "aud (string or array) does not contain client_id/audience; multiple aud without azp; azp != client_id; an access token presented as an id_token",
		Fix:    "Request the token for this client (correct client_id / audience or resource parameter) and validate aud against the client's own ID, not a shared value.",
		Refs: []string{
			"https://openid.net/specs/openid-connect-core-1_0.html",
			"https://datatracker.ietf.org/doc/html/rfc8725",
		},
		MergedFrom: []string{"OIDC Core 3.1.3.7", "IdentityModel IDX10214", "RFC 8725 section 3.9"},
		Mutator:    "jwt_aud_mismatch",
	},
	{
		Code: OIDCIssuerMismatch, Number: 16, Protocol: "OIDC/JWT", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v0",
		Title:  "Issuer does not match the configured OP",
		Signal: "iss != issuer exactly; discovery issuer != fetch URL prefix; unresolved {tenantid}; Entra v1 sts.windows.net vs v2 login.microsoftonline.com",
		Fix:    "Configure the SP's issuer to the exact string the OP publishes in its discovery document (scheme, host, tenant path, trailing slash) and request tokens from that endpoint version.",
		Refs: []string{
			"https://github.com/coreos/go-oidc/blob/v3/oidc/oidc.go",
			"https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation",
		},
		MergedFrom: []string{"go-oidc IssuerMismatchError", "IdentityModel IDX10205", "OIDC Discovery 4.3"},
		Mutator:    "jwt_iss_mismatch",
	},
	{
		Code: JWTKidNotFoundInJWKS, Number: 17, Protocol: "JWT", Lane: LaneFault, Severity: SeverityError, Kind: "D", Tier: "v0",
		Title:  "Signing key (kid) not found in the JWKS",
		Signal: "header.kid not present in the JWKS; JWKS unreachable or non-200; only keys with use != sig",
		Fix:    "Refresh the JWKS from the OP's jwks_uri (keys rotate); confirm the SP fetches from the same tenant/issuer that minted the token.",
		Refs: []string{
			"https://learn.microsoft.com/en-us/entra/identity-platform/signing-key-rollover",
			"https://github.com/auth0/node-jwks-rsa",
		},
		MergedFrom: []string{"IdentityModel IDX10503 / IDX10522", "Entra signing key rollover", "jwks-rsa SigningKeyNotFoundError"},
		Mutator:    "jwt_kid_unknown",
	},
	{
		Code: JWTAlgNoneOrConfusion, Number: 18, Protocol: "JWT", Lane: LaneFault, Severity: SeverityError, Kind: "D", Tier: "v0",
		Title:  "Token algorithm is none, not allowed, or suggests key confusion",
		Signal: "alg == none (any case); alg not in allowed_algs; HS* against an asymmetric OP; jwk/jku/x5u headers present; kid with path or quote characters",
		Fix:    "Reject the token; pin the SP's allowed algorithms to the asymmetric ones the OP publishes (e.g. RS256) and never accept alg from the token itself.",
		Refs: []string{
			"https://datatracker.ietf.org/doc/html/rfc8725",
			"https://portswigger.net/web-security/jwt",
		},
		MergedFrom: []string{"RFC 8725 sections 2.1 / 3.1 / 3.10", "PortSwigger JWT attacks"},
		Mutator:    "jwt_alg_none",
	},
	{
		Code: OIDCRequestBindingMismatch, Number: 19, Protocol: "OIDC", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v1",
		Title:  "nonce or at_hash does not bind the token to this request",
		Signal: "nonce absent when expected or != nonce; at_hash != left half of hash(access_token) using the alg's hash family; at_hash absent for response_type containing token",
		Fix:    "Generate a fresh nonce per authorization request, store it in the session, and compare it to the id_token nonce claim; compute at_hash with the hash family of the token's alg.",
		Refs: []string{
			"https://openid.net/specs/openid-connect-core-1_0.html",
		},
		MergedFrom: []string{"OIDC Core 3.1.3.6 / 3.1.3.7", "go-oidc 'access token hash does not match'", "Entra AADSTS50027"},
	},
	{
		Code: OIDCDiscoveryDocInvalid, Number: 20, Protocol: "OIDC", Lane: LaneFault, Severity: SeverityError, Kind: "D", Tier: "v1",
		Title:  "Discovery document is missing required fields or is unsafe",
		Signal: "Missing REQUIRED fields (issuer, authorization_endpoint, jwks_uri, response_types_supported, subject_types_supported, id_token_signing_alg_values_supported); no RS256; non-https; endpoints off-host; token_endpoint missing for code flow; wrong content-type",
		Fix:    "Point the SP at the OP's canonical /.well-known/openid-configuration URL for the correct tenant; if the OP's document is non-conformant, configure the endpoints explicitly rather than guessing.",
		Refs: []string{
			"https://openid.net/specs/openid-connect-discovery-1_0.html",
		},
		MergedFrom: []string{"OIDC Discovery 3", "go-oidc 'failed to decode provider discovery object'", "Entra AADSTS50049"},
	},
	{
		Code: OAuthRedirectURIMismatch, Number: 21, Protocol: "OAuth/OIDC", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v1",
		Title:  "redirect_uri is not registered for this client",
		Signal: "redirect_uri not in registered_redirect_uris (exact string compare, RFC 6749 3.1.2.3); differs between the authorize and token requests",
		Fix:    "Register the exact redirect URI (scheme, host, port, path, no trailing-slash drift) on the client and send the identical value in both the authorize and token requests.",
		Refs: []string{
			"https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/error-code-aadsts50011-redirect-uri-mismatch",
			"https://auth0.com/docs/get-started/applications/application-settings",
			"https://workos.com/docs/sso/troubleshooting",
		},
		MergedFrom: []string{"Entra AADSTS50011", "Auth0 'Callback URL mismatch'", "WorkOS 'Redirect URI not allowed'"},
	},
	{
		Code: OAuthPKCEVerifierMismatch, Number: 22, Protocol: "OAuth", Lane: LaneFault, Severity: SeverityError, Kind: "D", Tier: "v1",
		Title:  "PKCE code_verifier does not match the code_challenge",
		Signal: "BASE64URL(SHA256(code_verifier)) != code_challenge; verifier length not 43-128; plain vs S256 mismatch; challenge missing when required",
		Fix:    "Generate the verifier once per flow, store it with the session, derive the challenge with S256, and send the stored verifier unchanged at the token endpoint.",
		Refs: []string{
			"https://datatracker.ietf.org/doc/html/rfc7636#section-4.6",
			"https://support.auth0.com/center/s/article/Invalid-code-verifier",
		},
		MergedFrom: []string{"RFC 7636 4.6", "Auth0 'Failed to verify code verifier'"},
	},
	{
		Code: OAuthInvalidGrantCode, Number: 23, Protocol: "OAuth", Lane: LaneFault, Severity: SeverityError, Kind: "D+C", Tier: "v1",
		Title:  "Authorization code rejected (expired, reused, or bound to another request)",
		Signal: "error=invalid_grant; code age > 10 minutes; code reused; redirect_uri differs at exchange",
		Fix:    "Exchange the code exactly once and within minutes of issuance, with the same redirect_uri and client; guard against double submission (e.g. React StrictMode effects firing twice).",
		Refs: []string{
			"https://datatracker.ietf.org/doc/html/rfc6749#section-5.2",
		},
		MergedFrom: []string{"RFC 6749 5.2 / 10.5", "Entra AADSTS70000 / 70008 / 50173", "WorkOS 'code is valid for 10 minutes'"},
	},
	{
		Code: OAuthClientConfigRejected, Number: 24, Protocol: "OAuth", Lane: LaneFault, Severity: SeverityError, Kind: "D classify / C fix", Tier: "v1",
		Title:  "Client configuration rejected by the authorization server",
		Signal: "invalid_client (bad/expired secret, secret from a public client, missing assertion), invalid_scope, unauthorized_client, unsupported_response_type / grant_type; response_type not in response_types_supported",
		Fix:    "Compare the client's registered type, grant types, scopes and credential against what the request sends; rotate an expired secret rather than reusing it.",
		Refs: []string{
			"https://auth0.com/docs/get-started/applications/application-grant-types",
		},
		MergedFrom: []string{"Entra AADSTS7000215 / 7000222 / 700025 / 70011 / 700054", "Scalekit failed_to_exchange_token", "Auth0 grant types"},
	},
	{
		Code: IdPPolicyRefusal, Number: 25, Protocol: "SAML/OIDC", Lane: LaneFault, Severity: SeverityError, Kind: "C", Tier: "v2",
		Title:  "IdP refused for a policy reason outside the artifact",
		Signal: "User not assigned, consent / admin consent required, MFA or Conditional Access, wrong tenant or app not found, /common with a single-tenant app; prompt=none -> login_required / consent_required / interaction_required",
		Fix:    "Resolve on the IdP side: assign the user or group to the application, grant admin consent, satisfy the access policy, or target the correct tenant endpoint.",
		Refs: []string{
			"https://openid.net/specs/openid-connect-core-1_0.html#AuthError",
			"https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes",
		},
		MergedFrom: []string{"Entra AADSTS50105 / 65001 / 90094 / 50076 / 53003 / 700016 / 500011 / 50194", "OIDC Core 3.1.2.6", "Google app_not_enabled_for_user", "Scalekit user_not_active"},
	},

	// Posture lane (section 3.1): the artifact validates, or would under the
	// SP settings in expected, yet exhibits an unsafe property.
	{
		Code: PostureUnsignedAssertionAccepted, Protocol: "SAML", Lane: LanePosture, Severity: SeverityWarn, Kind: "D+C", Tier: "v0",
		Title:      "Assertion is unsigned and the SP would accept it",
		Signal:     "expected.require_signed_assertion == false, or absent while the artifact carries only a Response signature over an unsigned assertion",
		Fix:        "Require a signed assertion on the SP (and keep response signing); an unsigned assertion inside a signed response is still safe only if the SP consumes nothing outside the verified element.",
		Refs:       []string{"https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html"},
		MergedFrom: []string{"OWASP SAML cheat sheet", "crewjam CVE-2022-41912 class"},
		Mutator:    "posture_unsigned_assertion",
	},
	{
		Code: PostureEmbeddedKeyTrust, Protocol: "SAML", Lane: LanePosture, Severity: SeverityWarn, Kind: "D+C", Tier: "v0",
		Title:      "No trusted IdP certificate supplied; only the embedded KeyInfo key is available",
		Signal:     "No idp_cert_pem / metadata supplied, so the only key available is the one inside KeyInfo; a validator that passes this way trusts the sender's key",
		Fix:        "Configure the IdP signing certificate (from metadata) on the SP and verify against it; never trust the certificate embedded in the message.",
		Refs:       []string{"https://datatracker.ietf.org/doc/html/rfc8725"},
		MergedFrom: []string{"RFC 8725 3.10 analogue (jwk/jku/x5u)", "goxmldsig requires store roots"},
		Mutator:    "posture_embedded_key",
	},
	{
		Code: PostureExpiredCertAccepted, Protocol: "SAML/CERT", Lane: LanePosture, Severity: SeverityWarn, Kind: "D", Tier: "v0",
		Title:      "Signature verifies but the signing certificate is expired",
		Signal:     "Signature verifies and signing cert notAfter < now",
		Fix:        "Rotate the IdP signing certificate and configure the SP to reject expired signing certificates.",
		Refs:       []string{"https://workos.com/docs/sso/signing-certificates"},
		MergedFrom: []string{"Okta KB: expired IdP certs still accepted by some SPs"},
		Mutator:    "posture_expired_cert",
	},
	{
		Code: PostureDecryptBeforeVerify, Protocol: "SAML", Lane: LanePosture, Severity: SeverityWarn, Kind: "D", Tier: "v0",
		Title:      "Encrypted assertion inside an unsigned response forces decrypt-before-verify",
		Signal:     "EncryptedAssertion present and the Response is unsigned, so an SP must decrypt before it can verify anything",
		Fix:        "Have the IdP sign the Response (or the assertion before encrypting) so the SP can verify a signature before decrypting.",
		Refs:       []string{"https://spring.io/security/cve-2026-41694"},
		MergedFrom: []string{"Spring Security CVE-2026-41694"},
	},
	{
		Code: PostureParserDifferentialExposure, Protocol: "SAML", Lane: LanePosture, Severity: SeverityWarn, Kind: "D", Tier: "v0",
		Title:  "Artifact contains constructs that two XML parsers may read differently",
		Signal: "DOCTYPE or entity declarations, comment nodes inside identity-bearing elements, duplicate attributes, or unusual encodings",
		Fix:    "Reject DOCTYPE and entity declarations before parsing, strip or reject comments inside NameID and AttributeValue, and use one parser for both verification and extraction.",
		Refs: []string{
			"https://github.blog/security/sign-in-as-anyone-bypassing-saml-sso-authentication-with-parser-differentials/",
			"https://duo.com/labs/psa/duo-psa-2017-003",
		},
		MergedFrom: []string{"GitHub CVE-2025-25291 / 25292", "Duo PSA-2017-003"},
		Mutator:    "posture_comment_in_nameid",
	},
	{
		Code: PostureWeakAlgorithm, Protocol: "SAML/JWT", Lane: LanePosture, Severity: SeverityWarn, Kind: "D", Tier: "v0",
		Title:      "Weak algorithm or key size in use",
		Signal:     "RSA-SHA1 signature or SHA-1 digest, RSA key < 2048 bits, HS* id_token",
		Fix:        "Move the IdP application to RSA-SHA256 with a 2048-bit or larger key; for OIDC, prefer RS256/ES256 id_tokens.",
		Refs:       []string{"https://datatracker.ietf.org/doc/html/rfc8725"},
		MergedFrom: []string{"overlaps CERT_EXPIRED_OR_WEAK; posture lane when it still verifies"},
		Mutator:    "posture_sha1",
	},
	{
		Code: PostureValidityWindowTooLong, Protocol: "SAML/JWT", Lane: LanePosture, Severity: SeverityWarn, Kind: "D", Tier: "v0",
		Title:      "Validity window is longer than policy",
		Signal:     "Assertion window > 10 minutes; SessionNotOnOrAfter > 24 hours; id_token exp - iat > 1 hour",
		Fix:        "Shorten the IdP's assertion and token lifetimes; fix clock skew with NTP instead of widening validity windows.",
		Refs:       []string{"https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html"},
		MergedFrom: []string{"widening windows is the classic bad fix"},
		Mutator:    "posture_long_window",
	},
	{
		Code: PosturePKCEPlainOrAbsent, Protocol: "OAuth", Lane: LanePosture, Severity: SeverityWarn, Kind: "D", Tier: "v1",
		Title:      "Public client without PKCE S256",
		Signal:     "Public client using code_challenge_method=plain or no PKCE at all",
		Fix:        "Use PKCE with S256 on every public client (and on confidential clients too; it is cheap).",
		Refs:       []string{"https://datatracker.ietf.org/doc/html/rfc7636"},
		MergedFrom: []string{"RFC 7636 4.2"},
	},
}
