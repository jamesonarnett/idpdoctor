// SPDX-License-Identifier: Apache-2.0

package saml

// Evidence paths are namespace-free and stable so an LLM can cite them and
// a harness can check citations against the Summary. They name the logical
// element, not the vendor's prefix.
const (
	PathResponse                = "/Response"
	PathResponseID              = "/Response/@ID"
	PathResponseDestination     = "/Response/@Destination"
	PathResponseInResponseTo    = "/Response/@InResponseTo"
	PathResponseIssuer          = "/Response/Issuer"
	PathStatusCode              = "/Response/Status/StatusCode/@Value"
	PathStatusSubCode           = "/Response/Status/StatusCode/StatusCode/@Value"
	PathStatusMessage           = "/Response/Status/StatusMessage"
	PathResponseSignature       = "/Response/Signature"
	PathAssertion               = "/Response/Assertion"
	PathAssertionIssuer         = "/Response/Assertion/Issuer"
	PathAssertionSignature      = "/Response/Assertion/Signature"
	PathNameID                  = "/Response/Assertion/Subject/NameID"
	PathNameIDFormat            = "/Response/Assertion/Subject/NameID/@Format"
	PathSubjectConfirmationData = "/Response/Assertion/Subject/SubjectConfirmation/SubjectConfirmationData"
	PathRecipient               = PathSubjectConfirmationData + "/@Recipient"
	PathSCDNotOnOrAfter         = PathSubjectConfirmationData + "/@NotOnOrAfter"
	PathSCDInResponseTo         = PathSubjectConfirmationData + "/@InResponseTo"
	PathConditions              = "/Response/Assertion/Conditions"
	PathConditionsNotBefore     = PathConditions + "/@NotBefore"
	PathConditionsNotOnOrAfter  = PathConditions + "/@NotOnOrAfter"
	PathAudience                = PathConditions + "/AudienceRestriction/Audience"
	PathAttributeStatement      = "/Response/Assertion/AttributeStatement"
	PathSignatureMethod         = "/Signature/SignedInfo/SignatureMethod/@Algorithm"
	PathDigestMethod            = "/Signature/SignedInfo/Reference/DigestMethod/@Algorithm"
	PathKeyInfoCertificate      = "/Signature/KeyInfo/X509Data/X509Certificate"
	PathSessionNotOnOrAfter     = "/Response/Assertion/AuthnStatement/@SessionNotOnOrAfter"
	PathRelayState              = "/RelayState"
)

// PathAttribute names one attribute by its Name, e.g.
// /Response/Assertion/AttributeStatement/Attribute[@Name='email'].
func PathAttribute(name string) string {
	return PathAttributeStatement + "/Attribute[@Name='" + name + "']"
}
