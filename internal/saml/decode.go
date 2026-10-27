// SPDX-License-Identifier: Apache-2.0

package saml

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// Binding names how the Response reached the SP.
type Binding string

const (
	BindingAuto     Binding = "auto"
	BindingPOST     Binding = "post"     // base64 of the XML, in a SAMLResponse form field
	BindingRedirect Binding = "redirect" // base64(raw deflate(XML)), URL-encoded in a query string
	BindingXML      Binding = "xml"      // the XML itself
)

// Decode errors. Callers use errors.Is; messages are for humans.
var (
	ErrEmptyInput   = errors.New("saml: empty input")
	ErrNotXML       = errors.New("saml: decoded bytes are not XML")
	ErrBadBase64    = errors.New("saml: invalid base64")
	ErrBadDeflate   = errors.New("saml: invalid deflate stream")
	ErrNoSAMLField  = errors.New("saml: no SAMLResponse or SAMLRequest field found")
	ErrBadBinding   = errors.New("saml: unknown binding")
	ErrInputTooLong = errors.New("saml: input exceeds size limit")
)

// MaxInput bounds decoded output to keep a hostile deflate stream from
// expanding without limit (a 1 MB assertion is already absurd).
const MaxInput = 4 << 20

// Decoded is the binding-independent result of Decode.
type Decoded struct {
	Binding    Binding
	XML        []byte
	RelayState string
	// SigAlg and Signature are the Redirect binding's detached signature
	// parameters, when present. Signature is a replayable value and is
	// never echoed; only its presence is reported.
	SigAlg       string
	HasSignature bool
	// Field says whether the payload was a SAMLResponse or SAMLRequest.
	Field string
}

// Decode turns whatever the developer captured into XML: a raw Response,
// a base64 POST payload, a deflated Redirect payload, a full form body, or
// a full URL. binding "auto" sniffs; the others force one path and fail
// loudly if the bytes do not match, which is itself a diagnosis.
func Decode(input string, binding Binding) (*Decoded, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil, ErrEmptyInput
	}
	if len(s) > MaxInput {
		return nil, ErrInputTooLong
	}
	if binding == "" {
		binding = BindingAuto
	}

	out := &Decoded{Binding: binding, Field: "SAMLResponse"}

	// Step 1: unwrap a form body or URL into the payload field.
	payload, hinted, err := extractField(s, out)
	if err != nil {
		return nil, err
	}
	if binding == BindingAuto && hinted != "" {
		binding = hinted
	}

	// Step 2: the payload is XML, base64(XML) or base64(deflate(XML)).
	switch binding {
	case BindingXML:
		return finish(out, BindingXML, []byte(payload))
	case BindingPOST:
		raw, err := b64(payload)
		if err != nil {
			return nil, err
		}
		return finish(out, BindingPOST, raw)
	case BindingRedirect:
		raw, err := b64(payload)
		if err != nil {
			return nil, err
		}
		xml, err := inflate(raw)
		if err != nil {
			return nil, err
		}
		return finish(out, BindingRedirect, xml)
	case BindingAuto:
		if looksLikeXML([]byte(payload)) {
			return finish(out, BindingXML, []byte(payload))
		}
		raw, err := b64(payload)
		if err != nil {
			return nil, fmt.Errorf("%w (input is neither XML nor base64)", err)
		}
		if looksLikeXML(raw) {
			return finish(out, BindingPOST, raw)
		}
		xml, err := inflate(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: base64 decoded but is neither XML nor deflate", ErrNotXML)
		}
		return finish(out, BindingRedirect, xml)
	}
	return nil, fmt.Errorf("%w: %q", ErrBadBinding, binding)
}

func finish(out *Decoded, b Binding, xml []byte) (*Decoded, error) {
	if !looksLikeXML(xml) {
		return nil, ErrNotXML
	}
	out.Binding = b
	out.XML = xml
	return out, nil
}

// extractField pulls SAMLResponse/SAMLRequest (+RelayState, SigAlg,
// Signature) out of a URL or x-www-form-urlencoded body. If the input is
// neither, it is returned unchanged with no binding hint.
func extractField(s string, out *Decoded) (payload string, hint Binding, err error) {
	var values url.Values
	switch {
	case strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://"):
		u, perr := url.Parse(s)
		if perr != nil {
			return "", "", fmt.Errorf("saml: parse url: %w", perr)
		}
		values = u.Query()
		hint = BindingRedirect
	case strings.Contains(s, "SAMLResponse=") || strings.Contains(s, "SAMLRequest="):
		// A form body may be pasted raw ("SAMLResponse=PHNh...&RelayState=x")
		// or with a leading '?' from a URL fragment.
		values, err = url.ParseQuery(strings.TrimPrefix(s, "?"))
		if err != nil {
			return "", "", fmt.Errorf("saml: parse form body: %w", err)
		}
		hint = BindingPOST
	default:
		return s, "", nil
	}

	payload = values.Get("SAMLResponse")
	if payload == "" {
		payload = values.Get("SAMLRequest")
		out.Field = "SAMLRequest"
	}
	if payload == "" {
		return "", "", ErrNoSAMLField
	}
	out.RelayState = values.Get("RelayState")
	out.SigAlg = values.Get("SigAlg")
	out.HasSignature = values.Get("Signature") != ""
	return payload, hint, nil
}

// b64 accepts standard or URL-safe alphabets, padded or not, and tolerates
// embedded whitespace (captures from logs often wrap).
func b64(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		}
		return r
	}, s)
	unpadded := strings.TrimRight(clean, "=")
	candidates := []struct {
		enc *base64.Encoding
		in  string
	}{
		{base64.StdEncoding, clean},
		{base64.URLEncoding, clean},
		{base64.RawStdEncoding, unpadded},
		{base64.RawURLEncoding, unpadded},
	}
	for _, c := range candidates {
		if out, err := c.enc.DecodeString(c.in); err == nil {
			return out, nil
		}
	}
	return nil, ErrBadBase64
}

// inflate decompresses RFC 1951 raw deflate (not zlib, not gzip) with a cap.
func inflate(raw []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(raw))
	defer r.Close()
	out, err := io.ReadAll(io.LimitReader(r, MaxInput+1))
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("%w: %v", ErrBadDeflate, err)
	}
	if len(out) > MaxInput {
		return nil, ErrInputTooLong
	}
	if len(out) == 0 {
		return nil, ErrBadDeflate
	}
	return out, nil
}

// looksLikeXML is a cheap sniff: optional BOM/whitespace then '<'.
func looksLikeXML(b []byte) bool {
	b = bytes.TrimLeft(bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}), " \t\r\n")
	return len(b) > 0 && b[0] == '<'
}

func trim(s string) string { return strings.TrimSpace(s) }
