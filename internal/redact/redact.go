// SPDX-License-Identifier: Apache-2.0

// Package redact implements the redact-by-default policy (BUILD_PLAN 2.7):
// identity-bearing values are replaced with a kind-tagged hash prefix before
// they appear in any output. There is deliberately no "off" switch. The
// package also holds the in-process artifact handle store that lets an agent
// refer to an assertion it has never seen.
package redact

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/beevik/etree"
)

// Value returns the redaction token for a sensitive value. The first 8 hex
// chars of the SHA-256 let a reader tell two different values apart (and
// recognise the same value in two places) without learning either. Empty
// input stays empty so "missing" remains distinguishable from "present".
func Value(kind, s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return "[REDACTED:" + kind + ":" + hex.EncodeToString(sum[:4]) + "]"
}

// xmlSensitive maps XML local names whose text content is identity-bearing
// or replayable to the redaction kind used for them. Attribute *names*,
// Issuer, Audience, URLs, timestamps and status codes stay in clear because
// diagnosis needs them and they are not PII.
var xmlSensitive = map[string]string{
	"NameID":         "nameid",
	"AttributeValue": "attr",
	"SignatureValue": "sig",
	"CipherValue":    "cipher",
	"EncryptedID":    "nameid",
	"BaseID":         "nameid",
}

// XML redacts an etree tree in place. It is namespace-agnostic on purpose:
// a NameID is a NameID whatever prefix the vendor chose. Comment and CDATA
// children of sensitive elements are dropped too, since they are the vector
// for comment-injection attacks and would otherwise leak around the mask.
func XML(root *etree.Element) {
	if root == nil {
		return
	}
	if kind, ok := xmlSensitive[root.Tag]; ok {
		text := strings.TrimSpace(root.Text())
		// Replace every child token (text, comments, CDATA) with one mask.
		for len(root.Child) > 0 {
			root.RemoveChildAt(0)
		}
		root.SetText(Value(kind, text))
		return
	}
	for _, c := range root.ChildElements() {
		XML(c)
	}
}

// jwtSensitive lists claim names treated as identity-bearing or secret.
// Issuer, audience, timestamps, nonce, kid, alg, scopes and token type are
// not in this list: they are what a diagnosis is about.
var jwtSensitive = map[string]bool{
	"sub": true, "email": true, "emails": true, "name": true, "given_name": true,
	"family_name": true, "middle_name": true, "nickname": true, "preferred_username": true,
	"upn": true, "unique_name": true, "oid": true, "phone_number": true, "address": true,
	"picture": true, "ipaddr": true, "onprem_sid": true, "sid": true, "puid": true,
	"at_hash": true, "c_hash": true,
	"access_token": true, "refresh_token": true, "id_token": true, "code": true,
	"client_secret": true, "password": true, "groups": true, "wids": true,
}

// IsSensitiveClaim reports whether a JWT claim name is redacted.
func IsSensitiveClaim(name string) bool { return jwtSensitive[name] }

// Claims returns a copy of a decoded claim set with sensitive values masked.
// Arrays of strings are masked element-wise so the count stays visible.
func Claims(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if !jwtSensitive[k] {
			out[k] = v
			continue
		}
		out[k] = maskAny("claim:"+k, v)
	}
	return out
}

func maskAny(kind string, v any) any {
	switch t := v.(type) {
	case string:
		return Value(kind, t)
	case []any:
		masked := make([]any, len(t))
		for i, e := range t {
			masked[i] = maskAny(kind, e)
		}
		return masked
	case nil:
		return nil
	default:
		// Numbers, bools, objects: hash their textual form; we never
		// echo the structure of an address object either.
		return Value(kind, stringify(t))
	}
}

func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	}
	// Good enough for a hash input; precision is irrelevant here.
	return strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(fmtAny(v), "\n", ""), " ", ""))
}
