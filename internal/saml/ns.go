// SPDX-License-Identifier: Apache-2.0

// Package saml decodes SAML 2.0 Responses from any binding, parses them into
// a Summary with namespace-safe lookups, and runs every validator without
// stopping at the first failure.
package saml

import "github.com/beevik/etree"

// Namespace URIs. Lookups compare these, never prefixes: Okta writes saml2:,
// Entra puts Response in the default namespace, Auth0 uses samlp:/saml:.
const (
	NSProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	NSAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	NSDSig      = "http://www.w3.org/2000/09/xmldsig#"
	NSXMLEnc    = "http://www.w3.org/2001/04/xmlenc#"

	StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
)

// child returns the first direct child with the given namespace URI and
// local name, or nil.
func child(el *etree.Element, ns, tag string) *etree.Element {
	if el == nil {
		return nil
	}
	for _, c := range el.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			return c
		}
	}
	return nil
}

// children returns every direct child with the given namespace URI and tag.
func children(el *etree.Element, ns, tag string) []*etree.Element {
	var out []*etree.Element
	if el == nil {
		return out
	}
	for _, c := range el.ChildElements() {
		if c.Tag == tag && c.NamespaceURI() == ns {
			out = append(out, c)
		}
	}
	return out
}

// path walks a chain of (ns, tag) pairs from el, returning nil if any hop
// is missing. It keeps parse.go readable without XPath.
func path(el *etree.Element, hops ...string) *etree.Element {
	cur := el
	for i := 0; i+1 < len(hops); i += 2 {
		cur = child(cur, hops[i], hops[i+1])
		if cur == nil {
			return nil
		}
	}
	return cur
}

// text returns trimmed element text, or "" for nil.
func text(el *etree.Element) string {
	if el == nil {
		return ""
	}
	return trim(el.Text())
}

// attr returns an attribute value, or "" if absent.
func attr(el *etree.Element, key string) string {
	if el == nil {
		return ""
	}
	return el.SelectAttrValue(key, "")
}

// hasComment reports whether an element has a comment token among its
// direct children: the Duo PSA-2017-003 / GitHub parser-differential vector.
func hasComment(el *etree.Element) bool {
	if el == nil {
		return false
	}
	for _, tok := range el.Child {
		if _, ok := tok.(*etree.Comment); ok {
			return true
		}
	}
	return false
}
