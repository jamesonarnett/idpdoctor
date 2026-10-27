// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrFetch reports a transport-level failure (DNS, TLS, timeout, read). An
// HTTP response of any status is not an error: Check explains a 404 or an
// HTML body as findings, which is more useful than an error string.
var ErrFetch = errors.New("oidc: discovery fetch failed")

// maxDiscovery bounds a fetched document; real ones are a few KB.
const maxDiscovery = 1 << 20

// Fetch GETs the discovery document for issuerURL. It is the only network
// call this package makes and runs only because the caller passed an
// issuer_url. client nil means a default 10s client; tests pass httptest's.
func Fetch(ctx context.Context, client *http.Client, issuerURL string) ([]byte, Options, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	u := DiscoveryURL(issuerURL)
	opts := Options{FetchedFrom: u}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, opts, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, opts, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	defer resp.Body.Close()
	opts.FetchStatus = resp.StatusCode
	opts.ContentType = resp.Header.Get("Content-Type")
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscovery))
	if err != nil {
		return nil, opts, fmt.Errorf("%w: read body: %v", ErrFetch, err)
	}
	return body, opts, nil
}

// DiscoveryURL appends the well-known path to an issuer (Discovery 4.1:
// strip one terminating "/" first) unless it is already there.
func DiscoveryURL(issuerURL string) string {
	if strings.HasSuffix(issuerURL, wellKnown) {
		return issuerURL
	}
	return strings.TrimSuffix(issuerURL, "/") + wellKnown
}
