// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"encoding/json"
	"testing"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
