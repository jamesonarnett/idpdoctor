// SPDX-License-Identifier: Apache-2.0

package eval

import "encoding/json"

func unmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
