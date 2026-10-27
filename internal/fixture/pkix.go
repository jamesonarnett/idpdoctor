// SPDX-License-Identifier: Apache-2.0

package fixture

import (
	"crypto/rsa"
	"crypto/x509"
)

func marshalPKIX(pub *rsa.PublicKey) ([]byte, error) { return x509.MarshalPKIXPublicKey(pub) }
