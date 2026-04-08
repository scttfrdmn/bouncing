// Package hooks provides HMAC-signed webhook dispatch with async retry.
package hooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Sign returns the HMAC-SHA256 signature of body using secret,
// in the format "sha256=<hex>" (same format as GitHub webhooks).
func Sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks that sig matches Sign(body, secret).
// Uses constant-time comparison.
func Verify(body []byte, secret, sig string) error {
	expected := Sign(body, secret)
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return fmt.Errorf("hooks: signature mismatch")
	}
	return nil
}
