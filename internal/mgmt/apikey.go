// Package mgmt provides the management API HTTP handlers and API key authentication.
package mgmt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// APIKey validates management API keys via HMAC-SHA256.
// The raw key is never stored; only its SHA256 hash is kept.
type APIKey struct {
	hash string // hex(SHA256(raw))
}

// NewAPIKey creates an APIKey from the raw key string.
func NewAPIKey(raw string) *APIKey {
	return &APIKey{hash: hashAPIKey(raw)}
}

// Validate returns true if the provided key's hash matches the stored hash.
// Uses constant-time comparison.
func (k *APIKey) Validate(provided string) bool {
	got := hashAPIKey(provided)
	return hmac.Equal([]byte(got), []byte(k.hash))
}

func hashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
