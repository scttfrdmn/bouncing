package session

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWKSHandler serves the public JWKS at both /.well-known/jwks.json and /auth/jwks.
// All keys in the ring are included so tokens signed by rotated keys can still
// be verified by clients during the grace period.
// Response is cached by clients for 1 hour (Cache-Control: public, max-age=3600).
type JWKSHandler struct {
	payload []byte
}

// NewJWKSHandler builds the JSON payload from all keys in the ring.
func NewJWKSHandler(ring *KeyRing) (*JWKSHandler, error) {
	set := jwk.NewSet()

	for _, ks := range ring.Keys {
		jwkKey, err := jwk.PublicKeyOf(ks.Public)
		if err != nil {
			return nil, fmt.Errorf("session.NewJWKSHandler: derive JWK for %s: %w", ks.KID, err)
		}
		if err := jwkKey.Set(jwk.KeyIDKey, ks.KID); err != nil {
			return nil, fmt.Errorf("session.NewJWKSHandler: set kid: %w", err)
		}
		if err := jwkKey.Set(jwk.KeyUsageKey, "sig"); err != nil {
			return nil, fmt.Errorf("session.NewJWKSHandler: set use: %w", err)
		}
		if err := set.AddKey(jwkKey); err != nil {
			return nil, fmt.Errorf("session.NewJWKSHandler: add key %s: %w", ks.KID, err)
		}
	}

	payload, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("session.NewJWKSHandler: marshal: %w", err)
	}

	return &JWKSHandler{payload: payload}, nil
}

// ServeHTTP serves the pre-built JWKS payload.
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.payload)
}
