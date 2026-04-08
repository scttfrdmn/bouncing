package session

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWKSHandler serves the public JWKS at both /.well-known/jwks.json and /auth/jwks.
// Response is cached by clients for 1 hour (Cache-Control: public, max-age=3600).
type JWKSHandler struct {
	payload []byte
}

// NewJWKSHandler builds the JSON payload from the active KeySet and returns a handler
// ready to be mounted on the mux.
func NewJWKSHandler(keys *KeySet) (*JWKSHandler, error) {
	jwkKey, err := jwk.PublicKeyOf(keys.Public)
	if err != nil {
		return nil, fmt.Errorf("session.NewJWKSHandler: derive JWK: %w", err)
	}

	if err := jwkKey.Set(jwk.KeyIDKey, keys.KID); err != nil {
		return nil, fmt.Errorf("session.NewJWKSHandler: set kid: %w", err)
	}
	if err := jwkKey.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return nil, fmt.Errorf("session.NewJWKSHandler: set use: %w", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(jwkKey); err != nil {
		return nil, fmt.Errorf("session.NewJWKSHandler: add key: %w", err)
	}

	payload, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("session.NewJWKSHandler: marshal: %w", err)
	}

	return &JWKSHandler{payload: payload}, nil
}

// ServeHTTP serves the pre-built JWKS payload.
func (h *JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.payload)
}
