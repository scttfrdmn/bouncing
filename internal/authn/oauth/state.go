package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const stateCookieName = "bouncing_oauth_state"

// ErrInvalidState is returned when the CSRF state cookie cannot be validated.
var ErrInvalidState = errors.New("invalid oauth state")

// StateManager generates and validates CSRF state parameters.
// The state is stored as an HMAC-signed cookie: base64url(nonce) + "." + hex(HMAC-SHA256(nonce, secret))
type StateManager struct {
	secret []byte
}

// NewStateManager creates a StateManager with the given secret.
func NewStateManager(secret []byte) *StateManager {
	return &StateManager{secret: secret}
}

// SetState generates a fresh nonce, signs it, stores it in a cookie on w,
// and returns the state string to embed in the authorization URL.
func (m *StateManager) SetState(w http.ResponseWriter, r *http.Request) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("oauth.SetState: %w", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(nonce)
	sig := m.sign(b64)
	state := b64 + "." + sig

	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    state,
		Path:     "/",
		MaxAge:   600, // 10 minutes
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	return state, nil
}

// ValidateState checks that stateParam matches the cookie stored by SetState.
// Clears the state cookie on success.
func (m *StateManager) ValidateState(w http.ResponseWriter, r *http.Request, stateParam string) error {
	cookie, err := r.Cookie(stateCookieName)
	if err != nil {
		return ErrInvalidState
	}
	// Clear cookie regardless of validation result to prevent reuse.
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
	})

	if !hmac.Equal([]byte(stateParam), []byte(cookie.Value)) {
		// Constant-time compare of the full state strings.
		return ErrInvalidState
	}

	// Also verify the HMAC within the state itself.
	parts := strings.SplitN(stateParam, ".", 2)
	if len(parts) != 2 {
		return ErrInvalidState
	}
	expected := m.sign(parts[0])
	if !hmac.Equal([]byte(expected), []byte(parts[1])) {
		return ErrInvalidState
	}
	return nil
}

func (m *StateManager) sign(data string) string {
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}
