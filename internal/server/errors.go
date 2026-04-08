package server

import (
	"encoding/json"
	"net/http"
)

// Stable error code constants. These are part of the API contract and must not change.
const (
	ErrCodeInvalidState                 = "invalid_state"
	ErrCodeNotOnTheList                 = "not_on_the_list"
	ErrCodeTokenRevoked                 = "token_revoked"
	ErrCodeClonedAuthenticator          = "cloned_authenticator_detected"
	ErrCodeSessionExpired               = "session_expired"
	ErrCodeUnauthorized                 = "unauthorized"
	ErrCodeInvalidEmailFormat           = "invalid_email_format"
	ErrCodeInvalidRequest               = "invalid_request"
	ErrCodeNotFound                     = "not_found"
	ErrCodeInternalError                = "internal_error"
	ErrCodeProviderError                = "provider_error"
	ErrCodeVerificationFailed           = "verification_failed"
)

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

// writeJSON writes a JSON success response.
func writeJSON(w http.ResponseWriter, statusCode int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(v)
}
