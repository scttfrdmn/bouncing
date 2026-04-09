package bouncing

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Protect returns middleware that requires a valid session.
// The session is stored in the request context and can be retrieved
// with SessionFromContext.
//
// Token is read from the Authorization header (Bearer scheme) or the
// bouncing_access cookie.
//
// Returns 401 with a JSON error body on failure.
func (c *Client) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			writeAuthError(w, "authentication required")
			return
		}

		session, err := c.VerifyToken(r.Context(), token)
		if err != nil {
			writeAuthError(w, "invalid or expired token")
			return
		}

		next.ServeHTTP(w, withSession(r, session))
	})
}

// Require returns middleware that checks for a specific role.
// Must be used after Protect (session must be in context).
func (c *Client) Require(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session := SessionFromContext(r.Context())
			if session == nil {
				writeAuthError(w, "authentication required")
				return
			}
			if !session.HasRole(role) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]string{
						"code":    "forbidden",
						"message": "insufficient permissions",
					},
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		if after, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return after
		}
	}
	if c, err := r.Cookie("bouncing_access"); err == nil {
		return c.Value
	}
	return ""
}

func writeAuthError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"code":    "unauthorized",
			"message": msg,
		},
	})
}
