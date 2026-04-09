package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/scttfrdmn/bouncing/internal/session"
)

// RequestID adds a unique X-Request-Id header and stores it in context.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Logger logs each request using slog.
func Logger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, code: http.StatusOK}
			next.ServeHTTP(rw, r)
			log.Info("http",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.code,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", RequestIDFromContext(r.Context()),
			)
		})
	}
}

// responseWriter captures the status code for logging.
type responseWriter struct {
	http.ResponseWriter
	code int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.code = code
	rw.ResponseWriter.WriteHeader(code)
}

// CORS adds permissive CORS headers. Origins are checked against an allowlist
// if provided; otherwise all origins are allowed (dev mode).
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				if len(allowedOrigins) == 0 || originAllowed(origin, allowedOrigins) {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Vary", "Origin")
				}
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func originAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(a, origin) {
			return true
		}
	}
	return false
}

// RequireAuth validates the Bearer token or bouncing_access cookie and stores
// the claims in context. Returns 401 on failure.
func RequireAuth(issuer *session.Issuer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := bearerToken(r)
			if tokenStr == "" {
				if c, err := r.Cookie("bouncing_access"); err == nil {
					tokenStr = c.Value
				}
			}
			if tokenStr == "" {
				writeError(w, http.StatusUnauthorized, ErrCodeUnauthorized, "authentication required")
				return
			}

			claims, err := issuer.Verify(r.Context(), tokenStr)
			if err != nil {
				writeError(w, http.StatusUnauthorized, ErrCodeSessionExpired, "token expired or invalid")
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAPIKey validates the Bearer token against an HMAC-SHA256 hash.
// The hash is compared using ValidateAPIKey from the mgmt package.
func RequireAPIKey(validate func(string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := bearerToken(r)
			if key == "" || !validate(key) {
				writeError(w, http.StatusUnauthorized, ErrCodeUnauthorized, "valid API key required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin chains RequireAuth + admin role check. Returns 401 if not
// authenticated, 403 if authenticated but not admin.
func RequireAdmin(issuer *session.Issuer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		inner := RequireAuth(issuer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			isAdmin := false
			for _, role := range claims.Roles {
				if role == "admin" {
					isAdmin = true
					break
				}
			}
			if !isAdmin {
				http.Error(w, "Forbidden — admin role required", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		}))
		return inner
	}
}

// RequireSCIMToken validates the Bearer token against a static SCIM token.
func RequireSCIMToken(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := bearerToken(r)
			if key == "" || key != token {
				writeError(w, http.StatusUnauthorized, ErrCodeUnauthorized, "valid SCIM token required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func bearerToken(r *http.Request) string {
	v := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(v, "Bearer "); ok {
		return after
	}
	return ""
}
