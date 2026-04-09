// Package bouncing provides a Go client SDK for the Bouncing auth service.
// It has zero external dependencies — only Go stdlib + crypto/ed25519.
//
// Usage:
//
//	client := bouncing.New(bouncing.Config{
//	    BaseURL: "https://auth.example.com",
//	    APIKey:  "bnc_api_...", // optional, for admin operations
//	})
//
//	// Verify a JWT from a request
//	session, err := client.VerifyToken(ctx, tokenString)
//
//	// Use as middleware
//	http.Handle("/protected", client.Protect(myHandler))
//	http.Handle("/admin", client.Require("admin")(adminHandler))
package bouncing

import (
	"context"
	"net/http"
	"time"
)

// Config holds the configuration for the Bouncing client.
type Config struct {
	BaseURL string // Base URL of the Bouncing server (e.g. "https://auth.example.com")
	APIKey  string // Management API key (optional — only needed for Admin operations)
}

// Client provides JWT verification, middleware, and management API access.
type Client struct {
	baseURL string
	jwks    *jwksCache
	Admin   *AdminClient
}

// Session represents the authenticated user's claims from a verified JWT.
type Session struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	AvatarURL   string    `json:"avatar_url"`
	Roles       []string  `json:"roles"`
	Permissions []string  `json:"permissions"`
	OrgID       *string   `json:"org_id,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// New creates a Bouncing client.
func New(cfg Config) *Client {
	c := &Client{
		baseURL: cfg.BaseURL,
		jwks:    newJWKSCache(cfg.BaseURL + "/.well-known/jwks.json"),
	}
	if cfg.APIKey != "" {
		c.Admin = newAdminClient(cfg.BaseURL, cfg.APIKey)
	}
	return c
}

// VerifyToken verifies a signed JWT and returns the Session on success.
// It fetches and caches the JWKS from the server automatically.
func (c *Client) VerifyToken(ctx context.Context, token string) (*Session, error) {
	return c.jwks.verify(ctx, token)
}

// HasRole returns true if the session has the given role.
func (s *Session) HasRole(role string) bool {
	for _, r := range s.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasPermission returns true if the session has the given permission.
// A wildcard "*" matches any permission.
func (s *Session) HasPermission(perm string) bool {
	for _, p := range s.Permissions {
		if p == "*" || p == perm {
			return true
		}
	}
	return false
}

// context key for storing Session in request context.
type contextKey struct{}

// SessionFromContext retrieves the Session stored by Protect middleware.
func SessionFromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(contextKey{}).(*Session)
	return s
}

func withSession(r *http.Request, s *Session) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), contextKey{}, s))
}
