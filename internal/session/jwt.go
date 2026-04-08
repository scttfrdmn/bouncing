package session

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Claims represents the application-level JWT payload.
type Claims struct {
	UserID      string
	Email       string
	Name        string
	AvatarURL   string
	Roles       []string
	Permissions []string
	OrgID       *string
}

// Issuer signs and verifies access tokens.
type Issuer struct {
	keys *KeySet
	ttl  time.Duration
	iss  string // base URL (issuer claim)
}

// NewIssuer creates an Issuer with the given keys, TTL, and issuer URL.
func NewIssuer(keys *KeySet, ttl time.Duration, iss string) *Issuer {
	return &Issuer{keys: keys, ttl: ttl, iss: iss}
}

// Issue creates a signed JWT for the given claims.
func (i *Issuer) Issue(_ context.Context, c Claims) (string, error) {
	now := time.Now()

	b := jwt.NewBuilder().
		Issuer(i.iss).
		Subject(c.UserID).
		IssuedAt(now).
		Expiration(now.Add(i.ttl)).
		Claim("email", c.Email).
		Claim("name", c.Name).
		Claim("avatar_url", c.AvatarURL).
		Claim("roles", c.Roles).
		Claim("permissions", c.Permissions).
		Claim("org_id", c.OrgID).
		Claim("kid", i.keys.KID)

	token, err := b.Build()
	if err != nil {
		return "", fmt.Errorf("session.Issue: build: %w", err)
	}

	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA(), i.keys.Private))
	if err != nil {
		return "", fmt.Errorf("session.Issue: sign: %w", err)
	}
	return string(signed), nil
}

// Verify parses and validates a signed JWT, returning the Claims on success.
func (i *Issuer) Verify(_ context.Context, tokenStr string) (*Claims, error) {
	token, err := jwt.Parse(
		[]byte(tokenStr),
		jwt.WithKey(jwa.EdDSA(), i.keys.Public),
		jwt.WithValidate(true),
	)
	if err != nil {
		return nil, fmt.Errorf("session.Verify: %w", err)
	}

	c := &Claims{}
	c.UserID, _ = token.Subject()

	var email string
	if token.Get("email", &email) == nil {
		c.Email = email
	}
	var name string
	if token.Get("name", &name) == nil {
		c.Name = name
	}
	var avatarURL string
	if token.Get("avatar_url", &avatarURL) == nil {
		c.AvatarURL = avatarURL
	}
	var roles any
	if token.Get("roles", &roles) == nil {
		c.Roles = toStringSlice(roles)
	}
	var permissions any
	if token.Get("permissions", &permissions) == nil {
		c.Permissions = toStringSlice(permissions)
	}
	var orgID any
	if token.Get("org_id", &orgID) == nil {
		if s, ok := orgID.(string); ok && s != "" {
			c.OrgID = &s
		}
	}

	return c, nil
}

func toStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
