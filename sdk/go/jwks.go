package bouncing

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	errInvalidToken   = errors.New("bouncing: invalid token")
	errTokenExpired   = errors.New("bouncing: token expired")
	errNoMatchingKey  = errors.New("bouncing: no matching key in JWKS")
	errInvalidJWKS    = errors.New("bouncing: invalid JWKS response")
)

// jwksCache fetches and caches Ed25519 public keys from a JWKS endpoint.
type jwksCache struct {
	url       string
	mu        sync.RWMutex
	keys      map[string]ed25519.PublicKey // kid → public key
	fetchedAt time.Time
	ttl       time.Duration
}

func newJWKSCache(url string) *jwksCache {
	return &jwksCache{
		url:  url,
		keys: make(map[string]ed25519.PublicKey),
		ttl:  1 * time.Hour,
	}
}

// verify parses and verifies a JWT, returning the Session.
func (c *jwksCache) verify(ctx context.Context, tokenStr string) (*Session, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errInvalidToken
	}

	// Decode header to get kid.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: decode header: %v", errInvalidToken, err)
	}
	var header struct {
		Alg string `json:"alg"`
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: parse header: %v", errInvalidToken, err)
	}
	if header.Alg != "" && header.Alg != "EdDSA" {
		return nil, fmt.Errorf("%w: unsupported algorithm %q", errInvalidToken, header.Alg)
	}

	// Decode payload.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %v", errInvalidToken, err)
	}

	// Decode signature.
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: decode signature: %v", errInvalidToken, err)
	}

	// Get the kid from claims if not in header (bouncing puts it in claims).
	var claimsRaw struct {
		KID string `json:"kid"`
	}
	_ = json.Unmarshal(payloadBytes, &claimsRaw)
	kid := header.KID
	if kid == "" {
		kid = claimsRaw.KID
	}

	// Refresh keys if needed.
	if err := c.ensureFresh(ctx); err != nil {
		return nil, err
	}

	// Find the matching key.
	key, err := c.getKey(kid)
	if err != nil {
		return nil, err
	}

	// Verify Ed25519 signature over "header.payload".
	signedContent := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(key, signedContent, sigBytes) {
		return nil, errInvalidToken
	}

	// Parse claims.
	var claims struct {
		Sub       string   `json:"sub"`
		Email     string   `json:"email"`
		Name      string   `json:"name"`
		AvatarURL string   `json:"avatar_url"`
		Roles     []string `json:"roles"`
		Perms     []string `json:"permissions"`
		OrgID     *string  `json:"org_id"`
		Exp       int64    `json:"exp"`
		Iat       int64    `json:"iat"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("%w: parse claims: %v", errInvalidToken, err)
	}

	// Check expiration.
	if time.Now().Unix() > claims.Exp {
		return nil, errTokenExpired
	}

	return &Session{
		UserID:      claims.Sub,
		Email:       claims.Email,
		Name:        claims.Name,
		AvatarURL:   claims.AvatarURL,
		Roles:       claims.Roles,
		Permissions: claims.Perms,
		OrgID:       claims.OrgID,
		ExpiresAt:   time.Unix(claims.Exp, 0),
	}, nil
}

func (c *jwksCache) ensureFresh(ctx context.Context) error {
	c.mu.RLock()
	fresh := time.Since(c.fetchedAt) < c.ttl && len(c.keys) > 0
	c.mu.RUnlock()
	if fresh {
		return nil
	}
	return c.refresh(ctx)
}

func (c *jwksCache) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.url, nil)
	if err != nil {
		return fmt.Errorf("bouncing: build JWKS request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("bouncing: fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", errInvalidJWKS, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("bouncing: read JWKS: %w", err)
	}

	var jwks struct {
		Keys []struct {
			KTY string `json:"kty"`
			CRV string `json:"crv"`
			KID string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("%w: %v", errInvalidJWKS, err)
	}

	keys := make(map[string]ed25519.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.KTY != "OKP" || k.CRV != "Ed25519" {
			continue
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(xBytes) != ed25519.PublicKeySize {
			continue
		}
		keys[k.KID] = ed25519.PublicKey(xBytes)
	}

	c.mu.Lock()
	c.keys = keys
	c.fetchedAt = time.Now()
	c.mu.Unlock()

	return nil
}

func (c *jwksCache) getKey(kid string) (ed25519.PublicKey, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if kid != "" {
		if key, ok := c.keys[kid]; ok {
			return key, nil
		}
	}
	// If no kid or kid not found, try any key (single-key setups).
	for _, key := range c.keys {
		return key, nil
	}
	return nil, errNoMatchingKey
}
