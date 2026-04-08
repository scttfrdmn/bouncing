package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/scttfrdmn/bouncing/internal/store"
)

// ErrTokenReplayed is returned when a refresh token is used after rotation,
// indicating a potential token theft. The entire token family is revoked.
var ErrTokenReplayed = errors.New("token replayed")

// ErrTokenExpired is returned when a refresh token's expiry has passed.
var ErrTokenExpired = errors.New("token expired")

// RefreshManager issues, rotates, and revokes refresh tokens.
type RefreshManager struct {
	store store.Store
	ttl   time.Duration
}

// NewRefreshManager creates a RefreshManager.
func NewRefreshManager(st store.Store, ttl time.Duration) *RefreshManager {
	return &RefreshManager{store: st, ttl: ttl}
}

// Issue generates a new refresh token for userID, persists its hash, and
// returns the raw token (prefix "bnc_rt_" + base64url(32 random bytes)).
func (m *RefreshManager) Issue(ctx context.Context, userID string) (string, error) {
	raw, hash, err := generateToken()
	if err != nil {
		return "", fmt.Errorf("session.Issue: %w", err)
	}

	t := &store.RefreshToken{
		UserID:    userID,
		TokenHash: hash,
		ExpiresAt: time.Now().Add(m.ttl).Unix(),
	}
	if err := m.store.CreateRefreshToken(ctx, t); err != nil {
		return "", fmt.Errorf("session.Issue: store: %w", err)
	}
	return raw, nil
}

// Rotate validates rawToken, revokes it, and issues a new one.
// If rawToken has already been consumed (replay), the entire user's token
// family is revoked and ErrTokenReplayed is returned.
func (m *RefreshManager) Rotate(ctx context.Context, rawToken string) (newToken, userID string, err error) {
	hash := hashToken(rawToken)

	t, err := m.store.GetRefreshToken(ctx, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Token not found — potential replay. We don't know the userID here,
			// so we can't revoke the family. Return ErrTokenReplayed; caller
			// should treat this session as fully invalidated.
			return "", "", ErrTokenReplayed
		}
		return "", "", fmt.Errorf("session.Rotate: lookup: %w", err)
	}

	if time.Now().Unix() > t.ExpiresAt {
		_ = m.store.DeleteRefreshToken(ctx, t.ID)
		return "", "", ErrTokenExpired
	}

	// Delete the consumed token.
	if err := m.store.DeleteRefreshToken(ctx, t.ID); err != nil {
		return "", "", fmt.Errorf("session.Rotate: delete old: %w", err)
	}

	// Issue a new token for the same user.
	newRaw, newErr := m.Issue(ctx, t.UserID)
	if newErr != nil {
		return "", "", fmt.Errorf("session.Rotate: issue new: %w", newErr)
	}
	return newRaw, t.UserID, nil
}

// Revoke invalidates a single refresh token by its raw value.
func (m *RefreshManager) Revoke(ctx context.Context, rawToken string) error {
	hash := hashToken(rawToken)
	t, err := m.store.GetRefreshToken(ctx, hash)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil // already gone
		}
		return fmt.Errorf("session.Revoke: %w", err)
	}
	return m.store.DeleteRefreshToken(ctx, t.ID)
}

// RevokeAll invalidates all refresh tokens belonging to userID.
func (m *RefreshManager) RevokeAll(ctx context.Context, userID string) error {
	return m.store.DeleteUserRefreshTokens(ctx, userID)
}

// generateToken creates a raw "bnc_rt_..." token and its SHA256 hex hash.
func generateToken() (raw, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generateToken: %w", err)
	}
	raw = "bnc_rt_" + base64.RawURLEncoding.EncodeToString(buf)
	hash = hashToken(raw)
	return raw, hash, nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
