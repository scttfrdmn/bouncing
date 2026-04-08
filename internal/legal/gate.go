// Package legal implements the TOS/NDA acceptance gate.
package legal

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/scttfrdmn/bouncing/internal/config"
	"github.com/scttfrdmn/bouncing/internal/store"
)

const pendingCookieName = "bouncing_pending"

// Gate manages the legal acceptance flow.
type Gate struct {
	cfg    *config.LegalConfig
	store  store.Store
	secret []byte
	log    *slog.Logger
}

// NewGate creates a Gate. secret is used for HMAC signing the pending cookie.
func NewGate(st store.Store, cfg *config.LegalConfig, log *slog.Logger) *Gate {
	// Derive a signing secret from the document version.
	h := sha256.Sum256([]byte("bouncing-legal-" + cfg.Version))
	return &Gate{cfg: cfg, store: st, secret: h[:], log: log}
}

// NeedsAcceptance returns true if the user has not yet accepted the current version.
func (g *Gate) NeedsAcceptance(ctx context.Context, userID string) bool {
	a, err := g.store.GetTOSAcceptance(ctx, userID, g.cfg.Version)
	if err != nil || a == nil {
		return true
	}
	return false
}

// IssuePendingCookie sets the bouncing_pending cookie encoding userID + timestamp + HMAC.
func (g *Gate) IssuePendingCookie(w http.ResponseWriter, r *http.Request, userID string) error {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	data := userID + "." + ts
	sig := g.sign(data)
	value := base64.RawURLEncoding.EncodeToString([]byte(data + "." + sig))

	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     pendingCookieName,
		Value:    value,
		Path:     "/auth/agree",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

// ValidatePendingCookie reads and verifies the pending cookie, returning userID.
func (g *Gate) ValidatePendingCookie(r *http.Request) (string, error) {
	c, err := r.Cookie(pendingCookieName)
	if err != nil {
		return "", fmt.Errorf("legal: pending cookie missing")
	}

	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", fmt.Errorf("legal: pending cookie decode: %w", err)
	}

	// Format: userID.timestamp.sig
	parts := strings.SplitN(string(raw), ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("legal: pending cookie malformed")
	}
	userID, ts, sig := parts[0], parts[1], parts[2]
	data := userID + "." + ts

	expected := g.sign(data)
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		return "", fmt.Errorf("legal: pending cookie signature invalid")
	}

	// Check TTL.
	var tsInt int64
	if _, err := fmt.Sscan(ts, &tsInt); err != nil {
		return "", fmt.Errorf("legal: pending cookie timestamp: %w", err)
	}
	if time.Now().Unix()-tsInt > 600 {
		return "", fmt.Errorf("legal: pending cookie expired")
	}

	return userID, nil
}

// Record persists a TOS acceptance record.
func (g *Gate) Record(ctx context.Context, userID, name, ipAddr string) error {
	a := &store.TOSAcceptance{
		UserID:     userID,
		Version:    g.cfg.Version,
		NameTyped:  name,
		AcceptedAt: time.Now().Unix(),
		IPAddress:  ipAddr,
	}
	return g.store.CreateTOSAcceptance(ctx, a)
}

// ClearPendingCookie removes the pending cookie.
func (g *Gate) ClearPendingCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     pendingCookieName,
		Value:    "",
		Path:     "/auth/agree",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteStrictMode,
	})
}

func (g *Gate) sign(data string) string {
	mac := hmac.New(sha256.New, g.secret)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// DocumentURL returns the configured document URL.
func (g *Gate) DocumentURL() string { return g.cfg.DocumentURL }

// DocumentLabel returns the configured document label.
func (g *Gate) DocumentLabel() string { return g.cfg.DocumentLabel }

// Version returns the configured document version.
func (g *Gate) Version() string { return g.cfg.Version }
