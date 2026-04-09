package session

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/bouncing/internal/store"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func newTestIssuer(t *testing.T) *Issuer {
	t.Helper()
	keys, err := LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	return NewIssuer(keys, 15*time.Minute, "https://test.example.com")
}

func newTestIssuerShortTTL(t *testing.T, ttl time.Duration) *Issuer {
	t.Helper()
	keys, err := LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	return NewIssuer(keys, ttl, "https://test.example.com")
}

func sampleClaims() Claims {
	orgID := "org-123"
	return Claims{
		UserID:      "user-abc",
		Email:       "scott@example.com",
		Name:        "Scott",
		AvatarURL:   "https://example.com/avatar.png",
		Roles:       []string{"admin", "editor"},
		Permissions: []string{"*"},
		OrgID:       &orgID,
	}
}

// ── JWT Issue + Verify round-trip ─────────────────────────────────────────────

func TestIssueVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	issuer := newTestIssuer(t)
	ctx := context.Background()

	in := sampleClaims()
	token, err := issuer.Issue(ctx, in)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if token == "" {
		t.Fatal("Issue returned empty token")
	}

	out, err := issuer.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if out.UserID != in.UserID {
		t.Errorf("UserID: got %q, want %q", out.UserID, in.UserID)
	}
	if out.Email != in.Email {
		t.Errorf("Email: got %q, want %q", out.Email, in.Email)
	}
	if out.Name != in.Name {
		t.Errorf("Name: got %q, want %q", out.Name, in.Name)
	}
	if out.AvatarURL != in.AvatarURL {
		t.Errorf("AvatarURL: got %q, want %q", out.AvatarURL, in.AvatarURL)
	}
	if len(out.Roles) != len(in.Roles) || out.Roles[0] != in.Roles[0] {
		t.Errorf("Roles: got %v, want %v", out.Roles, in.Roles)
	}
	if len(out.Permissions) != 1 || out.Permissions[0] != "*" {
		t.Errorf("Permissions: got %v, want [*]", out.Permissions)
	}
	if out.OrgID == nil || *out.OrgID != *in.OrgID {
		t.Errorf("OrgID: got %v, want %v", out.OrgID, in.OrgID)
	}
}

func TestIssueVerifyNilOrgID(t *testing.T) {
	t.Parallel()
	issuer := newTestIssuer(t)
	ctx := context.Background()

	in := sampleClaims()
	in.OrgID = nil

	token, err := issuer.Issue(ctx, in)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	out, err := issuer.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.OrgID != nil {
		t.Errorf("OrgID: got %v, want nil", out.OrgID)
	}
}

// ── Tampered token ────────────────────────────────────────────────────────────

func TestVerifyTamperedToken(t *testing.T) {
	t.Parallel()
	issuer := newTestIssuer(t)
	ctx := context.Background()

	token, err := issuer.Issue(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Flip a character in the signature (last segment).
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	sig := []byte(parts[2])
	sig[0] ^= 0x01
	tampered := strings.Join([]string{parts[0], parts[1], string(sig)}, ".")

	_, err = issuer.Verify(ctx, tampered)
	if err == nil {
		t.Error("Verify should fail on tampered token")
	}
}

// ── Expired token ─────────────────────────────────────────────────────────────

func TestVerifyExpiredToken(t *testing.T) {
	t.Parallel()
	// Issue with negative TTL so the token is already expired.
	issuer := newTestIssuerShortTTL(t, -1*time.Second)
	ctx := context.Background()

	token, err := issuer.Issue(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = issuer.Verify(ctx, token)
	if err == nil {
		t.Error("Verify should fail on expired token")
	}
}

// ── Wrong key ─────────────────────────────────────────────────────────────────

func TestVerifyWrongKey(t *testing.T) {
	t.Parallel()
	issuer1 := newTestIssuer(t)
	issuer2 := newTestIssuer(t) // different temp dir → different keypair
	ctx := context.Background()

	token, err := issuer1.Issue(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, err = issuer2.Verify(ctx, token)
	if err == nil {
		t.Error("Verify should fail when verifying with a different key")
	}
}

// ── Refresh token: Issue + Rotate ────────────────────────────────────────────

func mustCreateUser(t *testing.T, ctx context.Context, db interface {
	CreateUser(context.Context, *store.User) error
}, id string) {
	t.Helper()
	u := &store.User{ID: id, Email: id + "@example.com", Status: "active"}
	if err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser(%q): %v", id, err)
	}
}

func TestRefreshIssueRotate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	mustCreateUser(t, ctx, db, "user-1")
	rm := NewRefreshManager(db, 7*24*time.Hour)

	raw, err := rm.Issue(ctx, "user-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.HasPrefix(raw, "bnc_rt_") {
		t.Errorf("token prefix: got %q", raw[:min(len(raw), 20)])
	}

	newRaw, userID, err := rm.Rotate(ctx, raw)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if userID != "user-1" {
		t.Errorf("Rotate userID: got %q, want %q", userID, "user-1")
	}
	if newRaw == raw {
		t.Error("Rotate should issue a different token")
	}
	if !strings.HasPrefix(newRaw, "bnc_rt_") {
		t.Errorf("new token prefix: got %q", newRaw[:min(len(newRaw), 20)])
	}
}

// ── Replay detection ──────────────────────────────────────────────────────────

func TestRefreshReplayDetection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	mustCreateUser(t, ctx, db, "user-2")
	rm := NewRefreshManager(db, 7*24*time.Hour)

	raw, err := rm.Issue(ctx, "user-2")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// First rotation succeeds.
	_, _, err = rm.Rotate(ctx, raw)
	if err != nil {
		t.Fatalf("Rotate first: %v", err)
	}

	// Second rotation of the already-consumed token → replay.
	_, _, err = rm.Rotate(ctx, raw)
	if !errors.Is(err, ErrTokenReplayed) {
		t.Errorf("expected ErrTokenReplayed, got %v", err)
	}
}

// ── Expired refresh token ─────────────────────────────────────────────────────

func TestRefreshExpired(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	mustCreateUser(t, ctx, db, "user-3")
	rm := NewRefreshManager(db, -1*time.Second) // already expired

	raw, err := rm.Issue(ctx, "user-3")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, _, err = rm.Rotate(ctx, raw)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", err)
	}
}

// ── Revoke ────────────────────────────────────────────────────────────────────

func TestRefreshRevoke(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	mustCreateUser(t, ctx, db, "user-4")
	rm := NewRefreshManager(db, 7*24*time.Hour)

	raw, err := rm.Issue(ctx, "user-4")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := rm.Revoke(ctx, raw); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Rotating a revoked token should look like a replay.
	_, _, err = rm.Rotate(ctx, raw)
	if !errors.Is(err, ErrTokenReplayed) {
		t.Errorf("expected ErrTokenReplayed after revoke, got %v", err)
	}
}

func TestRefreshRevokeAll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	mustCreateUser(t, ctx, db, "user-5")
	rm := NewRefreshManager(db, 7*24*time.Hour)

	raw1, _ := rm.Issue(ctx, "user-5")
	raw2, _ := rm.Issue(ctx, "user-5")

	if err := rm.RevokeAll(ctx, "user-5"); err != nil {
		t.Fatalf("RevokeAll: %v", err)
	}

	for _, raw := range []string{raw1, raw2} {
		_, _, err := rm.Rotate(ctx, raw)
		if !errors.Is(err, ErrTokenReplayed) {
			t.Errorf("expected ErrTokenReplayed after RevokeAll, got %v", err)
		}
	}
}

// ── Key rotation ─────────────────────────────────────────────────────────────

func TestRotateAndVerifyOldToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()

	// Load initial key ring (generates first key).
	ring1, err := LoadAll(dir)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	issuer1 := NewIssuer(ring1, 15*time.Minute, "https://test.example.com")

	// Issue a token with the first key.
	token, err := issuer1.Issue(ctx, sampleClaims())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Rotate — generates a new key.
	time.Sleep(time.Millisecond) // ensure different timestamp
	ring2, err := Rotate(dir)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if len(ring2.Keys) < 2 {
		t.Fatalf("expected ≥2 keys after rotation, got %d", len(ring2.Keys))
	}
	if ring2.Current.KID == ring1.Current.KID {
		t.Error("Rotate should produce a new current KID")
	}

	// Verify old token with new ring — should still work.
	issuer2 := NewIssuer(ring2, 15*time.Minute, "https://test.example.com")
	claims, err := issuer2.Verify(ctx, token)
	if err != nil {
		t.Fatalf("Verify old token with new ring: %v", err)
	}
	if claims.UserID != "user-abc" {
		t.Errorf("UserID: got %q", claims.UserID)
	}
}

func TestLoadAllMultipleKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Generate two keys.
	_, err := LoadAll(dir) // first key
	if err != nil {
		t.Fatalf("first LoadAll: %v", err)
	}
	time.Sleep(time.Millisecond)
	ring, err := Rotate(dir) // second key
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	if len(ring.Keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(ring.Keys))
	}

	// Current should be the newest (lexicographically last KID).
	for i := 1; i < len(ring.Keys); i++ {
		if ring.Keys[i].KID > ring.Keys[i-1].KID {
			t.Errorf("keys not sorted newest-first: %s > %s", ring.Keys[i].KID, ring.Keys[i-1].KID)
		}
	}
}

// ── JWKS handler ──────────────────────────────────────────────────────────────

func TestJWKSHandler(t *testing.T) {
	t.Parallel()
	keys, err := LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	h, err := NewJWKSHandler(keys)
	if err != nil {
		t.Fatalf("NewJWKSHandler: %v", err)
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	h.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: got %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=3600" {
		t.Errorf("Cache-Control: got %q", cc)
	}

	body := w.Body.String()
	if !strings.Contains(body, `"keys"`) {
		t.Errorf("body missing 'keys': %s", body)
	}
	if !strings.Contains(body, keys.Current.KID) {
		t.Errorf("body missing KID %q: %s", keys.Current.KID, body)
	}
	if !strings.Contains(body, `"OKP"`) {
		t.Errorf("body missing OKP key type: %s", body)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
