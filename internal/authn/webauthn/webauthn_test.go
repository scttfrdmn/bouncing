package webauthn

import (
	"context"
	"fmt"
	"testing"
	"time"

	gowa "github.com/go-webauthn/webauthn/webauthn"

	"github.com/scttfrdmn/bouncing/internal/store"
)

// ── SessionStore ──────────────────────────────────────────────────────────────

func TestSessionStoreSaveLoad(t *testing.T) {
	t.Parallel()
	stop := make(chan struct{})
	defer close(stop)
	s := NewSessionStore(stop)

	data := &gowa.SessionData{Challenge: "abc123"}
	s.Save("user-1", data)

	got := s.Load("user-1")
	if got == nil {
		t.Error("Load returned nil for existing entry")
	} else if got.Challenge != "abc123" {
		t.Errorf("Challenge: got %q, want %q", got.Challenge, "abc123")
	}

	// Second load should return nil (consumed).
	if s.Load("user-1") != nil {
		t.Error("expected nil on second Load (entry should be consumed)")
	}
}

func TestSessionStoreMiss(t *testing.T) {
	t.Parallel()
	stop := make(chan struct{})
	defer close(stop)
	s := NewSessionStore(stop)

	if s.Load("nonexistent") != nil {
		t.Error("expected nil for missing key")
	}
}

func TestSessionStoreExpiry(t *testing.T) {
	t.Parallel()
	stop := make(chan struct{})
	defer close(stop)
	s := NewSessionStore(stop)

	// Manually insert an already-expired entry.
	s.mu.Lock()
	s.entries["expired"] = &sessionEntry{
		data:      &gowa.SessionData{Challenge: "xyz"},
		expiresAt: time.Now().Add(-1 * time.Second),
	}
	s.mu.Unlock()

	if s.Load("expired") != nil {
		t.Error("expected nil for expired entry")
	}
}

func TestSessionStoreOverwrite(t *testing.T) {
	t.Parallel()
	stop := make(chan struct{})
	defer close(stop)
	s := NewSessionStore(stop)

	s.Save("user-2", &gowa.SessionData{Challenge: "first"})
	s.Save("user-2", &gowa.SessionData{Challenge: "second"})

	got := s.Load("user-2")
	if got == nil {
		t.Error("Load returned nil")
	} else if got.Challenge != "second" {
		t.Errorf("expected second save to overwrite first, got %q", got.Challenge)
	}
}

// ── webAuthnUser adapter ──────────────────────────────────────────────────────

func TestWebAuthnUserID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_ = ctx

	u := newWebAuthnUser(
		newTestUser("01JTEST0000000000000000001"),
		nil,
	)

	id := u.WebAuthnID()
	if len(id) == 0 {
		t.Error("WebAuthnID returned empty bytes")
	}
}

func TestWebAuthnUserDisplayName(t *testing.T) {
	t.Parallel()
	u := newWebAuthnUser(newTestUser("01JTEST0000000000000000002"), nil)
	if u.WebAuthnDisplayName() == "" {
		t.Error("WebAuthnDisplayName is empty")
	}
	if u.WebAuthnName() == "" {
		t.Error("WebAuthnName is empty")
	}
}

// ── ulidFromBytes ──────────────────────────────────────────────────────────────

func TestULIDFromBytes(t *testing.T) {
	t.Parallel()
	import_ulid := "01JTEST0000000000000000001"
	wu := newWebAuthnUser(newTestUser(import_ulid), nil)
	b := wu.WebAuthnID()

	reconstructed, err := ulidFromBytes(b)
	if err != nil {
		t.Fatalf("ulidFromBytes: %v", err)
	}
	if reconstructed != import_ulid {
		t.Errorf("roundtrip: got %q, want %q", reconstructed, import_ulid)
	}
}

func TestULIDFromBytesInvalidLength(t *testing.T) {
	t.Parallel()
	_, err := ulidFromBytes([]byte("tooshort"))
	if err == nil {
		t.Error("expected error for wrong-length bytes")
	}
}

// ── WebAuthn adapter tests ───────────────────────────────────────────────────

func TestWebAuthnCredentials(t *testing.T) {
	t.Parallel()
	creds := []*store.WebAuthnCredential{
		{ID: "cred-1", PublicKey: []byte("pk1"), SignCount: 5},
		{ID: "cred-2", PublicKey: []byte("pk2"), SignCount: 10},
	}
	u := newWebAuthnUser(newTestUser("01JTEST0000000000000000001"), creds)

	got := u.WebAuthnCredentials()
	if len(got) != 2 {
		t.Fatalf("credentials: got %d, want 2", len(got))
	}
	if string(got[0].PublicKey) != "pk1" {
		t.Errorf("cred[0] public key: got %q", got[0].PublicKey)
	}
	if got[1].Authenticator.SignCount != 10 {
		t.Errorf("cred[1] sign count: got %d", got[1].Authenticator.SignCount)
	}
}

func TestWebAuthnCredentialsEmpty(t *testing.T) {
	t.Parallel()
	u := newWebAuthnUser(newTestUser("01JTEST0000000000000000002"), nil)
	got := u.WebAuthnCredentials()
	if len(got) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(got))
	}
}

func TestWebAuthnNameIsEmail(t *testing.T) {
	t.Parallel()
	u := newWebAuthnUser(newTestUser("01JTEST0000000000000000003"), nil)
	if u.WebAuthnName() != u.user.Email {
		t.Errorf("WebAuthnName: got %q, want %q", u.WebAuthnName(), u.user.Email)
	}
}

func TestWebAuthnDisplayNameFallback(t *testing.T) {
	t.Parallel()
	user := newTestUser("01JTEST0000000000000000004")
	user.Name = ""
	u := newWebAuthnUser(user, nil)
	if u.WebAuthnDisplayName() != user.Email {
		t.Errorf("DisplayName fallback: got %q, want %q", u.WebAuthnDisplayName(), user.Email)
	}
}

func TestSessionStoreExpiredLoadReturnsNil(t *testing.T) {
	t.Parallel()
	stop := make(chan struct{})
	defer close(stop)
	s := NewSessionStore(stop)

	// Insert an expired entry directly.
	s.mu.Lock()
	s.entries["expired-cleanup"] = &sessionEntry{
		data:      &gowa.SessionData{Challenge: "test"},
		expiresAt: time.Now().Add(-1 * time.Minute),
	}
	s.mu.Unlock()

	// Load should return nil for expired entries (checked at load time).
	if s.Load("expired-cleanup") != nil {
		t.Error("expected nil for expired entry on Load")
	}
}

func TestSessionStoreConcurrent(t *testing.T) {
	t.Parallel()
	stop := make(chan struct{})
	defer close(stop)
	s := NewSessionStore(stop)

	// Concurrent Save/Load should not panic.
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func(n int) {
			key := fmt.Sprintf("user-%d", n)
			s.Save(key, &gowa.SessionData{Challenge: key})
			_ = s.Load(key)
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}
