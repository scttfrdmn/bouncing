package webauthn

import (
	"context"
	"testing"
	"time"

	gowa "github.com/go-webauthn/webauthn/webauthn"
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
		t.Fatal("Load returned nil for existing entry")
	}
	if got.Challenge != "abc123" {
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
		t.Fatal("Load returned nil")
	}
	if got.Challenge != "second" {
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
