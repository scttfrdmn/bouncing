package audit

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/scttfrdmn/bouncing/internal/store"
)

type mockStore struct {
	entries []*store.AuditEntry
}

func (m *mockStore) CreateAuditEntry(_ context.Context, e *store.AuditEntry) error {
	m.entries = append(m.entries, e)
	return nil
}

func TestLogBasic(t *testing.T) {
	t.Parallel()
	ms := &mockStore{}
	l := New(ms, nil)

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Set("X-Request-Id", "req-123")

	l.Log(context.Background(), r, "user-1", "user.login", "user", "user-1", map[string]any{
		"method": "oauth:google",
	})

	if len(ms.entries) != 1 {
		t.Fatalf("entries: got %d, want 1", len(ms.entries))
	}
	e := ms.entries[0]
	if e.Action != "user.login" {
		t.Errorf("Action: got %q", e.Action)
	}
	if e.ActorID != "user-1" {
		t.Errorf("ActorID: got %q", e.ActorID)
	}
	if e.IPAddress != "10.0.0.1" {
		t.Errorf("IPAddress: got %q", e.IPAddress)
	}
	if e.RequestID != "req-123" {
		t.Errorf("RequestID: got %q", e.RequestID)
	}
	if e.Metadata == "" {
		t.Error("Metadata should not be empty")
	}
}

func TestLogWithXForwardedFor(t *testing.T) {
	t.Parallel()
	ms := &mockStore{}
	l := New(ms, nil)

	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")

	l.Log(context.Background(), r, "", "user.created", "", "", nil)

	if ms.entries[0].IPAddress != "203.0.113.50" {
		t.Errorf("IPAddress: got %q, want 203.0.113.50", ms.entries[0].IPAddress)
	}
}

func TestLogNilMetadata(t *testing.T) {
	t.Parallel()
	ms := &mockStore{}
	l := New(ms, nil)

	l.Log(context.Background(), nil, "admin", "role.assigned", "role", "r1", nil)

	if len(ms.entries) != 1 {
		t.Fatalf("entries: got %d", len(ms.entries))
	}
	if ms.entries[0].Metadata != "" {
		t.Errorf("Metadata: got %q, want empty", ms.entries[0].Metadata)
	}
}

func TestLogNilLogger(t *testing.T) {
	t.Parallel()
	var l *Logger
	// Should not panic.
	l.Log(context.Background(), nil, "", "", "", "", nil)
}

func TestLogNilStore(t *testing.T) {
	t.Parallel()
	l := New(nil, nil)
	// Should not panic.
	l.Log(context.Background(), nil, "", "", "", "", nil)
}
