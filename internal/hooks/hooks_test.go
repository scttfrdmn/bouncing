package hooks

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/scttfrdmn/bouncing/internal/config"
)

// ── Sign / Verify ─────────────────────────────────────────────────────────────

func TestSignVerify(t *testing.T) {
	t.Parallel()
	body := []byte(`{"event":"user.created","payload":{}}`)
	secret := "test-secret"

	sig := Sign(body, secret)
	if sig == "" {
		t.Fatal("Sign returned empty signature")
	}
	if err := Verify(body, secret, sig); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerifyWrongSecret(t *testing.T) {
	t.Parallel()
	body := []byte(`{}`)
	sig := Sign(body, "secret-a")
	if err := Verify(body, "secret-b", sig); err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestVerifyTamperedBody(t *testing.T) {
	t.Parallel()
	sig := Sign([]byte(`{"ok":true}`), "secret")
	if err := Verify([]byte(`{"ok":false}`), "secret", sig); err == nil {
		t.Error("expected error for tampered body")
	}
}

func TestSignFormat(t *testing.T) {
	t.Parallel()
	sig := Sign([]byte("hello"), "key")
	if len(sig) < 7 || sig[:7] != "sha256=" {
		t.Errorf("expected sha256= prefix, got %q", sig)
	}
}

// ── eventMatches ──────────────────────────────────────────────────────────────

func TestEventMatches(t *testing.T) {
	t.Parallel()
	tests := []struct {
		patterns []string
		event    string
		want     bool
	}{
		{[]string{"user.created"}, "user.created", true},
		{[]string{"user.deleted"}, "user.created", false},
		{[]string{"*"}, "anything", true},
		{[]string{"user.created", "user.deleted"}, "user.deleted", true},
		{[]string{}, "user.created", false},
	}
	for _, tt := range tests {
		got := eventMatches(tt.patterns, tt.event)
		if got != tt.want {
			t.Errorf("eventMatches(%v, %q) = %v, want %v", tt.patterns, tt.event, got, tt.want)
		}
	}
}

// ── Dispatcher delivers events ────────────────────────────────────────────────

func TestDispatcherDelivers(t *testing.T) {
	received := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		event := r.Header.Get("X-Bouncing-Event")
		received <- event
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := NewDispatcher([]config.WebhookConfig{
		{URL: ts.URL, Events: []string{"user.created"}, Secret: "s3cr3t"},
	}, log)

	d.Dispatch(context.Background(), "user.created", map[string]any{"user_id": "abc"})

	select {
	case event := <-received:
		if event != "user.created" {
			t.Errorf("event: got %q, want %q", event, "user.created")
		}
	case <-time.After(2 * time.Second):
		t.Error("webhook not delivered within 2 seconds")
	}
}

func TestDispatcherFiltersEvents(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := NewDispatcher([]config.WebhookConfig{
		{URL: ts.URL, Events: []string{"user.deleted"}}, // only listens to deleted
	}, log)

	// Dispatch "user.created" — should NOT reach the server.
	d.Dispatch(context.Background(), "user.created", nil)
	time.Sleep(50 * time.Millisecond) // give goroutine time to run if it does

	if called {
		t.Error("dispatcher should not have called the webhook for a non-matching event")
	}
}

func TestDispatcherIncludesSignature(t *testing.T) {
	sigCh := make(chan string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sigCh <- r.Header.Get("X-Hub-Signature-256")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := NewDispatcher([]config.WebhookConfig{
		{URL: ts.URL, Events: []string{"*"}, Secret: "webhook-secret"},
	}, log)

	d.Dispatch(context.Background(), "test.event", map[string]any{})

	select {
	case sig := <-sigCh:
		if len(sig) < 7 || sig[:7] != "sha256=" {
			t.Errorf("signature format: got %q", sig)
		}
	case <-time.After(2 * time.Second):
		t.Error("webhook not delivered")
	}
}
