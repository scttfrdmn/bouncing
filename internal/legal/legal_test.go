package legal

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scttfrdmn/bouncing/internal/config"
	"github.com/scttfrdmn/bouncing/internal/store"
)

func newTestGate(t *testing.T) (*Gate, store.Store) {
	t.Helper()
	db, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	cfg := &config.LegalConfig{
		Enabled:       true,
		Version:       "1.0",
		DocumentURL:   "https://example.com/tos",
		DocumentLabel: "Terms of Service",
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewGate(db, cfg, log), db
}

// ── NeedsAcceptance ───────────────────────────────────────────────────────────

func TestNeedsAcceptanceTrue(t *testing.T) {
	t.Parallel()
	g, _ := newTestGate(t)

	// No acceptance record exists → needs acceptance.
	if !g.NeedsAcceptance(context.Background(), "user-new") {
		t.Error("expected NeedsAcceptance=true for user with no record")
	}
}

func TestNeedsAcceptanceFalse(t *testing.T) {
	t.Parallel()
	g, db := newTestGate(t)
	ctx := context.Background()

	u := &store.User{Email: "tos@example.com", Status: "active"}
	_ = db.CreateUser(ctx, u)

	_ = db.CreateTOSAcceptance(ctx, &store.TOSAcceptance{
		UserID:     u.ID,
		Version:    "1.0",
		NameTyped:  "Jane Smith",
		AcceptedAt: 1712505600,
		IPAddress:  "127.0.0.1",
	})

	if g.NeedsAcceptance(ctx, u.ID) {
		t.Error("expected NeedsAcceptance=false after acceptance recorded")
	}
}

// ── Pending cookie round-trip ─────────────────────────────────────────────────

func TestPendingCookieRoundTrip(t *testing.T) {
	t.Parallel()
	g, _ := newTestGate(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/agree", nil)

	if err := g.IssuePendingCookie(w, r, "user-abc"); err != nil {
		t.Fatalf("IssuePendingCookie: %v", err)
	}

	// Build a request with the cookie.
	cbReq := httptest.NewRequest("GET", "/auth/agree", nil)
	for _, c := range w.Result().Cookies() {
		cbReq.AddCookie(c)
	}

	userID, err := g.ValidatePendingCookie(cbReq)
	if err != nil {
		t.Fatalf("ValidatePendingCookie: %v", err)
	}
	if userID != "user-abc" {
		t.Errorf("userID: got %q, want %q", userID, "user-abc")
	}
}

func TestPendingCookieMissing(t *testing.T) {
	t.Parallel()
	g, _ := newTestGate(t)

	r := httptest.NewRequest("GET", "/auth/agree", nil)
	_, err := g.ValidatePendingCookie(r)
	if err == nil {
		t.Error("expected error for missing cookie")
	}
}

func TestPendingCookieTampered(t *testing.T) {
	t.Parallel()
	g, _ := newTestGate(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/agree", nil)
	_ = g.IssuePendingCookie(w, r, "user-1")

	cbReq := httptest.NewRequest("GET", "/auth/agree", nil)
	for _, c := range w.Result().Cookies() {
		// Tamper: append extra character to value.
		c.Value += "x"
		cbReq.AddCookie(c)
	}

	_, err := g.ValidatePendingCookie(cbReq)
	if err == nil {
		t.Error("expected error for tampered cookie")
	}
}

// ── Record ────────────────────────────────────────────────────────────────────

func TestRecord(t *testing.T) {
	t.Parallel()
	g, db := newTestGate(t)
	ctx := context.Background()

	u := &store.User{Email: "record@example.com", Status: "active"}
	_ = db.CreateUser(ctx, u)

	if err := g.Record(ctx, u.ID, "Jane Smith", "127.0.0.1"); err != nil {
		t.Fatalf("Record: %v", err)
	}

	// NeedsAcceptance should now return false.
	if g.NeedsAcceptance(ctx, u.ID) {
		t.Error("expected NeedsAcceptance=false after Record")
	}
}

// ── Accessor methods ─────────────────────────────────────────────────────────

func TestDocumentAccessors(t *testing.T) {
	t.Parallel()
	g, _ := newTestGate(t)

	if g.DocumentURL() != "https://example.com/tos" {
		t.Errorf("DocumentURL: got %q", g.DocumentURL())
	}
	if g.DocumentLabel() != "Terms of Service" {
		t.Errorf("DocumentLabel: got %q", g.DocumentLabel())
	}
	if g.Version() != "1.0" {
		t.Errorf("Version: got %q", g.Version())
	}
}

// ── ClearPendingCookie ───────────────────────────────────────────────────────

func TestClearPendingCookie(t *testing.T) {
	t.Parallel()
	g, _ := newTestGate(t)

	// Issue a cookie.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/agree", nil)
	_ = g.IssuePendingCookie(w, r, "user-clear")

	// Clear it.
	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/auth/agree", nil)
	g.ClearPendingCookie(w2, r2)

	// The clear cookie should have MaxAge=-1.
	for _, c := range w2.Result().Cookies() {
		if c.Name == "bouncing_pending" && c.MaxAge != -1 {
			t.Errorf("expected MaxAge=-1, got %d", c.MaxAge)
		}
	}
}

// ── ShowAgreement handler ────────────────────────────────────────────────────

func TestShowAgreementRendersHTML(t *testing.T) {
	t.Parallel()
	g, db := newTestGate(t)

	h := NewHandler(g, nil, nil, db, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Issue a pending cookie first.
	wCookie := httptest.NewRecorder()
	rCookie := httptest.NewRequest("GET", "/auth/agree", nil)
	_ = g.IssuePendingCookie(wCookie, rCookie, "user-show")

	// Build request with the pending cookie.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/agree", nil)
	for _, c := range wCookie.Result().Cookies() {
		r.AddCookie(c)
	}

	h.ShowAgreement(w, r)

	if w.Code != 200 {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "https://example.com/tos") {
		t.Error("HTML missing document URL")
	}
	if !strings.Contains(body, "Terms of Service") {
		t.Error("HTML missing document label")
	}
}

func TestShowAgreementNoCookie(t *testing.T) {
	t.Parallel()
	g, db := newTestGate(t)
	h := NewHandler(g, nil, nil, db, nil, nil, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/agree", nil)
	h.ShowAgreement(w, r)

	if w.Code != 400 {
		t.Errorf("status: got %d, want 400", w.Code)
	}
}
