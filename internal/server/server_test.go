package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/bouncing/internal/config"
	"github.com/scttfrdmn/bouncing/internal/session"
	"github.com/scttfrdmn/bouncing/internal/store"
)

// ── test helpers ──────────────────────────────────────────────────────────────

func newTestServer(t *testing.T) (*Server, store.Store) {
	t.Helper()
	db, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	cfg := &config.Config{
		Listen:  ":0",
		BaseURL: "http://localhost",
		Signing: config.SigningConfig{KeysDir: t.TempDir()},
		Session: config.SessionConfig{
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
		},
		Access: config.AccessConfig{Mode: "open"},
		I18n:   config.I18nConfig{DefaultLocale: "en"},
	}

	// Set before t.Parallel() — can't use t.Setenv in parallel tests,
	// so we set it here and restore manually.
	t.Setenv("BOUNCING_API_KEY", "bnc_api_test_key_for_testing_only_1234") //nolint:tenv

	srv, err := New(cfg, db, newDiscardLogger())
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return srv, db
}

func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ── middleware ────────────────────────────────────────────────────────────────

func TestRequestIDMiddleware(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := RequestIDFromContext(r.Context())
		if id == "" {
			t.Error("request ID missing from context")
		}
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	RequestID(next).ServeHTTP(w, r)

	if w.Header().Get("X-Request-Id") == "" {
		t.Error("X-Request-Id header not set")
	}
}

func TestRequestIDPassthrough(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := RequestIDFromContext(r.Context())
		if id != "my-request-id" {
			t.Errorf("expected 'my-request-id', got %q", id)
		}
		w.WriteHeader(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Request-Id", "my-request-id")
	RequestID(next).ServeHTTP(w, r)
}

func TestCORSPreflight(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called for preflight")
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("OPTIONS", "/auth/me", nil)
	r.Header.Set("Origin", "https://myapp.com")
	CORS(nil)(next).ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("CORS origin header not set")
	}
}

// ── RequireAuth middleware ────────────────────────────────────────────────────

func TestRequireAuthMissingToken(t *testing.T) {
	t.Parallel()
	keys, err := session.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	issuer := session.NewIssuer(keys, 15*time.Minute, "https://test.example.com")

	handler := RequireAuth(issuer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/me", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", w.Code)
	}
}

func TestRequireAuthValidToken(t *testing.T) {
	t.Parallel()
	keys, err := session.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	issuer := session.NewIssuer(keys, 15*time.Minute, "https://test.example.com")

	token, err := issuer.Issue(context.Background(), session.Claims{
		UserID: "user-1",
		Email:  "user@example.com",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	var gotClaims *session.Claims
	handler := RequireAuth(issuer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/me", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	if gotClaims == nil || gotClaims.UserID != "user-1" {
		t.Errorf("claims not set in context")
	}
}

// ── /auth/me ──────────────────────────────────────────────────────────────────

func TestHandleMeUnauthorized(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.HTTPHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/me", nil)
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", w.Code)
	}
}

func TestHandleMe(t *testing.T) {
	srv, _ := newTestServer(t)

	token, err := srv.issuer.Issue(context.Background(), session.Claims{
		UserID: "user-abc",
		Email:  "me@example.com",
		Name:   "Test User",
		Roles:  []string{"admin"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/me", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	srv.HTTPHandler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["id"] != "user-abc" {
		t.Errorf("id: got %v", body["id"])
	}
	if body["email"] != "me@example.com" {
		t.Errorf("email: got %v", body["email"])
	}
}

// ── JWKS endpoint ─────────────────────────────────────────────────────────────

func TestJWKSEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	h := srv.HTTPHandler()

	for _, path := range []string{"/.well-known/jwks.json", "/auth/jwks"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		h.ServeHTTP(w, r)

		if w.Code != http.StatusOK {
			t.Errorf("%s status: got %d, want 200", path, w.Code)
		}
		if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=3600") {
			t.Errorf("%s Cache-Control: got %q", path, cc)
		}
		var body map[string]any
		_ = json.NewDecoder(w.Body).Decode(&body)
		if _, ok := body["keys"]; !ok {
			t.Errorf("%s: missing 'keys' in response", path)
		}
	}
}

// ── /auth/refresh ──────────────────────────────────────────────────────────────

func TestHandleRefreshMissingToken(t *testing.T) {
	srv, _ := newTestServer(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/refresh", nil)
	srv.HTTPHandler().ServeHTTP(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
}

func TestHandleRefreshRotation(t *testing.T) {
	srv, db := newTestServer(t)
	ctx := context.Background()

	// Create a user and issue a refresh token.
	u := &store.User{ID: "user-refresh-1", Email: "r@example.com", Status: "active"}
	_ = db.CreateUser(ctx, u)

	rawToken, err := srv.refreshMgr.Issue(ctx, u.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/refresh",
		strings.NewReader(`{"refresh_token":"`+rawToken+`"}`))
	r.Header.Set("Content-Type", "application/json")
	srv.HTTPHandler().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["access_token"] == nil {
		t.Error("access_token missing from response")
	}
}

// ── /auth/logout ──────────────────────────────────────────────────────────────

func TestHandleLogout(t *testing.T) {
	srv, _ := newTestServer(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/logout", nil)
	srv.HTTPHandler().ServeHTTP(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status: got %d, want 302", w.Code)
	}
}
