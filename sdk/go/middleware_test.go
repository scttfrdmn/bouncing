package bouncing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestClient(t *testing.T) (*Client, func(string) string) {
	t.Helper()
	pub, priv := generateTestKey(t)
	kid := "mw-test-key"
	srv := serveJWKS(t, pub, kid)

	client := New(Config{BaseURL: srv.URL})
	client.jwks.url = srv.URL

	sign := func(userID string) string {
		return signTestToken(t, priv, kid, map[string]any{
			"sub":         userID,
			"email":       userID + "@example.com",
			"roles":       []string{"admin"},
			"permissions": []string{"*"},
			"exp":         time.Now().Add(15 * time.Minute).Unix(),
		})
	}

	return client, sign
}

func TestProtectAllows(t *testing.T) {
	t.Parallel()
	client, sign := newTestClient(t)

	var gotSession *Session
	handler := client.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSession = SessionFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+sign("user-1"))
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	if gotSession == nil || gotSession.UserID != "user-1" {
		t.Errorf("session: %+v", gotSession)
	}
}

func TestProtectRejectsNoToken(t *testing.T) {
	t.Parallel()
	client, _ := newTestClient(t)

	handler := client.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want 401", w.Code)
	}
}

func TestProtectReadsCookie(t *testing.T) {
	t.Parallel()
	client, sign := newTestClient(t)

	handler := client.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "bouncing_access", Value: sign("user-2")})
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
}

func TestRequireRole(t *testing.T) {
	t.Parallel()
	client, sign := newTestClient(t)

	handler := client.Protect(client.Require("admin")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	// Admin role — should pass.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+sign("user-1"))
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("admin: got %d, want 200", w.Code)
	}
}

func TestRequireRoleForbidden(t *testing.T) {
	t.Parallel()
	pub, priv := generateTestKey(t)
	kid := "role-test"
	srv := serveJWKS(t, pub, kid)
	client := New(Config{BaseURL: srv.URL})
	client.jwks.url = srv.URL

	// Token with "viewer" role, require "admin".
	token := signTestToken(t, priv, kid, map[string]any{
		"sub":   "user-1",
		"roles": []string{"viewer"},
		"exp":   time.Now().Add(15 * time.Minute).Unix(),
	})

	handler := client.Protect(client.Require("admin")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status: got %d, want 403", w.Code)
	}
}

func TestSessionFromContextNil(t *testing.T) {
	t.Parallel()
	s := SessionFromContext(context.Background())
	if s != nil {
		t.Error("expected nil session from empty context")
	}
}
