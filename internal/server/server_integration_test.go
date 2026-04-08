//go:build integration

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scttfrdmn/bouncing/internal/authz"
	"github.com/scttfrdmn/bouncing/internal/config"
	"github.com/scttfrdmn/bouncing/internal/hooks"
	"github.com/scttfrdmn/bouncing/internal/session"
	"github.com/scttfrdmn/bouncing/internal/store"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func newIntegrationServer(t *testing.T, cfg *config.Config) (*Server, store.Store) {
	t.Helper()
	db, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Setenv("BOUNCING_API_KEY", "bnc_api_integration_test_key_12345678")
	if cfg == nil {
		cfg = integrationConfig(t)
	}
	srv, err := New(cfg, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return srv, db
}

func integrationConfig(t *testing.T) *config.Config {
	return &config.Config{
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
}

// parseJWT decodes a JWT payload without verification.
func parseJWT(t *testing.T, tokenStr string) map[string]any {
	t.Helper()
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT: %q", tokenStr)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("JWT payload decode: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("JWT payload unmarshal: %v", err)
	}
	return claims
}

// ── Scenario 1: JWKS endpoint ─────────────────────────────────────────────────

func TestIntegration_JWKS(t *testing.T) {
	srv, _ := newIntegrationServer(t, nil)
	h := srv.HTTPHandler()

	for _, path := range []string{"/.well-known/jwks.json", "/auth/jwks"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", path, nil)
		h.ServeHTTP(w, r)

		if w.Code != 200 {
			t.Errorf("%s: status %d", path, w.Code)
		}
		if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=3600") {
			t.Errorf("%s Cache-Control: %q", path, cc)
		}
		var body map[string]any
		_ = json.NewDecoder(w.Body).Decode(&body)
		keys, _ := body["keys"].([]any)
		if len(keys) == 0 {
			t.Fatalf("%s: empty keys", path)
		}
		key := keys[0].(map[string]any)
		if key["kty"] != "OKP" {
			t.Errorf("%s: kty=%v, want OKP", path, key["kty"])
		}
		if key["crv"] != "Ed25519" {
			t.Errorf("%s: crv=%v, want Ed25519", path, key["crv"])
		}
	}
}

// ── Scenario 2: /auth/me with valid token ─────────────────────────────────────

func TestIntegration_AuthMe(t *testing.T) {
	srv, _ := newIntegrationServer(t, nil)
	h := srv.HTTPHandler()

	token, err := srv.issuer.Issue(context.Background(), session.Claims{
		UserID:      "user-001",
		Email:       "test@example.com",
		Name:        "Test User",
		Roles:       []string{"admin"},
		Permissions: []string{"*"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/me", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("/auth/me status: %d body: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["email"] != "test@example.com" {
		t.Errorf("email: %v", body["email"])
	}

	claims := parseJWT(t, token)
	if claims["sub"] != "user-001" {
		t.Errorf("sub: %v", claims["sub"])
	}
}

// ── Scenario 3: Refresh token rotation ────────────────────────────────────────

func TestIntegration_RefreshRotation(t *testing.T) {
	srv, db := newIntegrationServer(t, nil)
	h := srv.HTTPHandler()
	ctx := context.Background()

	u := &store.User{Email: "refresh@example.com", Status: "active"}
	if err := db.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	raw, err := srv.refreshMgr.Issue(ctx, u.ID)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/refresh",
		strings.NewReader(`{"refresh_token":"`+raw+`"}`))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Fatalf("refresh status: %d body: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	newToken := body["refresh_token"].(string)
	if newToken == raw {
		t.Error("new refresh token should differ from old")
	}
}

// ── Scenario 4: Refresh token replay detection ────────────────────────────────

func TestIntegration_RefreshReplay(t *testing.T) {
	srv, db := newIntegrationServer(t, nil)
	h := srv.HTTPHandler()
	ctx := context.Background()

	u := &store.User{Email: "replay@example.com", Status: "active"}
	_ = db.CreateUser(ctx, u)
	raw, _ := srv.refreshMgr.Issue(ctx, u.ID)

	doRefresh := func() int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/auth/refresh",
			strings.NewReader(`{"refresh_token":"`+raw+`"}`))
		r.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, r)
		return w.Code
	}

	if code := doRefresh(); code != 200 {
		t.Fatalf("first rotation failed: %d", code)
	}
	if code := doRefresh(); code != 401 {
		t.Errorf("replay: expected 401, got %d", code)
	}
}

// ── Scenario 5: Domain-restricted policy ─────────────────────────────────────

func TestIntegration_DomainRestricted(t *testing.T) {
	st, _ := store.NewSQLite(":memory:")
	defer st.Close()

	policy := authz.NewPolicy("domain-restricted", []string{"@allowed.com"})
	ctx := context.Background()

	if err := policy.Check(ctx, "user@allowed.com", st); err != nil {
		t.Errorf("allowed domain rejected: %v", err)
	}
	if err := policy.Check(ctx, "user@blocked.com", st); err == nil {
		t.Error("blocked domain not rejected")
	}
	// Case-insensitive.
	if err := policy.Check(ctx, "USER@ALLOWED.COM", st); err != nil {
		t.Errorf("case-insensitive match failed: %v", err)
	}
	// No subdomain.
	if err := policy.Check(ctx, "user@sub.allowed.com", st); err == nil {
		t.Error("subdomain should not be allowed")
	}
}

// ── Scenario 6: RBAC permissions sorted + deduped in JWT ─────────────────────

func TestIntegration_RBACPermissionsInJWT(t *testing.T) {
	srv, db := newIntegrationServer(t, nil)
	ctx := context.Background()

	u := &store.User{Email: "rbac@example.com", Status: "active"}
	_ = db.CreateUser(ctx, u)

	r1 := &store.Role{Name: "editor", Permissions: []string{"content:read", "content:write"}}
	r2 := &store.Role{Name: "reviewer", Permissions: []string{"content:read", "content:review"}}
	_ = db.CreateRole(ctx, r1)
	_ = db.CreateRole(ctx, r2)
	_ = db.AssignRole(ctx, u.ID, r1.ID, nil)
	_ = db.AssignRole(ctx, u.ID, r2.ID, nil)

	_, perms := srv.resolveRolesPerms(ctx, u.ID)

	wantPerms := []string{"content:read", "content:review", "content:write"}
	if len(perms) != len(wantPerms) {
		t.Fatalf("perms: got %v, want %v", perms, wantPerms)
	}
	for i, p := range wantPerms {
		if perms[i] != p {
			t.Errorf("perms[%d]: got %q, want %q", i, perms[i], p)
		}
	}
}

// ── Scenario 7: Management API CRUD ──────────────────────────────────────────

func TestIntegration_ManagementAPI(t *testing.T) {
	srv, db := newIntegrationServer(t, nil)
	h := srv.HTTPHandler()
	apiKey := "bnc_api_integration_test_key_12345678"

	authHeader := func(r *http.Request) *http.Request {
		r.Header.Set("Authorization", "Bearer "+apiKey)
		return r
	}

	// Invite.
	wInv := httptest.NewRecorder()
	h.ServeHTTP(wInv, authHeader(httptest.NewRequest("POST", "/manage/users/invite",
		bytes.NewBufferString(`{"email":"invited@example.com","name":"Inv"}`))).
		WithContext(contextWithContentType("application/json")))

	// Simpler: set header directly.
	wInv2 := httptest.NewRecorder()
	rInv := httptest.NewRequest("POST", "/manage/users/invite",
		bytes.NewBufferString(`{"email":"invited2@example.com"}`))
	rInv.Header.Set("Authorization", "Bearer "+apiKey)
	rInv.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(wInv2, rInv)

	if wInv2.Code != 201 {
		t.Fatalf("invite status: %d body: %s", wInv2.Code, wInv2.Body.String())
	}

	var invResp map[string]any
	_ = json.NewDecoder(wInv2.Body).Decode(&invResp)
	userID := invResp["id"].(string)

	// List.
	wList := httptest.NewRecorder()
	rList := httptest.NewRequest("GET", "/manage/users", nil)
	rList.Header.Set("Authorization", "Bearer "+apiKey)
	h.ServeHTTP(wList, rList)
	if wList.Code != 200 {
		t.Fatalf("list status: %d", wList.Code)
	}

	// Delete.
	wDel := httptest.NewRecorder()
	rDel := httptest.NewRequest("DELETE", "/manage/users/"+userID, nil)
	rDel.Header.Set("Authorization", "Bearer "+apiKey)
	h.ServeHTTP(wDel, rDel)
	if wDel.Code != 200 {
		t.Fatalf("delete status: %d body: %s", wDel.Code, wDel.Body.String())
	}

	_, err := db.GetUser(context.Background(), userID)
	if err == nil {
		t.Error("user should be deleted")
	}
}

// ── Scenario 8: API key required for /manage ─────────────────────────────────

func TestIntegration_ManagementAPIKeyRequired(t *testing.T) {
	srv, _ := newIntegrationServer(t, nil)
	h := srv.HTTPHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/manage/users", nil)
	h.ServeHTTP(w, r)

	if w.Code != 401 {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

// ── Scenario 9: Webhook HMAC signature ───────────────────────────────────────

func TestIntegration_WebhookHMAC(t *testing.T) {
	received := make(chan map[string]string, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received <- map[string]string{
			"event": r.Header.Get("X-Bouncing-Event"),
			"sig":   r.Header.Get("X-Hub-Signature-256"),
			"body":  string(body),
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	cfg := integrationConfig(t)
	cfg.Webhooks = []config.WebhookConfig{
		{URL: ts.URL, Events: []string{"*"}, Secret: "wh-secret"},
	}
	srv, _ := newIntegrationServer(t, cfg)
	srv.hooks.Dispatch(context.Background(), "test.event", map[string]any{"x": 1})

	select {
	case msg := <-received:
		if msg["event"] != "test.event" {
			t.Errorf("event: %q", msg["event"])
		}
		if !strings.HasPrefix(msg["sig"], "sha256=") {
			t.Errorf("sig format: %q", msg["sig"])
		}
		expectedSig := hooks.Sign([]byte(msg["body"]), "wh-secret")
		if msg["sig"] != expectedSig {
			t.Errorf("sig mismatch: got %q, want %q", msg["sig"], expectedSig)
		}
	case <-time.After(3 * time.Second):
		t.Error("webhook not delivered within 3 seconds")
	}
}

// ── Scenario 10: Logout clears cookies ───────────────────────────────────────

func TestIntegration_Logout(t *testing.T) {
	srv, _ := newIntegrationServer(t, nil)
	h := srv.HTTPHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/auth/logout", nil)
	h.ServeHTTP(w, r)

	if w.Code != 302 {
		t.Errorf("expected 302, got %d", w.Code)
	}
	// Check that cookies are cleared.
	var cleared []string
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			cleared = append(cleared, c.Name)
		}
	}
	for _, name := range []string{"bouncing_access", "bouncing_refresh"} {
		found := false
		for _, c := range cleared {
			if c == name {
				found = true
			}
		}
		if !found {
			t.Errorf("cookie %q not cleared on logout", name)
		}
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func contextWithContentType(ct string) context.Context {
	return context.Background() // placeholder — content type is set via header
}
