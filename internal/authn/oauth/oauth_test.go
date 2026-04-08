package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── StateManager ──────────────────────────────────────────────────────────────

func TestStateRoundTrip(t *testing.T) {
	t.Parallel()
	mgr := NewStateManager([]byte("test-secret"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/oauth/google", nil)

	state, err := mgr.SetState(w, r)
	if err != nil {
		t.Fatalf("SetState: %v", err)
	}
	if state == "" {
		t.Fatal("SetState returned empty state")
	}

	// Simulate the callback request with the state param and cookie.
	cbReq := httptest.NewRequest("GET", "/auth/oauth/google/callback?state="+state, nil)
	for _, c := range w.Result().Cookies() {
		cbReq.AddCookie(c)
	}
	cbW := httptest.NewRecorder()

	if err := mgr.ValidateState(cbW, cbReq, state); err != nil {
		t.Errorf("ValidateState: %v", err)
	}
}

func TestStateReplay(t *testing.T) {
	t.Parallel()
	mgr := NewStateManager([]byte("test-secret"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	state, _ := mgr.SetState(w, r)

	// First validation clears the cookie.
	cbReq := httptest.NewRequest("GET", "/?state="+state, nil)
	for _, c := range w.Result().Cookies() {
		cbReq.AddCookie(c)
	}
	_ = mgr.ValidateState(httptest.NewRecorder(), cbReq, state)
	_ = state

	// Second attempt — cookie is gone → invalid state.
	cbReq2 := httptest.NewRequest("GET", "/?state="+state, nil)
	err := mgr.ValidateState(httptest.NewRecorder(), cbReq2, state)
	if err == nil {
		t.Error("expected error on state replay, got nil")
	}
}

func TestStateWrongValue(t *testing.T) {
	t.Parallel()
	mgr := NewStateManager([]byte("test-secret"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	_, _ = mgr.SetState(w, r)

	cbReq := httptest.NewRequest("GET", "/?state=wrong", nil)
	for _, c := range w.Result().Cookies() {
		cbReq.AddCookie(c)
	}

	err := mgr.ValidateState(httptest.NewRecorder(), cbReq, "wrong")
	if err == nil {
		t.Error("expected error for wrong state, got nil")
	}
}

func TestStateTamperedHMAC(t *testing.T) {
	t.Parallel()
	mgr := NewStateManager([]byte("test-secret"))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	state, _ := mgr.SetState(w, r)

	// Tamper the HMAC part (after the dot).
	idx := strings.LastIndex(state, ".")
	if idx < 0 {
		t.Fatal("state has no dot separator")
	}
	tampered := state[:idx+1] + "deadbeef"

	cbReq := httptest.NewRequest("GET", "/?state="+tampered, nil)
	for _, c := range w.Result().Cookies() {
		cbReq.AddCookie(c)
	}

	err := mgr.ValidateState(httptest.NewRecorder(), cbReq, tampered)
	if err == nil {
		t.Error("expected error for tampered HMAC, got nil")
	}
}

// ── Provider ──────────────────────────────────────────────────────────────────

func TestNewProviderKnown(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"google", "github", "microsoft", "apple"} {
		p, err := NewProvider(name, "id", "secret", "https://example.com/callback")
		if err != nil {
			t.Errorf("NewProvider(%q): %v", name, err)
		}
		if p.Name != name {
			t.Errorf("Name: got %q, want %q", p.Name, name)
		}
		if p.AuthCodeURL("state") == "" {
			t.Errorf("AuthCodeURL(%q): empty URL", name)
		}
	}
}

func TestNewProviderUnknown(t *testing.T) {
	t.Parallel()
	_, err := NewProvider("twitter", "id", "secret", "https://example.com/callback")
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

// ── fetchApple (JWT payload decoding) ─────────────────────────────────────────

func TestFetchAppleIDToken(t *testing.T) {
	t.Parallel()
	// Craft a minimal id_token with base64url-encoded payload.
	// Header: {"alg":"RS256"}
	// Payload: {"sub":"abc123","email":"user@icloud.com"}
	// Signature: fake
	header := "eyJhbGciOiJSUzI1NiJ9"
	payload := "eyJzdWIiOiJhYmMxMjMiLCJlbWFpbCI6InVzZXJAaWNsb3VkLmNvbSJ9"
	sig := "fakesig"
	idToken := header + "." + payload + "." + sig

	tok := &mockToken{idToken: idToken}
	info, err := fetchApple(tok)
	if err != nil {
		t.Fatalf("fetchApple: %v", err)
	}
	if info.ProviderID != "abc123" {
		t.Errorf("ProviderID: got %q, want %q", info.ProviderID, "abc123")
	}
	if info.Email != "user@icloud.com" {
		t.Errorf("Email: got %q, want %q", info.Email, "user@icloud.com")
	}
}

// ── BeginOAuth sets a redirect ────────────────────────────────────────────────

func TestBeginOAuthRedirects(t *testing.T) {
	t.Parallel()
	p, _ := NewProvider("google", "client-id", "client-secret", "https://example.com/callback")
	h := &Handler{
		provider: p,
		stateMgr: NewStateManager([]byte("secret")),
		log:      newDiscardLogger(),
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/auth/oauth/google", nil)
	h.BeginOAuth(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status: got %d, want 302", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "accounts.google.com") {
		t.Errorf("redirect location %q does not contain accounts.google.com", loc)
	}
}
