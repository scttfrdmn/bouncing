package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/h2non/gock"
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
	for _, name := range []string{"google", "github", "microsoft", "apple", "gitlab", "slack"} {
		cfg := OAuthProviderCfg{ClientID: "id", ClientSecret: "secret"}
		p, err := NewProvider(name, cfg, "https://example.com/callback")
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
	cfg := OAuthProviderCfg{ClientID: "id", ClientSecret: "secret"}
	_, err := NewProvider("twitter", cfg, "https://example.com/callback")
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

func TestFetchAppleNoIDToken(t *testing.T) {
	t.Parallel()
	tok := &mockToken{idToken: ""}
	_, err := fetchApple(tok)
	if err == nil {
		t.Error("expected error for missing id_token")
	}
}

func TestFetchAppleMalformedIDToken(t *testing.T) {
	t.Parallel()
	tok := &mockToken{idToken: "only.twoparts"}
	_, err := fetchApple(tok)
	if err == nil {
		t.Error("expected error for malformed id_token")
	}
}

// ── Provider fetcher tests with gock ──────────────────────────────────────

func TestFetchGoogleGock(t *testing.T) {
	defer gock.Off()
	gock.New("https://www.googleapis.com").
		Get("/oauth2/v3/userinfo").
		Reply(200).
		JSON(map[string]string{
			"sub":     "google-123",
			"email":   "alice@gmail.com",
			"name":    "Alice",
			"picture": "https://photo.example.com/alice.jpg",
		})

	info, err := fetchGoogle(http.DefaultClient)
	if err != nil {
		t.Fatalf("fetchGoogle: %v", err)
	}
	if info.ProviderID != "google-123" {
		t.Errorf("ProviderID: got %q", info.ProviderID)
	}
	if info.Email != "alice@gmail.com" {
		t.Errorf("Email: got %q", info.Email)
	}
	if info.Name != "Alice" {
		t.Errorf("Name: got %q", info.Name)
	}
	if info.AvatarURL != "https://photo.example.com/alice.jpg" {
		t.Errorf("AvatarURL: got %q", info.AvatarURL)
	}
}

func TestFetchGitHubGock(t *testing.T) {
	defer gock.Off()
	gock.New("https://api.github.com").
		Get("/user").
		Reply(200).
		JSON(map[string]any{
			"id":         42,
			"login":      "alice",
			"name":       "Alice Smith",
			"email":      "",
			"avatar_url": "https://avatars.example.com/42",
		})
	gock.New("https://api.github.com").
		Get("/user/emails").
		Reply(200).
		JSON([]map[string]any{
			{"email": "alice@work.com", "primary": false, "verified": true},
			{"email": "alice@home.com", "primary": true, "verified": true},
		})

	info, err := fetchGitHub(http.DefaultClient)
	if err != nil {
		t.Fatalf("fetchGitHub: %v", err)
	}
	if info.ProviderID != "42" {
		t.Errorf("ProviderID: got %q", info.ProviderID)
	}
	if info.Email != "alice@home.com" {
		t.Errorf("Email: got %q, want alice@home.com (primary)", info.Email)
	}
	if info.Name != "Alice Smith" {
		t.Errorf("Name: got %q", info.Name)
	}
}

func TestFetchGitHubWithInlineEmail(t *testing.T) {
	defer gock.Off()
	gock.New("https://api.github.com").
		Get("/user").
		Reply(200).
		JSON(map[string]any{
			"id":    99,
			"login": "bob",
			"name":  "",
			"email": "bob@github.com",
		})

	info, err := fetchGitHub(http.DefaultClient)
	if err != nil {
		t.Fatalf("fetchGitHub: %v", err)
	}
	if info.Email != "bob@github.com" {
		t.Errorf("Email: got %q, want bob@github.com", info.Email)
	}
	if info.Name != "bob" {
		t.Errorf("Name: got %q, want login fallback 'bob'", info.Name)
	}
}

func TestFetchMicrosoftGock(t *testing.T) {
	defer gock.Off()
	gock.New("https://graph.microsoft.com").
		Get("/v1.0/me").
		Reply(200).
		JSON(map[string]string{
			"id":                "ms-456",
			"displayName":       "Carol",
			"userPrincipalName": "carol@contoso.com",
			"mail":              "carol@contoso.com",
		})

	info, err := fetchMicrosoft(http.DefaultClient)
	if err != nil {
		t.Fatalf("fetchMicrosoft: %v", err)
	}
	if info.ProviderID != "ms-456" {
		t.Errorf("ProviderID: got %q", info.ProviderID)
	}
	if info.Email != "carol@contoso.com" {
		t.Errorf("Email: got %q", info.Email)
	}
}

func TestFetchGoogleError(t *testing.T) {
	defer gock.Off()
	gock.New("https://www.googleapis.com").
		Get("/oauth2/v3/userinfo").
		Reply(500).
		BodyString("internal error")

	// fetchGoogle reads the body regardless of status — but the JSON parse will fail.
	_, err := fetchGoogle(http.DefaultClient)
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestFetchGitHubNoPrimaryEmail(t *testing.T) {
	defer gock.Off()
	gock.New("https://api.github.com").
		Get("/user").
		Reply(200).
		JSON(map[string]any{
			"id":    55,
			"login": "noemail",
			"name":  "No Email",
			"email": "",
		})
	gock.New("https://api.github.com").
		Get("/user/emails").
		Reply(200).
		JSON([]map[string]any{
			{"email": "unverified@test.com", "primary": true, "verified": false},
			{"email": "notprimary@test.com", "primary": false, "verified": true},
		})

	_, err := fetchGitHub(http.DefaultClient)
	if err == nil {
		t.Error("expected error when no primary verified email")
	}
}

func TestFetchMicrosoftMailEmpty(t *testing.T) {
	defer gock.Off()
	gock.New("https://graph.microsoft.com").
		Get("/v1.0/me").
		Reply(200).
		JSON(map[string]string{
			"id":                "ms-789",
			"displayName":       "UPN User",
			"userPrincipalName": "upn@contoso.com",
			"mail":              "",
		})

	info, err := fetchMicrosoft(http.DefaultClient)
	if err != nil {
		t.Fatalf("fetchMicrosoft: %v", err)
	}
	if info.Email != "upn@contoso.com" {
		t.Errorf("Email fallback: got %q, want upn@contoso.com", info.Email)
	}
}

// ── BeginOAuth sets a redirect ────────────────────────────────────────────────

func TestBeginOAuthRedirects(t *testing.T) {
	t.Parallel()
	p, _ := NewProvider("google", OAuthProviderCfg{ClientID: "client-id", ClientSecret: "client-secret"}, "https://example.com/callback")
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
