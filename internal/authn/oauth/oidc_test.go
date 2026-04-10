package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverValid(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(OIDCConfig{
			Issuer:                "https://idp.example.com",
			AuthorizationEndpoint: "https://idp.example.com/authorize",
			TokenEndpoint:         "https://idp.example.com/token",
			UserinfoEndpoint:      "https://idp.example.com/userinfo",
			JWKSURI:               "https://idp.example.com/.well-known/jwks.json",
		})
	}))
	defer srv.Close()

	// Override the default HTTP client to trust the test TLS cert.
	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	cfg, err := Discover(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if cfg.AuthorizationEndpoint != "https://idp.example.com/authorize" {
		t.Errorf("AuthorizationEndpoint: got %q", cfg.AuthorizationEndpoint)
	}
	if cfg.TokenEndpoint != "https://idp.example.com/token" {
		t.Errorf("TokenEndpoint: got %q", cfg.TokenEndpoint)
	}
	if cfg.UserinfoEndpoint != "https://idp.example.com/userinfo" {
		t.Errorf("UserinfoEndpoint: got %q", cfg.UserinfoEndpoint)
	}
}

func TestDiscoverNon200(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := Discover(context.Background(), srv.URL)
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

func TestDiscoverMissingEndpoints(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": "https://idp.example.com",
			// Missing authorization_endpoint and token_endpoint
		})
	}))
	defer srv.Close()

	_, err := Discover(context.Background(), srv.URL)
	if err == nil {
		t.Error("expected error for missing endpoints")
	}
}

func TestFetchOIDCUserInfoValid(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"sub":     "oidc-user-123",
			"email":   "alice@corp.com",
			"name":    "Alice Corp",
			"picture": "https://idp.example.com/photos/alice.jpg",
		})
	}))
	defer srv.Close()

	info, err := fetchOIDCUserInfo(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchOIDCUserInfo: %v", err)
	}
	if info.ProviderID != "oidc-user-123" {
		t.Errorf("ProviderID: got %q", info.ProviderID)
	}
	if info.Email != "alice@corp.com" {
		t.Errorf("Email: got %q", info.Email)
	}
	if info.Name != "Alice Corp" {
		t.Errorf("Name: got %q", info.Name)
	}
	if info.AvatarURL != "https://idp.example.com/photos/alice.jpg" {
		t.Errorf("AvatarURL: got %q", info.AvatarURL)
	}
}

func TestFetchOIDCUserInfoError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	_, err := fetchOIDCUserInfo(srv.Client(), srv.URL)
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestDiscoverRejectsHTTP(t *testing.T) {
	t.Parallel()
	_, err := Discover(context.Background(), "http://evil.internal")
	if err == nil {
		t.Error("expected error for http:// issuer_url")
	}
}

func TestNewProviderOIDC(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		_ = json.NewEncoder(w).Encode(OIDCConfig{
			Issuer:                base,
			AuthorizationEndpoint: base + "/authorize",
			TokenEndpoint:         base + "/token",
			UserinfoEndpoint:      base + "/userinfo",
		})
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	cfg := OAuthProviderCfg{
		ClientID:     "corp-client",
		ClientSecret: "corp-secret",
		IssuerURL:    srv.URL,
	}
	p, err := NewProvider("corp-idp", cfg, "https://app.example.com/callback")
	if err != nil {
		t.Fatalf("NewProvider OIDC: %v", err)
	}
	if p.Name != "corp-idp" {
		t.Errorf("Name: got %q", p.Name)
	}
	if p.userinfoURL == "" {
		t.Error("userinfoURL should be set for OIDC provider")
	}
	if p.AuthCodeURL("state") == "" {
		t.Error("AuthCodeURL should produce a URL")
	}
}
