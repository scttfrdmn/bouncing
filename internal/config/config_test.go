package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bouncing.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	return path
}

func TestLoadMinimal(t *testing.T) {
	t.Parallel()
	path := writeYAML(t, `base_url: "https://auth.example.com"`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BaseURL != "https://auth.example.com" {
		t.Errorf("BaseURL: got %q", cfg.BaseURL)
	}
}

func TestLoadRateLimitDefaults(t *testing.T) {
	t.Parallel()
	path := writeYAML(t, `base_url: "https://auth.example.com"`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RateLimit.Rate != 10 {
		t.Errorf("RateLimit.Rate: got %v, want 10", cfg.RateLimit.Rate)
	}
	if cfg.RateLimit.Burst != 20 {
		t.Errorf("RateLimit.Burst: got %v, want 20", cfg.RateLimit.Burst)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Parallel()
	path := writeYAML(t, `base_url: "https://auth.example.com"`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Listen != ":3117" {
		t.Errorf("Listen: got %q, want :3117", cfg.Listen)
	}
	if cfg.Access.Mode != "open" {
		t.Errorf("Access.Mode: got %q, want open", cfg.Access.Mode)
	}
	if cfg.Session.AccessTokenTTL != 15*time.Minute {
		t.Errorf("AccessTokenTTL: got %v, want 15m", cfg.Session.AccessTokenTTL)
	}
	if cfg.Session.RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("RefreshTokenTTL: got %v, want 168h", cfg.Session.RefreshTokenTTL)
	}
	if cfg.I18n.DefaultLocale != "en" {
		t.Errorf("DefaultLocale: got %q, want en", cfg.I18n.DefaultLocale)
	}
	if cfg.Signing.Algorithm != "ed25519" {
		t.Errorf("Signing.Algorithm: got %q, want ed25519", cfg.Signing.Algorithm)
	}
	if cfg.Signing.KeysDir != "./data/keys" {
		t.Errorf("Signing.KeysDir: got %q, want ./data/keys", cfg.Signing.KeysDir)
	}
	if cfg.Store.Driver != "sqlite" {
		t.Errorf("Store.Driver: got %q, want sqlite", cfg.Store.Driver)
	}
	if cfg.Store.Path != "./data/bouncing.db" {
		t.Errorf("Store.Path: got %q, want ./data/bouncing.db", cfg.Store.Path)
	}
}

func TestLoadPreservesExplicitValues(t *testing.T) {
	t.Parallel()
	path := writeYAML(t, `
base_url: "https://auth.example.com"
listen: ":9090"
access:
  mode: invite-only
session:
  access_token_ttl: 5m
  refresh_token_ttl: 24h
i18n:
  default_locale: fr
signing:
  algorithm: ed25519
  keys_dir: /custom/keys
store:
  driver: sqlite
  path: /data/my.db
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Listen != ":9090" {
		t.Errorf("Listen: got %q", cfg.Listen)
	}
	if cfg.Access.Mode != "invite-only" {
		t.Errorf("Access.Mode: got %q", cfg.Access.Mode)
	}
	if cfg.Session.AccessTokenTTL != 5*time.Minute {
		t.Errorf("AccessTokenTTL: got %v", cfg.Session.AccessTokenTTL)
	}
	if cfg.Session.RefreshTokenTTL != 24*time.Hour {
		t.Errorf("RefreshTokenTTL: got %v", cfg.Session.RefreshTokenTTL)
	}
	if cfg.I18n.DefaultLocale != "fr" {
		t.Errorf("DefaultLocale: got %q", cfg.I18n.DefaultLocale)
	}
	if cfg.Store.Path != "/data/my.db" {
		t.Errorf("Store.Path: got %q", cfg.Store.Path)
	}
}

func TestLoadMissingBaseURL(t *testing.T) {
	t.Parallel()
	path := writeYAML(t, `listen: ":8080"`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing base_url")
	}
}

func TestLoadInvalidAccessMode(t *testing.T) {
	t.Parallel()
	path := writeYAML(t, `
base_url: "https://auth.example.com"
access:
  mode: "bogus"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid access mode")
	}
}

func TestLoadValidAccessModes(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"open", "domain-restricted", "invite-only"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			path := writeYAML(t, `
base_url: "https://auth.example.com"
access:
  mode: "`+mode+`"
`)
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Access.Mode != mode {
				t.Errorf("mode: got %q, want %q", cfg.Access.Mode, mode)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	t.Parallel()
	_, err := Load("/nonexistent/path/bouncing.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	t.Parallel()
	path := writeYAML(t, `{{{invalid yaml`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadFullConfig(t *testing.T) {
	t.Parallel()
	path := writeYAML(t, `
base_url: "https://auth.example.com"
auth:
  methods:
    oauth:
      google:
        client_id: "goog-id"
        client_secret: "goog-secret"
    passkeys:
      enabled: true
      rp_name: "My App"
      rp_id: "example.com"
      origins: ["https://example.com"]
  redirect_url: "/dashboard"
  logout_url: "/goodbye"
legal:
  enabled: true
  version: "v1.0"
  document_url: "https://example.com/terms"
  document_label: "Terms of Service"
webhooks:
  - url: "https://hooks.example.com/events"
    events: ["user.created", "user.login"]
    secret: "whsec_abc123"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Auth.Methods.OAuth["google"].ClientID != "goog-id" {
		t.Errorf("google client_id: got %q", cfg.Auth.Methods.OAuth["google"].ClientID)
	}
	if !cfg.Auth.Methods.Passkeys.Enabled {
		t.Error("passkeys should be enabled")
	}
	if cfg.Auth.RedirectURL != "/dashboard" {
		t.Errorf("redirect_url: got %q", cfg.Auth.RedirectURL)
	}
	if cfg.Legal == nil || !cfg.Legal.Enabled {
		t.Error("legal should be enabled")
	}
	if len(cfg.Webhooks) != 1 || cfg.Webhooks[0].URL != "https://hooks.example.com/events" {
		t.Errorf("webhooks: %+v", cfg.Webhooks)
	}
}
