package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen    string           `yaml:"listen"`
	BaseURL   string           `yaml:"base_url"`
	Store     StoreConfig      `yaml:"store"`
	Signing   SigningConfig    `yaml:"signing"`
	Access    AccessConfig     `yaml:"access"`
	Auth      AuthConfig       `yaml:"auth"`
	Session   SessionConfig    `yaml:"session"`
	RBAC      RBACConfig       `yaml:"rbac"`
	Legal     *LegalConfig     `yaml:"legal,omitempty"`
	I18n      I18nConfig       `yaml:"i18n"`
	Webhooks  []WebhookConfig  `yaml:"webhooks"`
	Directory *DirectoryConfig `yaml:"directory,omitempty"`
}

type StoreConfig struct {
	Driver string `yaml:"driver"` // "sqlite" | "turso"
	Path   string `yaml:"path"`
	URL    string `yaml:"url,omitempty"` // for turso
}

type SigningConfig struct {
	Algorithm string `yaml:"algorithm"` // "ed25519"
	KeysDir   string `yaml:"keys_dir"`
}

type AccessConfig struct {
	Mode           string   `yaml:"mode"` // "open" | "domain-restricted" | "invite-only"
	AllowedDomains []string `yaml:"allowed_domains,omitempty"`
}

type AuthConfig struct {
	Methods     AuthMethodsConfig `yaml:"methods"`
	RedirectURL string            `yaml:"redirect_url"` // where to send users after login
	ErrorURL    string            `yaml:"error_url"`    // where to send users on auth failure
	LogoutURL   string            `yaml:"logout_url"`   // where to redirect after logout
	CORSOrigins []string          `yaml:"cors_origins"` // allowed CORS origins (empty = all)
}

type AuthMethodsConfig struct {
	OAuth    map[string]OAuthProviderConfig `yaml:"oauth"`
	Passkeys PasskeyConfig                  `yaml:"passkeys"`
}

type OAuthProviderConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

type PasskeyConfig struct {
	Enabled bool     `yaml:"enabled"`
	RPName  string   `yaml:"rp_name"`
	RPID    string   `yaml:"rp_id"`
	Origins []string `yaml:"origins"`
}

type SessionConfig struct {
	AccessTokenTTL  time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl"`
}

type RBACConfig struct {
	Roles map[string]RoleConfig `yaml:"roles"`
}

type RoleConfig struct {
	Permissions []string `yaml:"permissions"`
}

type LegalConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Version       string `yaml:"version"`
	DocumentURL   string `yaml:"document_url"`
	DocumentLabel string `yaml:"document_label"`
}

type I18nConfig struct {
	DefaultLocale string `yaml:"default_locale"` // BCP 47; defaults to "en"
}

type WebhookConfig struct {
	URL    string   `yaml:"url"`
	Events []string `yaml:"events"`
	Secret string   `yaml:"secret"`
}

type DirectoryConfig struct {
	Provider        string            `yaml:"provider"`
	Domain          string            `yaml:"domain"`
	ServiceAccount  string            `yaml:"service_account"`
	SyncInterval    time.Duration     `yaml:"sync_interval"`
	AutoDeprovision bool              `yaml:"auto_deprovision"`
	DefaultRole     string            `yaml:"default_role"`
	RoleMapping     map[string]string `yaml:"role_mapping"`
}

// Load reads and parses bouncing.yaml from path.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var cfg Config
	if err := yaml.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: decode: %w", err)
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	applyDefaults(&cfg)
	return &cfg, nil
}

func validate(cfg *Config) error {
	if cfg.BaseURL == "" {
		return fmt.Errorf("config: base_url is required")
	}
	switch cfg.Access.Mode {
	case "open", "domain-restricted", "invite-only":
	case "":
		// will be set by applyDefaults
	default:
		return fmt.Errorf("config: invalid access mode %q, must be open|domain-restricted|invite-only", cfg.Access.Mode)
	}
	return nil
}

func applyDefaults(cfg *Config) {
	if cfg.Listen == "" {
		cfg.Listen = ":3117"
	}
	if cfg.Access.Mode == "" {
		cfg.Access.Mode = "open"
	}
	if cfg.Session.AccessTokenTTL == 0 {
		cfg.Session.AccessTokenTTL = 15 * time.Minute
	}
	if cfg.Session.RefreshTokenTTL == 0 {
		cfg.Session.RefreshTokenTTL = 7 * 24 * time.Hour
	}
	if cfg.I18n.DefaultLocale == "" {
		cfg.I18n.DefaultLocale = "en"
	}
	if cfg.Signing.Algorithm == "" {
		cfg.Signing.Algorithm = "ed25519"
	}
	if cfg.Signing.KeysDir == "" {
		cfg.Signing.KeysDir = "./data/keys"
	}
	if cfg.Store.Driver == "" {
		cfg.Store.Driver = "sqlite"
	}
	if cfg.Store.Path == "" {
		cfg.Store.Path = "./data/bouncing.db"
	}
}
