// Package config exposes the public configuration types for bouncing.
// All types are aliases of their internal counterparts.
//
// External consumers (e.g. bouncing-managed) should use Load to parse a
// bouncing.yaml and pass the resulting *Config to pkg/server.New.
package config

import iconfig "github.com/scttfrdmn/bouncing/internal/config"

// Config is the top-level bouncing configuration parsed from bouncing.yaml.
type Config = iconfig.Config

// StoreConfig holds storage backend settings.
type StoreConfig = iconfig.StoreConfig

// SigningConfig holds JWT signing key settings.
type SigningConfig = iconfig.SigningConfig

// AccessConfig controls who is allowed to authenticate.
type AccessConfig = iconfig.AccessConfig

// AuthConfig holds authentication method configuration.
type AuthConfig = iconfig.AuthConfig

// AuthMethodsConfig groups OAuth and passkey settings.
type AuthMethodsConfig = iconfig.AuthMethodsConfig

// OAuthProviderConfig holds credentials for a single OAuth provider.
type OAuthProviderConfig = iconfig.OAuthProviderConfig

// PasskeyConfig holds WebAuthn / passkey settings.
type PasskeyConfig = iconfig.PasskeyConfig

// SessionConfig controls access-token and refresh-token TTLs.
type SessionConfig = iconfig.SessionConfig

// RBACConfig holds role definitions seeded at startup.
type RBACConfig = iconfig.RBACConfig

// RoleConfig holds the permissions for a named role.
type RoleConfig = iconfig.RoleConfig

// LegalConfig controls the terms-of-service gate.
type LegalConfig = iconfig.LegalConfig

// I18nConfig controls locale settings.
type I18nConfig = iconfig.I18nConfig

// WebhookConfig describes a static (config-file) webhook endpoint.
type WebhookConfig = iconfig.WebhookConfig

// DirectoryConfig controls external directory sync (e.g. Google Workspace).
type DirectoryConfig = iconfig.DirectoryConfig

// RateLimitConfig controls the per-IP token-bucket rate limiter.
type RateLimitConfig = iconfig.RateLimitConfig

// SCIMConfig controls the SCIM 2.0 provisioning endpoint.
type SCIMConfig = iconfig.SCIMConfig

// Load reads and parses the bouncing.yaml at path, applies defaults, and
// validates required fields.
func Load(path string) (*Config, error) { return iconfig.Load(path) }
