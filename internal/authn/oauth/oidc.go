package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OIDCConfig holds the endpoints discovered from .well-known/openid-configuration.
type OIDCConfig struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Discover fetches the OIDC discovery document from {issuerURL}/.well-known/openid-configuration.
// issuerURL must use the https:// scheme to prevent SSRF against internal services.
func Discover(ctx context.Context, issuerURL string) (*OIDCConfig, error) {
	if !strings.HasPrefix(issuerURL, "https://") {
		return nil, fmt.Errorf("oidc.Discover: issuer_url must use https:// scheme, got %q", issuerURL)
	}
	wellKnown := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, "GET", wellKnown, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc.Discover: build request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc.Discover: fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc.Discover: %s returned %d", wellKnown, resp.StatusCode)
	}

	var cfg OIDCConfig
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("oidc.Discover: decode: %w", err)
	}

	if cfg.AuthorizationEndpoint == "" || cfg.TokenEndpoint == "" {
		return nil, fmt.Errorf("oidc.Discover: missing required endpoints in discovery document")
	}

	return &cfg, nil
}

// fetchOIDCUserInfo fetches the standard OIDC userinfo endpoint and returns
// normalized UserInfo. Works with any OIDC-compliant provider.
func fetchOIDCUserInfo(client *http.Client, userinfoEndpoint string) (*UserInfo, error) {
	resp, err := client.Get(userinfoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("oidc userinfo: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("oidc userinfo: %d %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oidc userinfo read: %w", err)
	}

	var claims struct {
		Sub     string `json:"sub"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, fmt.Errorf("oidc userinfo decode: %w", err)
	}

	return &UserInfo{
		ProviderID: claims.Sub,
		Email:      claims.Email,
		Name:       claims.Name,
		AvatarURL:  claims.Picture,
	}, nil
}
