package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

// UserInfo holds the normalized profile returned by each provider.
type UserInfo struct {
	ProviderID string
	Email      string
	Name       string
	AvatarURL  string
}

// Provider wraps an oauth2.Config and knows how to fetch a UserInfo.
type Provider struct {
	Name   string
	config *oauth2.Config
}

// AuthCodeURL returns the authorization redirect URL with the given state.
func (p *Provider) AuthCodeURL(state string) string {
	return p.config.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// Exchange trades the authorization code for tokens then fetches the user profile.
func (p *Provider) Exchange(ctx context.Context, code string) (*UserInfo, error) {
	tok, err := p.config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oauth.%s.Exchange: %w", p.Name, err)
	}
	client := p.config.Client(ctx, tok)

	switch p.Name {
	case "google":
		return fetchGoogle(client)
	case "github":
		return fetchGitHub(client)
	case "microsoft":
		return fetchMicrosoft(client)
	case "apple":
		return fetchApple(tok) // tok implements tokenExtraer
	default:
		return nil, fmt.Errorf("oauth.Exchange: unknown provider %q", p.Name)
	}
}

// NewProvider builds a Provider for the named service.
func NewProvider(name, clientID, clientSecret, redirectURL string) (*Provider, error) {
	var endpoint oauth2.Endpoint
	var scopes []string

	switch name {
	case "google":
		endpoint = google.Endpoint
		scopes = []string{"openid", "email", "profile"}
	case "github":
		endpoint = github.Endpoint
		scopes = []string{"read:user", "user:email"}
	case "microsoft":
		endpoint = microsoft.AzureADEndpoint("common")
		scopes = []string{"openid", "email", "profile", "User.Read"}
	case "apple":
		endpoint = oauth2.Endpoint{
			AuthURL:  "https://appleid.apple.com/auth/authorize",
			TokenURL: "https://appleid.apple.com/auth/token",
		}
		scopes = []string{"name", "email"}
	default:
		return nil, fmt.Errorf("oauth.NewProvider: unknown provider %q", name)
	}

	return &Provider{
		Name: name,
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
			Endpoint:     endpoint,
		},
	}, nil
}

// ── per-provider fetchers ─────────────────────────────────────────────────────

func fetchGoogle(client *http.Client) (*UserInfo, error) {
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, fmt.Errorf("google userinfo: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var v struct {
		Sub     string `json:"sub"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("google userinfo decode: %w", err)
	}
	return &UserInfo{ProviderID: v.Sub, Email: v.Email, Name: v.Name, AvatarURL: v.Picture}, nil
}

func fetchGitHub(client *http.Client) (*UserInfo, error) {
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("github user: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var v struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("github user decode: %w", err)
	}

	email := v.Email
	if email == "" {
		var fetchErr error
		email, fetchErr = fetchGitHubPrimaryEmail(client)
		if fetchErr != nil {
			return nil, fetchErr
		}
	}

	name := v.Name
	if name == "" {
		name = v.Login
	}
	return &UserInfo{
		ProviderID: fmt.Sprintf("%d", v.ID),
		Email:      email,
		Name:       name,
		AvatarURL:  v.AvatarURL,
	}, nil
}

func fetchGitHubPrimaryEmail(client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", fmt.Errorf("github emails: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", fmt.Errorf("github emails decode: %w", err)
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", fmt.Errorf("github: no primary verified email found")
}

func fetchMicrosoft(client *http.Client) (*UserInfo, error) {
	resp, err := client.Get("https://graph.microsoft.com/v1.0/me")
	if err != nil {
		return nil, fmt.Errorf("microsoft graph: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var v struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		UserPrincipalName string `json:"userPrincipalName"`
		Mail              string `json:"mail"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return nil, fmt.Errorf("microsoft graph decode: %w", err)
	}
	email := v.Mail
	if email == "" {
		email = v.UserPrincipalName
	}
	return &UserInfo{ProviderID: v.ID, Email: email, Name: v.DisplayName}, nil
}

// tokenExtraer allows extracting extra fields from an OAuth token.
// Satisfied by *oauth2.Token.
type tokenExtraer interface {
	Extra(key string) any
}

func fetchApple(tok tokenExtraer) (*UserInfo, error) {
	// Apple puts the profile in the id_token JWT claims.
	idTokenRaw, ok := tok.Extra("id_token").(string)
	if !ok || idTokenRaw == "" {
		return nil, fmt.Errorf("apple: no id_token in response")
	}

	parts := strings.Split(idTokenRaw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("apple: malformed id_token")
	}

	// Decode the payload (middle segment) without signature verification.
	// We accept the risk: Apple's id_token is delivered over TLS from
	// the token endpoint, so transport security is the integrity guarantee.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("apple: id_token payload decode: %w", err)
	}

	var claims struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("apple: id_token claims decode: %w", err)
	}
	return &UserInfo{ProviderID: claims.Sub, Email: claims.Email}, nil
}
