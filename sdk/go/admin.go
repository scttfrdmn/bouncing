package bouncing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AdminClient provides access to the Bouncing management API.
type AdminClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// User represents a user returned by the management API.
type User struct {
	ID         string `json:"id"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	AuthMethod string `json:"auth_method"`
	CreatedAt  int64  `json:"created_at"`
	LastLogin  int64  `json:"last_login"`
}

// Role represents a role returned by the management API.
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

func newAdminClient(baseURL, apiKey string) *AdminClient {
	return &AdminClient{
		baseURL: baseURL,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// ListUsers returns all users.
func (a *AdminClient) ListUsers(ctx context.Context) ([]User, error) {
	var resp struct {
		Users []User `json:"users"`
	}
	if err := a.get(ctx, "/manage/users", &resp); err != nil {
		return nil, err
	}
	return resp.Users, nil
}

// InviteUser pre-provisions a user with the given email.
func (a *AdminClient) InviteUser(ctx context.Context, email, name, role string) (*User, error) {
	body := map[string]string{"email": email, "name": name, "role": role}
	var resp User
	if err := a.post(ctx, "/manage/users/invite", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteUser removes a user and revokes all their sessions.
func (a *AdminClient) DeleteUser(ctx context.Context, id string) error {
	return a.del(ctx, "/manage/users/"+id)
}

// ListRoles returns all roles.
func (a *AdminClient) ListRoles(ctx context.Context) ([]Role, error) {
	var resp struct {
		Roles []Role `json:"roles"`
	}
	if err := a.get(ctx, "/manage/roles", &resp); err != nil {
		return nil, err
	}
	return resp.Roles, nil
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

func (a *AdminClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "GET", a.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("bouncing.Admin: %w", err)
	}
	return a.do(req, out)
}

func (a *AdminClient) post(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("bouncing.Admin: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", a.baseURL+path, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("bouncing.Admin: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	return a.do(req, out)
}

func (a *AdminClient) del(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", a.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("bouncing.Admin: %w", err)
	}
	return a.do(req, nil)
}

func (a *AdminClient) do(req *http.Request, out any) error {
	req.Header.Set("Authorization", "Bearer "+a.apiKey)

	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("bouncing.Admin: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bouncing.Admin: %s %s: %d %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("bouncing.Admin: decode: %w", err)
		}
	}
	return nil
}
