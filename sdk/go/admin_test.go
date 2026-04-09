package bouncing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminListUsers(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/manage/users" {
			t.Errorf("path: got %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("auth: got %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"users": []map[string]any{
				{"id": "u1", "email": "a@b.com", "status": "active"},
			},
			"total": 1,
		})
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL, APIKey: "test-key"})
	users, err := client.Admin.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].Email != "a@b.com" {
		t.Errorf("users: %+v", users)
	}
}

func TestAdminInviteUser(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method: got %q", r.Method)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["email"] != "new@example.com" {
			t.Errorf("email: got %q", body["email"])
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "u2", "email": "new@example.com", "status": "pending",
		})
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL, APIKey: "test-key"})
	user, err := client.Admin.InviteUser(context.Background(), "new@example.com", "New User", "editor")
	if err != nil {
		t.Fatalf("InviteUser: %v", err)
	}
	if user.Email != "new@example.com" {
		t.Errorf("email: got %q", user.Email)
	}
}

func TestAdminDeleteUser(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" || r.URL.Path != "/manage/users/u1" {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL, APIKey: "test-key"})
	err := client.Admin.DeleteUser(context.Background(), "u1")
	if err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
}

func TestAdminListRoles(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"roles": []map[string]any{
				{"id": "r1", "name": "admin", "permissions": []string{"*"}},
			},
		})
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL, APIKey: "test-key"})
	roles, err := client.Admin.ListRoles(context.Background())
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 1 || roles[0].Name != "admin" {
		t.Errorf("roles: %+v", roles)
	}
}

func TestAdminServerError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal"}`))
	}))
	defer srv.Close()

	client := New(Config{BaseURL: srv.URL, APIKey: "test-key"})
	_, err := client.Admin.ListUsers(context.Background())
	if err == nil {
		t.Error("expected error for 500 response")
	}
}
