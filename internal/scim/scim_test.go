package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scttfrdmn/bouncing/internal/store"
)

// ── mock store ───────────────────────────────────────────────────────────────

type mockStore struct {
	users map[string]*store.User
	roles []*store.Role
}

func newMockStore() *mockStore {
	return &mockStore{users: make(map[string]*store.User)}
}

func (m *mockStore) CreateUser(_ context.Context, u *store.User) error {
	if u.ID == "" {
		u.ID = "generated-" + u.Email
	}
	if _, ok := m.users[u.Email]; ok {
		return store.ErrNotFound // reuse as conflict signal
	}
	m.users[u.ID] = u
	return nil
}

func (m *mockStore) GetUser(_ context.Context, id string) (*store.User, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return u, nil
}

func (m *mockStore) UpdateUser(_ context.Context, u *store.User) error {
	m.users[u.ID] = u
	return nil
}

func (m *mockStore) DeleteUser(_ context.Context, id string) error {
	if _, ok := m.users[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.users, id)
	return nil
}

func (m *mockStore) ListRoles(_ context.Context) ([]*store.Role, error) {
	return m.roles, nil
}

type noopHooks struct{}

func (n *noopHooks) Dispatch(_ context.Context, _ string, _ any) {}

func newTestHandler() *Handler {
	return NewHandler(newMockStore(), &noopHooks{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func jsonBody(v any) *bytes.Buffer {
	b, _ := json.Marshal(v)
	return bytes.NewBuffer(b)
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestCreateUser(t *testing.T) {
	t.Parallel()
	h := newTestHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/scim/v2/Users", jsonBody(map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":    "alice@example.com",
		"displayName": "Alice",
		"active":      true,
	}))
	h.CreateUser(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("status: got %d; body: %s", w.Code, w.Body.String())
	}

	var resp scimUser
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.UserName != "alice@example.com" {
		t.Errorf("userName: got %q", resp.UserName)
	}
	if !resp.Active {
		t.Error("expected active=true")
	}
}

func TestCreateUserMissingUserName(t *testing.T) {
	t.Parallel()
	h := newTestHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/scim/v2/Users", jsonBody(map[string]any{
		"displayName": "No Email",
	}))
	h.CreateUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
}

func TestGetUser(t *testing.T) {
	t.Parallel()
	ms := newMockStore()
	ms.users["u1"] = &store.User{ID: "u1", Email: "bob@example.com", Name: "Bob", Status: "active"}
	h := NewHandler(ms, &noopHooks{}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/scim/v2/Users/u1", nil)
	r.SetPathValue("id", "u1")
	h.GetUser(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d", w.Code)
	}
	var resp scimUser
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.UserName != "bob@example.com" {
		t.Errorf("userName: got %q", resp.UserName)
	}
}

func TestGetUserNotFound(t *testing.T) {
	t.Parallel()
	h := newTestHandler()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/scim/v2/Users/nonexistent", nil)
	r.SetPathValue("id", "nonexistent")
	h.GetUser(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", w.Code)
	}
}

func TestPatchUserDeactivate(t *testing.T) {
	t.Parallel()
	ms := newMockStore()
	ms.users["u2"] = &store.User{ID: "u2", Email: "carol@example.com", Status: "active"}
	h := NewHandler(ms, &noopHooks{}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("PATCH", "/scim/v2/Users/u2", jsonBody(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "replace", "path": "active", "value": false},
		},
	}))
	r.SetPathValue("id", "u2")
	h.PatchUser(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d; body: %s", w.Code, w.Body.String())
	}

	if ms.users["u2"].Status != "suspended" {
		t.Errorf("status: got %q, want suspended", ms.users["u2"].Status)
	}
}

func TestDeleteUser(t *testing.T) {
	t.Parallel()
	ms := newMockStore()
	ms.users["u3"] = &store.User{ID: "u3", Email: "dave@example.com"}
	h := NewHandler(ms, &noopHooks{}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/scim/v2/Users/u3", nil)
	r.SetPathValue("id", "u3")
	h.DeleteUser(w, r)

	if w.Code != http.StatusNoContent {
		t.Errorf("status: got %d, want 204", w.Code)
	}
	if _, ok := ms.users["u3"]; ok {
		t.Error("user still exists after delete")
	}
}

func TestListGroups(t *testing.T) {
	t.Parallel()
	ms := newMockStore()
	ms.roles = []*store.Role{
		{ID: "r1", Name: "admin", Permissions: []string{"*"}},
		{ID: "r2", Name: "editor", Permissions: []string{"write"}},
	}
	h := NewHandler(ms, &noopHooks{}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/scim/v2/Groups", nil)
	h.ListGroups(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d", w.Code)
	}
	var resp scimListResponse
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.TotalResults != 2 {
		t.Errorf("totalResults: got %d, want 2", resp.TotalResults)
	}
}
