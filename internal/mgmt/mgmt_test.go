package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/scttfrdmn/bouncing/internal/authz"
	"github.com/scttfrdmn/bouncing/internal/store"
)

// ── APIKey ────────────────────────────────────────────────────────────────────

func TestAPIKeyValidate(t *testing.T) {
	t.Parallel()
	k := NewAPIKey("bnc_api_mykey")
	if !k.Validate("bnc_api_mykey") {
		t.Error("Validate: expected true for correct key")
	}
	if k.Validate("wrong") {
		t.Error("Validate: expected false for wrong key")
	}
}

// ── Handler helpers ───────────────────────────────────────────────────────────

func newTestHandler(t *testing.T) (*Handler, store.Store) {
	t.Helper()
	db, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	h := NewHandler(Config{
		Store:  db,
		Engine: &authz.Engine{},
		Hooks:  &noopHooks{},
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return h, db
}

type noopHooks struct{}

func (n *noopHooks) Dispatch(_ context.Context, _ string, _ any) {}

func jsonBody(v any) *bytes.Buffer {
	b, _ := json.Marshal(v)
	return bytes.NewBuffer(b)
}

// ── InviteUser ────────────────────────────────────────────────────────────────

func TestInviteUser(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/manage/users/invite",
		jsonBody(map[string]string{"email": "new@example.com", "name": "New Person"}))
	r.Header.Set("Content-Type", "application/json")
	h.InviteUser(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("status: got %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	if body["id"] == nil {
		t.Error("id missing from response")
	}
	if body["status"] != "pending" {
		t.Errorf("status: got %v, want pending", body["status"])
	}
}

func TestInviteUserInvalidEmail(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/manage/users/invite",
		jsonBody(map[string]string{"email": "notanemail"}))
	r.Header.Set("Content-Type", "application/json")
	h.InviteUser(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
}

// ── ListUsers ─────────────────────────────────────────────────────────────────

func TestListUsers(t *testing.T) {
	t.Parallel()
	h, db := newTestHandler(t)
	ctx := context.Background()

	for _, email := range []string{"a@example.com", "b@example.com"} {
		_ = db.CreateUser(ctx, &store.User{Email: email, Status: "active"})
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/manage/users", nil)
	h.ListUsers(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200", w.Code)
	}
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	users := body["users"].([]any)
	if len(users) < 2 {
		t.Errorf("expected ≥2 users, got %d", len(users))
	}
}

// ── DeleteUser ────────────────────────────────────────────────────────────────

func TestDeleteUser(t *testing.T) {
	t.Parallel()
	h, db := newTestHandler(t)
	ctx := context.Background()

	u := &store.User{Email: "del@example.com", Status: "active"}
	_ = db.CreateUser(ctx, u)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/manage/users/"+u.ID, nil)
	r.SetPathValue("id", u.ID)
	h.DeleteUser(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want 200; body: %s", w.Code, w.Body.String())
	}

	// Verify user is gone.
	_, err := db.GetUser(ctx, u.ID)
	if err == nil {
		t.Error("user still exists after delete")
	}
}

func TestDeleteUserNotFound(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/manage/users/nonexistent", nil)
	r.SetPathValue("id", "nonexistent")
	h.DeleteUser(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("status: got %d, want 404", w.Code)
	}
}

// ── BulkImport ────────────────────────────────────────────────────────────────

func TestBulkImport(t *testing.T) {
	t.Parallel()
	h, db := newTestHandler(t)
	ctx := context.Background()

	// Pre-create one user to test skip.
	_ = db.CreateUser(ctx, &store.User{Email: "existing@example.com", Status: "pending"})

	body := jsonBody(map[string]any{
		"users": []map[string]string{
			{"email": "new1@example.com"},
			{"email": "new2@example.com"},
			{"email": "existing@example.com"}, // should be skipped
		},
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/manage/users/import", body)
	r.Header.Set("Content-Type", "application/json")
	h.BulkImport(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["created"].(float64) != 2 {
		t.Errorf("created: got %v, want 2", resp["created"])
	}
	if resp["skipped"].(float64) != 1 {
		t.Errorf("skipped: got %v, want 1", resp["skipped"])
	}
}

// ── CreateRole + ListRoles ────────────────────────────────────────────────────

func TestCreateListRoles(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/manage/roles",
		jsonBody(map[string]any{
			"name":        "editor",
			"permissions": []string{"content:write", "content:read", "content:write"}, // dupe
		}))
	r.Header.Set("Content-Type", "application/json")
	h.CreateRole(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("CreateRole status: got %d; body: %s", w.Code, w.Body.String())
	}

	w2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("GET", "/manage/roles", nil)
	h.ListRoles(w2, r2)

	if w2.Code != http.StatusOK {
		t.Errorf("ListRoles status: got %d", w2.Code)
	}
	var body map[string]any
	_ = json.NewDecoder(w2.Body).Decode(&body)
	roles := body["roles"].([]any)
	if len(roles) == 0 {
		t.Error("expected at least one role")
	}
	// store.Role marshals with capital field names (no json tags).
	first, ok := roles[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected role type: %T", roles[0])
	}
	perms, _ := first["Permissions"].([]any)
	if len(perms) != 2 {
		t.Errorf("expected 2 permissions (deduped), got %d in %v", len(perms), first)
	}
}

// ── AssignRole ────────────────────────────────────────────────────────────────

func TestAssignRole(t *testing.T) {
	t.Parallel()
	h, db := newTestHandler(t)
	ctx := context.Background()

	u := &store.User{Email: "assign@example.com", Status: "active"}
	_ = db.CreateUser(ctx, u)

	role := &store.Role{Name: "viewer", Permissions: []string{"content:read"}}
	_ = db.CreateRole(ctx, role)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/manage/users/"+u.ID+"/roles",
		jsonBody(map[string]any{"role": "viewer", "org_id": nil}))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("id", u.ID)
	h.AssignRole(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d; body: %s", w.Code, w.Body.String())
	}

	// Verify role was assigned.
	userRoles, err := db.GetUserRoles(ctx, u.ID)
	if err != nil || len(userRoles) == 0 {
		t.Errorf("expected role assigned, got: %v (err=%v)", userRoles, err)
	}
}

// ── ListAgreements ────────────────────────────────────────────────────────────

func TestListAgreements(t *testing.T) {
	t.Parallel()
	h, db := newTestHandler(t)
	ctx := context.Background()

	u := &store.User{Email: "agree@example.com", Status: "active"}
	_ = db.CreateUser(ctx, u)

	_ = db.CreateTOSAcceptance(ctx, &store.TOSAcceptance{
		UserID:     u.ID,
		Version:    "1.0",
		NameTyped:  "Jane Smith",
		AcceptedAt: 1712505600,
		IPAddress:  "127.0.0.1",
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/manage/users/"+u.ID+"/agreements", nil)
	r.SetPathValue("id", u.ID)
	h.ListAgreements(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d", w.Code)
	}
	var body map[string]any
	_ = json.NewDecoder(w.Body).Decode(&body)
	agreements := body["agreements"].([]any)
	if len(agreements) != 1 {
		t.Errorf("expected 1 agreement, got %d", len(agreements))
	}
}
