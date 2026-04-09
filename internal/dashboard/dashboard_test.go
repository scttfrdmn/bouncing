package dashboard

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/scttfrdmn/bouncing/internal/store"
)

func newTestHandler(t *testing.T) (*Handler, store.Store) {
	t.Helper()
	db, err := store.NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	h := NewHandler(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return h, db
}

func TestNewHandlerParsesTemplates(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)
	if len(h.pages) == 0 {
		t.Fatal("expected templates to be parsed")
	}
}

func TestUsersPage(t *testing.T) {
	t.Parallel()
	h, db := newTestHandler(t)
	ctx := context.Background()
	_ = db.CreateUser(ctx, &store.User{Email: "dash@example.com", Name: "Dash", Status: "active"})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/dashboard/users", nil)
	h.Users(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "dash@example.com") {
		t.Error("HTML missing user email")
	}
	if !strings.Contains(body, "<table>") {
		t.Error("HTML missing table element")
	}
}

func TestRolesPage(t *testing.T) {
	t.Parallel()
	h, db := newTestHandler(t)
	ctx := context.Background()
	_ = db.CreateRole(ctx, &store.Role{Name: "editor", Permissions: []string{"write"}})

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/dashboard/roles", nil)
	h.Roles(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "editor") {
		t.Error("HTML missing role name")
	}
}

func TestAuditPage(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/dashboard/audit", nil)
	h.Audit(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Audit Log") {
		t.Error("HTML missing Audit Log heading")
	}
}

func TestOrgsPage(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/dashboard/orgs", nil)
	h.Orgs(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Organizations") {
		t.Error("HTML missing Organizations heading")
	}
}

func TestWebhooksPage(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/dashboard/webhooks", nil)
	h.Webhooks(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d", w.Code)
	}
}

func TestDeleteUserHTMX(t *testing.T) {
	t.Parallel()
	h, db := newTestHandler(t)
	ctx := context.Background()
	u := &store.User{Email: "htmx-del@example.com", Status: "active"}
	_ = db.CreateUser(ctx, u)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/dashboard/users/"+u.ID, nil)
	r.SetPathValue("id", u.ID)
	h.DeleteUser(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d", w.Code)
	}
}

func TestCreateRoleHTMX(t *testing.T) {
	t.Parallel()
	h, _ := newTestHandler(t)

	form := url.Values{"name": {"tester"}, "permissions": {"test:run, test:read"}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/dashboard/roles", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.CreateRole(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "tester") {
		t.Error("response missing role name")
	}
}

func TestDeleteRoleHTMX(t *testing.T) {
	t.Parallel()
	h, db := newTestHandler(t)
	ctx := context.Background()
	role := &store.Role{Name: "disposable", Permissions: []string{"none"}}
	_ = db.CreateRole(ctx, role)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("DELETE", "/dashboard/roles/"+role.ID, nil)
	r.SetPathValue("id", role.ID)
	h.DeleteRole(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d", w.Code)
	}
}
