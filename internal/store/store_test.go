package store

import (
	"context"
	"errors"
	"database/sql"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	s, err := NewSQLite(":memory:")
	if err != nil {
		t.Fatalf("NewSQLite: %v", err)
	}
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrationIdempotent(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	// Second migration must not error.
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
}

// ── Users ────────────────────────────────────────────────────────────────────

func TestUserRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	u := &User{Email: "scott@enso.co", Name: "Scott", Status: "active"}
	if err := s.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == "" {
		t.Fatal("CreateUser did not assign ID")
	}

	got, err := s.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if got.Email != u.Email {
		t.Errorf("email: got %q want %q", got.Email, u.Email)
	}

	got2, err := s.GetUserByEmail(ctx, u.Email)
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got2.ID != u.ID {
		t.Errorf("GetUserByEmail id: got %q want %q", got2.ID, u.ID)
	}
}

func TestGetUserByEmailNotFound(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	_, err := s.GetUserByEmail(context.Background(), "nobody@example.com")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestListUsersFilters(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	users := []*User{
		{Email: "a@enso.co", Status: "active"},
		{Email: "b@enso.co", Status: "pending"},
		{Email: "c@enso.co", Status: "active"},
	}
	for _, u := range users {
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
	}

	active, err := s.ListUsers(ctx, ListOpts{Status: "active", PerPage: 100})
	if err != nil {
		t.Fatalf("ListUsers active: %v", err)
	}
	if len(active) != 2 {
		t.Errorf("active count: got %d want 2", len(active))
	}

	total, err := s.CountUsers(ctx, ListOpts{})
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if total != 3 {
		t.Errorf("CountUsers: got %d want 3", total)
	}

	// Query search
	found, err := s.ListUsers(ctx, ListOpts{Query: "a@enso", PerPage: 10})
	if err != nil {
		t.Fatalf("ListUsers query: %v", err)
	}
	if len(found) != 1 || found[0].Email != "a@enso.co" {
		t.Errorf("query filter: unexpected result %v", found)
	}
}

func TestListUsersPerPageClamp(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		s.CreateUser(ctx, &User{Email: "u" + string(rune('0'+i)) + "@x.co", Status: "active"})
	}
	users, err := s.ListUsers(ctx, ListOpts{PerPage: 200})
	if err != nil {
		t.Fatal(err)
	}
	// Should return all 5 (clamped to 100, which is > 5)
	if len(users) != 5 {
		t.Errorf("got %d, want 5", len(users))
	}
}

func TestDeleteUser(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	u := &User{Email: "del@enso.co", Status: "active"}
	s.CreateUser(ctx, u)

	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	_, err := s.GetUser(ctx, u.ID)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected not found after delete, got %v", err)
	}
}

func TestDeleteUserPreservesTOSAcceptances(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	u := &User{Email: "tos@enso.co", Status: "active"}
	s.CreateUser(ctx, u)
	s.CreateTOSAcceptance(ctx, &TOSAcceptance{
		UserID: u.ID, Version: "v1.0", NameTyped: "Scott Freeman",
	})

	if err := s.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser with TOS record: %v", err)
	}

	// TOS record must still exist.
	recs, err := s.ListTOSAcceptances(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListTOSAcceptances after delete: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("expected 1 TOS record, got %d", len(recs))
	}
}

// ── WebAuthn ─────────────────────────────────────────────────────────────────

func TestWebAuthnCredentialRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	u := &User{Email: "wn@enso.co", Status: "active"}
	s.CreateUser(ctx, u)

	cred := &WebAuthnCredential{
		UserID:     u.ID,
		PublicKey:  []byte{1, 2, 3, 4},
		SignCount:  5,
		Transports: []string{"internal", "usb"},
	}
	if err := s.CreateWebAuthnCredential(ctx, cred); err != nil {
		t.Fatalf("CreateWebAuthnCredential: %v", err)
	}

	got, err := s.GetWebAuthnCredentials(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetWebAuthnCredentials: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(got))
	}
	if len(got[0].Transports) != 2 || got[0].Transports[0] != "internal" {
		t.Errorf("transports round-trip failed: %v", got[0].Transports)
	}
	if got[0].SignCount != 5 {
		t.Errorf("sign_count: got %d want 5", got[0].SignCount)
	}
}

// ── Roles ────────────────────────────────────────────────────────────────────

func TestRolePermissionsRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	r := &Role{Name: "editor", Permissions: []string{"content:read", "content:write"}}
	if err := s.CreateRole(ctx, r); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	got, err := s.GetRoleByName(ctx, "editor")
	if err != nil {
		t.Fatalf("GetRoleByName: %v", err)
	}
	if len(got.Permissions) != 2 {
		t.Errorf("permissions count: got %d want 2", len(got.Permissions))
	}
	if got.Permissions[0] != "content:read" {
		t.Errorf("permissions[0]: got %q want %q", got.Permissions[0], "content:read")
	}
}

func TestAssignRevokeRole(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	u := &User{Email: "role@enso.co", Status: "active"}
	s.CreateUser(ctx, u)
	r := &Role{Name: "admin", Permissions: []string{"*"}}
	s.CreateRole(ctx, r)

	if err := s.AssignRole(ctx, u.ID, r.ID, nil); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	userRoles, err := s.GetUserRoles(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserRoles: %v", err)
	}
	if len(userRoles) != 1 || userRoles[0].OrgID != nil {
		t.Errorf("unexpected user roles: %v", userRoles)
	}

	if err := s.RevokeRole(ctx, u.ID, r.ID, nil); err != nil {
		t.Fatalf("RevokeRole: %v", err)
	}

	userRoles, _ = s.GetUserRoles(ctx, u.ID)
	if len(userRoles) != 0 {
		t.Errorf("expected 0 roles after revoke, got %d", len(userRoles))
	}
}

func TestAssignRoleWithOrgID(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	u := &User{Email: "org@enso.co", Status: "active"}
	s.CreateUser(ctx, u)
	r := &Role{Name: "member", Permissions: []string{"read"}}
	s.CreateRole(ctx, r)
	org := &Org{Name: "Acme", Slug: "acme"}
	s.CreateOrg(ctx, org)

	if err := s.AssignRole(ctx, u.ID, r.ID, &org.ID); err != nil {
		t.Fatalf("AssignRole with org: %v", err)
	}

	userRoles, _ := s.GetUserRoles(ctx, u.ID)
	if len(userRoles) != 1 || userRoles[0].OrgID == nil || *userRoles[0].OrgID != org.ID {
		t.Errorf("org role: unexpected result %+v", userRoles)
	}
}

// ── Refresh Tokens ───────────────────────────────────────────────────────────

func TestRefreshTokenRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	u := &User{Email: "rt@enso.co", Status: "active"}
	s.CreateUser(ctx, u)

	tok := &RefreshToken{
		UserID:    u.ID,
		TokenHash: "abc123hash",
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour).Unix(),
	}
	if err := s.CreateRefreshToken(ctx, tok); err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	got, err := s.GetRefreshToken(ctx, "abc123hash")
	if err != nil {
		t.Fatalf("GetRefreshToken: %v", err)
	}
	if got.UserID != u.ID {
		t.Errorf("userID: got %q want %q", got.UserID, u.ID)
	}

	if err := s.DeleteRefreshToken(ctx, tok.ID); err != nil {
		t.Fatalf("DeleteRefreshToken: %v", err)
	}

	_, err = s.GetRefreshToken(ctx, "abc123hash")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("expected not found after delete, got %v", err)
	}
}

func TestDeleteUserRefreshTokens(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	u := &User{Email: "multi@enso.co", Status: "active"}
	s.CreateUser(ctx, u)

	for _, h := range []string{"hash1", "hash2", "hash3"} {
		s.CreateRefreshToken(ctx, &RefreshToken{
			UserID:    u.ID,
			TokenHash: h,
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
		})
	}

	if err := s.DeleteUserRefreshTokens(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUserRefreshTokens: %v", err)
	}

	for _, h := range []string{"hash1", "hash2", "hash3"} {
		_, err := s.GetRefreshToken(ctx, h)
		if !errors.Is(err, sql.ErrNoRows) {
			t.Errorf("hash %s: expected not found, got %v", h, err)
		}
	}
}

// ── Allowed Domains ──────────────────────────────────────────────────────────

func TestIsAllowedDomain(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	// Insert domain via raw SQL (no public method to add domains in v0.1).
	s.db.ExecContext(ctx, `INSERT INTO allowed_domains (domain) VALUES ('enso.co')`)

	tests := []struct {
		domain string
		want   bool
	}{
		{"enso.co", true},
		{"ENSO.CO", true},          // case-insensitive
		{"@enso.co", true},         // @ prefix stripped
		{"sub.enso.co", false},     // no subdomain match
		{"gmail.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got, err := s.IsAllowedDomain(ctx, tt.domain)
			if err != nil {
				t.Fatalf("IsAllowedDomain(%q): %v", tt.domain, err)
			}
			if got != tt.want {
				t.Errorf("IsAllowedDomain(%q): got %v want %v", tt.domain, got, tt.want)
			}
		})
	}
}

// ── TOS Acceptances ──────────────────────────────────────────────────────────

func TestTOSAcceptanceRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	u := &User{Email: "tos2@enso.co", Status: "active"}
	s.CreateUser(ctx, u)

	a := &TOSAcceptance{
		UserID:    u.ID,
		Version:   "v1.0",
		NameTyped: "Scott Freeman",
		IPAddress: "127.0.0.1",
	}
	if err := s.CreateTOSAcceptance(ctx, a); err != nil {
		t.Fatalf("CreateTOSAcceptance: %v", err)
	}

	got, err := s.GetTOSAcceptance(ctx, u.ID, "v1.0")
	if err != nil {
		t.Fatalf("GetTOSAcceptance: %v", err)
	}
	if got.NameTyped != "Scott Freeman" {
		t.Errorf("name_typed: got %q want %q", got.NameTyped, "Scott Freeman")
	}

	// Version not found.
	_, err = s.GetTOSAcceptance(ctx, u.ID, "v2.0")
	if !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("v2.0 not found: expected sql.ErrNoRows, got %v", err)
	}
}

// ── Webhooks ─────────────────────────────────────────────────────────────────

func TestWebhookRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	w := &Webhook{
		URL:    "https://example.com/hook",
		Events: []string{"user.created", "user.deleted"},
		Secret: "mysecret",
	}
	if err := s.CreateWebhook(ctx, w); err != nil {
		t.Fatalf("CreateWebhook: %v", err)
	}

	hooks, err := s.ListWebhooks(ctx)
	if err != nil {
		t.Fatalf("ListWebhooks: %v", err)
	}
	if len(hooks) != 1 || len(hooks[0].Events) != 2 {
		t.Errorf("unexpected webhooks: %+v", hooks)
	}

	if err := s.DeleteWebhook(ctx, w.ID); err != nil {
		t.Fatalf("DeleteWebhook: %v", err)
	}
	hooks, _ = s.ListWebhooks(ctx)
	if len(hooks) != 0 {
		t.Errorf("expected 0 webhooks after delete, got %d", len(hooks))
	}
}

// ── Orgs ──────────────────────────────────────────────────────────────────────

func TestOrgCRUD(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	o := &Org{Name: "Acme Corp", Slug: "acme"}
	if err := s.CreateOrg(ctx, o); err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	if o.ID == "" {
		t.Fatal("expected org ID to be set")
	}

	got, err := s.GetOrg(ctx, o.ID)
	if err != nil {
		t.Fatalf("GetOrg: %v", err)
	}
	if got.Name != "Acme Corp" || got.Slug != "acme" {
		t.Errorf("GetOrg: got %+v", got)
	}

	all, err := s.ListOrgs(ctx)
	if err != nil {
		t.Fatalf("ListOrgs: %v", err)
	}
	if len(all) < 1 {
		t.Error("expected at least 1 org")
	}
}

func TestOrgMembershipRoundTrip(t *testing.T) {
	t.Parallel()
	s := newTestStore(t)
	ctx := context.Background()

	u := &User{Email: "member@example.com", Status: "active"}
	_ = s.CreateUser(ctx, u)

	role := &Role{Name: "viewer", Permissions: []string{"read"}}
	_ = s.CreateRole(ctx, role)

	o := &Org{Name: "TestOrg", Slug: "testorg"}
	_ = s.CreateOrg(ctx, o)

	if err := s.AddOrgMember(ctx, o.ID, u.ID, role.ID); err != nil {
		t.Fatalf("AddOrgMember: %v", err)
	}

	// Idempotent add.
	if err := s.AddOrgMember(ctx, o.ID, u.ID, role.ID); err != nil {
		t.Errorf("duplicate AddOrgMember should be ignored: %v", err)
	}

	if err := s.RemoveOrgMember(ctx, o.ID, u.ID); err != nil {
		t.Fatalf("RemoveOrgMember: %v", err)
	}
}
