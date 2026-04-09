package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite" // register "sqlite" driver
)

func mapNoRows(err error, op string) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%s: %w", op, ErrNotFound)
	}
	return fmt.Errorf("%s: %w", op, err)
}

// SQLiteStore implements Store against a local SQLite database.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLite opens (or creates) a SQLite database at path and configures pragmas.
// Use ":memory:" for an in-memory database.
func NewSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store.NewSQLite: open: %w", err)
	}

	// Serialise writes through a single connection to avoid SQLITE_BUSY on WAL.
	db.SetMaxOpenConns(1)

	for _, pragma := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA foreign_keys = ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("store.NewSQLite: %s: %w", pragma, err)
		}
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Migrate(ctx context.Context) error {
	return migrate(ctx, s.db)
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// ── Users ────────────────────────────────────────────────────────────────────

func (s *SQLiteStore) CreateUser(ctx context.Context, u *User) error {
	if u.ID == "" {
		u.ID = ulid.Make().String()
	}
	if u.CreatedAt == 0 {
		u.CreatedAt = time.Now().Unix()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, email, name, avatar_url, status, auth_method, created_at, last_login)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, u.Name, u.AvatarURL, u.Status, u.AuthMethod, u.CreatedAt, u.LastLogin,
	)
	if err != nil {
		return fmt.Errorf("store.CreateUser: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetUser(ctx context.Context, id string) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, name, avatar_url, status, auth_method, created_at, last_login
		FROM users WHERE id = ?`, id,
	).Scan(&u.ID, &u.Email, &u.Name, &u.AvatarURL, &u.Status, &u.AuthMethod, &u.CreatedAt, &u.LastLogin)
	if err != nil {
		return nil, mapNoRows(err, "store.GetUser")
	}
	return u, nil
}

func (s *SQLiteStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email, name, avatar_url, status, auth_method, created_at, last_login
		FROM users WHERE email = ?`, email,
	).Scan(&u.ID, &u.Email, &u.Name, &u.AvatarURL, &u.Status, &u.AuthMethod, &u.CreatedAt, &u.LastLogin)
	if err != nil {
		return nil, mapNoRows(err, "store.GetUserByEmail")
	}
	return u, nil
}

func (s *SQLiteStore) ListUsers(ctx context.Context, opts ListOpts) ([]*User, error) {
	where, args := buildUserWhere(opts)
	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 20
	}
	if perPage > 100 {
		perPage = 100
	}
	page := opts.Page
	if page <= 0 {
		page = 1
	}
	args = append(args, perPage, (page-1)*perPage)

	rows, err := s.db.QueryContext(ctx,
		`SELECT id, email, name, avatar_url, status, auth_method, created_at, last_login
		 FROM users`+where+` ORDER BY created_at DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListUsers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.AvatarURL, &u.Status, &u.AuthMethod, &u.CreatedAt, &u.LastLogin); err != nil {
			return nil, fmt.Errorf("store.ListUsers: scan: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *SQLiteStore) CountUsers(ctx context.Context, opts ListOpts) (int64, error) {
	where, args := buildUserWhere(opts)
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`+where, args...).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store.CountUsers: %w", err)
	}
	return n, nil
}

func buildUserWhere(opts ListOpts) (string, []any) {
	var clauses []string
	var args []any
	if opts.Status != "" {
		clauses = append(clauses, "status = ?")
		args = append(args, opts.Status)
	}
	if opts.Query != "" {
		clauses = append(clauses, "(email LIKE ? OR name LIKE ?)")
		q := "%" + opts.Query + "%"
		args = append(args, q, q)
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func (s *SQLiteStore) UpdateUser(ctx context.Context, u *User) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET email=?, name=?, avatar_url=?, status=?, auth_method=?, last_login=?
		WHERE id=?`,
		u.Email, u.Name, u.AvatarURL, u.Status, u.AuthMethod, u.LastLogin, u.ID,
	)
	if err != nil {
		return fmt.Errorf("store.UpdateUser: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteUser(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.DeleteUser: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range []string{
		"DELETE FROM refresh_tokens WHERE user_id = ?",
		"DELETE FROM oauth_connections WHERE user_id = ?",
		"DELETE FROM webauthn_credentials WHERE user_id = ?",
		"DELETE FROM user_roles WHERE user_id = ?",
		"DELETE FROM org_members WHERE user_id = ?",
		"DELETE FROM users WHERE id = ?",
	} {
		if _, err := tx.ExecContext(ctx, stmt, id); err != nil {
			return fmt.Errorf("store.DeleteUser: %w", err)
		}
	}
	// tos_acceptances intentionally excluded — audit trail must survive offboarding.

	return tx.Commit()
}

func (s *SQLiteStore) CountActiveUsers(ctx context.Context, since time.Time) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT id) FROM users WHERE last_login >= ?`, since.Unix(),
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store.CountActiveUsers: %w", err)
	}
	return n, nil
}

// ── OAuth ────────────────────────────────────────────────────────────────────

func (s *SQLiteStore) CreateOAuthConnection(ctx context.Context, c *OAuthConnection) error {
	if c.ID == "" {
		c.ID = ulid.Make().String()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_connections (id, user_id, provider, provider_id, email)
		VALUES (?, ?, ?, ?, ?)`,
		c.ID, c.UserID, c.Provider, c.ProviderID, c.Email,
	)
	if err != nil {
		return fmt.Errorf("store.CreateOAuthConnection: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetOAuthConnection(ctx context.Context, provider, providerID string) (*OAuthConnection, error) {
	c := &OAuthConnection{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, provider, provider_id, email
		FROM oauth_connections WHERE provider=? AND provider_id=?`, provider, providerID,
	).Scan(&c.ID, &c.UserID, &c.Provider, &c.ProviderID, &c.Email)
	if err != nil {
		return nil, mapNoRows(err, "store.GetOAuthConnection")
	}
	return c, nil
}

func (s *SQLiteStore) ListOAuthConnections(ctx context.Context, userID string) ([]*OAuthConnection, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, provider, provider_id, email
		FROM oauth_connections WHERE user_id=?`, userID)
	if err != nil {
		return nil, fmt.Errorf("store.ListOAuthConnections: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var conns []*OAuthConnection
	for rows.Next() {
		c := &OAuthConnection{}
		if err := rows.Scan(&c.ID, &c.UserID, &c.Provider, &c.ProviderID, &c.Email); err != nil {
			return nil, fmt.Errorf("store.ListOAuthConnections: scan: %w", err)
		}
		conns = append(conns, c)
	}
	return conns, rows.Err()
}

// ── WebAuthn Credentials ─────────────────────────────────────────────────────

func (s *SQLiteStore) CreateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error {
	if c.ID == "" {
		c.ID = ulid.Make().String()
	}
	if c.CreatedAt == 0 {
		c.CreatedAt = time.Now().Unix()
	}
	transports, err := marshalStrings(c.Transports)
	if err != nil {
		return fmt.Errorf("store.CreateWebAuthnCredential: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (id, user_id, public_key, sign_count, transports, created_at, last_used)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserID, c.PublicKey, c.SignCount, transports, c.CreatedAt, c.LastUsed,
	)
	if err != nil {
		return fmt.Errorf("store.CreateWebAuthnCredential: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetWebAuthnCredentials(ctx context.Context, userID string) ([]*WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, public_key, sign_count, transports, created_at, last_used
		FROM webauthn_credentials WHERE user_id=?`, userID)
	if err != nil {
		return nil, fmt.Errorf("store.GetWebAuthnCredentials: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var creds []*WebAuthnCredential
	for rows.Next() {
		c := &WebAuthnCredential{}
		var transports string
		if err := rows.Scan(&c.ID, &c.UserID, &c.PublicKey, &c.SignCount, &transports, &c.CreatedAt, &c.LastUsed); err != nil {
			return nil, fmt.Errorf("store.GetWebAuthnCredentials: scan: %w", err)
		}
		c.Transports, err = unmarshalStrings(transports)
		if err != nil {
			return nil, fmt.Errorf("store.GetWebAuthnCredentials: transports: %w", err)
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

func (s *SQLiteStore) UpdateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error {
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx, `
		UPDATE webauthn_credentials SET sign_count=?, last_used=? WHERE id=?`,
		c.SignCount, now, c.ID,
	)
	if err != nil {
		return fmt.Errorf("store.UpdateWebAuthnCredential: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteWebAuthnCredential(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store.DeleteWebAuthnCredential: %w", err)
	}
	return nil
}

// ── Roles ────────────────────────────────────────────────────────────────────

func (s *SQLiteStore) CreateRole(ctx context.Context, r *Role) error {
	if r.ID == "" {
		r.ID = ulid.Make().String()
	}
	perms, err := marshalStrings(r.Permissions)
	if err != nil {
		return fmt.Errorf("store.CreateRole: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO roles (id, name, permissions) VALUES (?, ?, ?)`,
		r.ID, r.Name, perms)
	if err != nil {
		return fmt.Errorf("store.CreateRole: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetRole(ctx context.Context, id string) (*Role, error) {
	return s.scanRole(s.db.QueryRowContext(ctx, `SELECT id, name, permissions FROM roles WHERE id=?`, id))
}

func (s *SQLiteStore) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	return s.scanRole(s.db.QueryRowContext(ctx, `SELECT id, name, permissions FROM roles WHERE name=?`, name))
}

func (s *SQLiteStore) scanRole(row *sql.Row) (*Role, error) {
	r := &Role{}
	var perms string
	if err := row.Scan(&r.ID, &r.Name, &perms); err != nil {
		return nil, mapNoRows(err, "store.scanRole")
	}
	var err error
	r.Permissions, err = unmarshalStrings(perms)
	if err != nil {
		return nil, fmt.Errorf("store.scanRole: permissions: %w", err)
	}
	return r, nil
}

func (s *SQLiteStore) ListRoles(ctx context.Context) ([]*Role, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, permissions FROM roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store.ListRoles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var roles []*Role
	for rows.Next() {
		r := &Role{}
		var perms string
		if err := rows.Scan(&r.ID, &r.Name, &perms); err != nil {
			return nil, fmt.Errorf("store.ListRoles: scan: %w", err)
		}
		r.Permissions, err = unmarshalStrings(perms)
		if err != nil {
			return nil, fmt.Errorf("store.ListRoles: permissions: %w", err)
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

func (s *SQLiteStore) UpdateRole(ctx context.Context, r *Role) error {
	perms, err := marshalStrings(r.Permissions)
	if err != nil {
		return fmt.Errorf("store.UpdateRole: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `UPDATE roles SET name=?, permissions=? WHERE id=?`,
		r.Name, perms, r.ID)
	if err != nil {
		return fmt.Errorf("store.UpdateRole: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteRole(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM roles WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store.DeleteRole: %w", err)
	}
	return nil
}

// ── User-Role Assignments ────────────────────────────────────────────────────

func (s *SQLiteStore) AssignRole(ctx context.Context, userID, roleID string, orgID *string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO user_roles (user_id, role_id, org_id) VALUES (?, ?, ?)`,
		userID, roleID, ptrToOrgID(orgID),
	)
	if err != nil {
		return fmt.Errorf("store.AssignRole: %w", err)
	}
	return nil
}

func (s *SQLiteStore) RevokeRole(ctx context.Context, userID, roleID string, orgID *string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_roles WHERE user_id=? AND role_id=? AND org_id=?`,
		userID, roleID, ptrToOrgID(orgID),
	)
	if err != nil {
		return fmt.Errorf("store.RevokeRole: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetUserRoles(ctx context.Context, userID string) ([]*UserRole, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT user_id, role_id, org_id FROM user_roles WHERE user_id=?`, userID)
	if err != nil {
		return nil, fmt.Errorf("store.GetUserRoles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var userRoles []*UserRole
	for rows.Next() {
		ur := &UserRole{}
		var orgID string
		if err := rows.Scan(&ur.UserID, &ur.RoleID, &orgID); err != nil {
			return nil, fmt.Errorf("store.GetUserRoles: scan: %w", err)
		}
		ur.OrgID = orgIDToPtr(orgID)
		userRoles = append(userRoles, ur)
	}
	return userRoles, rows.Err()
}

// ── Organizations ────────────────────────────────────────────────────────────

func (s *SQLiteStore) CreateOrg(ctx context.Context, o *Org) error {
	if o.ID == "" {
		o.ID = ulid.Make().String()
	}
	if o.CreatedAt == 0 {
		o.CreatedAt = time.Now().Unix()
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO orgs (id, name, slug, created_at) VALUES (?, ?, ?, ?)`,
		o.ID, o.Name, o.Slug, o.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("store.CreateOrg: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetOrg(ctx context.Context, id string) (*Org, error) {
	o := &Org{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, slug, created_at FROM orgs WHERE id=?`, id,
	).Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store.GetOrg: %w", err)
	}
	return o, nil
}

func (s *SQLiteStore) ListOrgs(ctx context.Context) ([]*Org, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, slug, created_at FROM orgs ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("store.ListOrgs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var orgs []*Org
	for rows.Next() {
		o := &Org{}
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt); err != nil {
			return nil, fmt.Errorf("store.ListOrgs: scan: %w", err)
		}
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}

func (s *SQLiteStore) AddOrgMember(ctx context.Context, orgID, userID, roleID string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO org_members (org_id, user_id, role_id) VALUES (?, ?, ?)`,
		orgID, userID, roleID,
	)
	if err != nil {
		return fmt.Errorf("store.AddOrgMember: %w", err)
	}
	return nil
}

func (s *SQLiteStore) RemoveOrgMember(ctx context.Context, orgID, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM org_members WHERE org_id=? AND user_id=?`, orgID, userID,
	)
	if err != nil {
		return fmt.Errorf("store.RemoveOrgMember: %w", err)
	}
	return nil
}

// ── Refresh Tokens ───────────────────────────────────────────────────────────

func (s *SQLiteStore) CreateRefreshToken(ctx context.Context, t *RefreshToken) error {
	if t.ID == "" {
		t.ID = ulid.Make().String()
	}
	if t.CreatedAt == 0 {
		t.CreatedAt = time.Now().Unix()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		t.ID, t.UserID, t.TokenHash, t.ExpiresAt, t.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("store.CreateRefreshToken: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	t := &RefreshToken{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, expires_at, created_at
		FROM refresh_tokens WHERE token_hash=?`, tokenHash,
	).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.CreatedAt)
	if err != nil {
		return nil, mapNoRows(err, "store.GetRefreshToken")
	}
	return t, nil
}

func (s *SQLiteStore) DeleteRefreshToken(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store.DeleteRefreshToken: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteUserRefreshTokens(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE user_id=?`, userID)
	if err != nil {
		return fmt.Errorf("store.DeleteUserRefreshTokens: %w", err)
	}
	return nil
}

// ── Allowed Domains ──────────────────────────────────────────────────────────

func (s *SQLiteStore) ListAllowedDomains(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT domain FROM allowed_domains ORDER BY domain`)
	if err != nil {
		return nil, fmt.Errorf("store.ListAllowedDomains: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var domains []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, fmt.Errorf("store.ListAllowedDomains: scan: %w", err)
		}
		domains = append(domains, d)
	}
	return domains, rows.Err()
}

func (s *SQLiteStore) IsAllowedDomain(ctx context.Context, domain string) (bool, error) {
	// Normalise: strip leading @ and lowercase.
	d := strings.ToLower(strings.TrimPrefix(domain, "@"))
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM allowed_domains WHERE domain=?`, d,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("store.IsAllowedDomain: %w", err)
	}
	return count > 0, nil
}

// ── Webhooks ─────────────────────────────────────────────────────────────────

func (s *SQLiteStore) ListWebhooks(ctx context.Context) ([]*Webhook, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, url, events, secret FROM webhooks`)
	if err != nil {
		return nil, fmt.Errorf("store.ListWebhooks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var hooks []*Webhook
	for rows.Next() {
		w := &Webhook{}
		var events string
		if err := rows.Scan(&w.ID, &w.URL, &events, &w.Secret); err != nil {
			return nil, fmt.Errorf("store.ListWebhooks: scan: %w", err)
		}
		w.Events, err = unmarshalStrings(events)
		if err != nil {
			return nil, fmt.Errorf("store.ListWebhooks: events: %w", err)
		}
		hooks = append(hooks, w)
	}
	return hooks, rows.Err()
}

func (s *SQLiteStore) CreateWebhook(ctx context.Context, w *Webhook) error {
	if w.ID == "" {
		w.ID = ulid.Make().String()
	}
	events, err := marshalStrings(w.Events)
	if err != nil {
		return fmt.Errorf("store.CreateWebhook: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO webhooks (id, url, events, secret) VALUES (?, ?, ?, ?)`,
		w.ID, w.URL, events, w.Secret,
	)
	if err != nil {
		return fmt.Errorf("store.CreateWebhook: %w", err)
	}
	return nil
}

func (s *SQLiteStore) DeleteWebhook(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webhooks WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("store.DeleteWebhook: %w", err)
	}
	return nil
}

// ── TOS Acceptances ──────────────────────────────────────────────────────────

func (s *SQLiteStore) CreateTOSAcceptance(ctx context.Context, a *TOSAcceptance) error {
	if a.ID == "" {
		a.ID = ulid.Make().String()
	}
	if a.AcceptedAt == 0 {
		a.AcceptedAt = time.Now().Unix()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tos_acceptances (id, user_id, version, name_typed, accepted_at, ip_address)
		VALUES (?, ?, ?, ?, ?, ?)`,
		a.ID, a.UserID, a.Version, a.NameTyped, a.AcceptedAt, a.IPAddress,
	)
	if err != nil {
		return fmt.Errorf("store.CreateTOSAcceptance: %w", err)
	}
	return nil
}

func (s *SQLiteStore) GetTOSAcceptance(ctx context.Context, userID, version string) (*TOSAcceptance, error) {
	a := &TOSAcceptance{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, version, name_typed, accepted_at, ip_address
		FROM tos_acceptances WHERE user_id=? AND version=?`, userID, version,
	).Scan(&a.ID, &a.UserID, &a.Version, &a.NameTyped, &a.AcceptedAt, &a.IPAddress)
	if err != nil {
		return nil, mapNoRows(err, "store.GetTOSAcceptance")
	}
	return a, nil
}

func (s *SQLiteStore) ListTOSAcceptances(ctx context.Context, userID string) ([]*TOSAcceptance, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, version, name_typed, accepted_at, ip_address
		FROM tos_acceptances WHERE user_id=? ORDER BY accepted_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("store.ListTOSAcceptances: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var acceptances []*TOSAcceptance
	for rows.Next() {
		a := &TOSAcceptance{}
		if err := rows.Scan(&a.ID, &a.UserID, &a.Version, &a.NameTyped, &a.AcceptedAt, &a.IPAddress); err != nil {
			return nil, fmt.Errorf("store.ListTOSAcceptances: scan: %w", err)
		}
		acceptances = append(acceptances, a)
	}
	return acceptances, rows.Err()
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func marshalStrings(v []string) (string, error) {
	if v == nil {
		v = []string{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("marshalStrings: %w", err)
	}
	return string(b), nil
}

func unmarshalStrings(s string) ([]string, error) {
	if s == "" || s == "null" {
		return []string{}, nil
	}
	var v []string
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, fmt.Errorf("unmarshalStrings: %w", err)
	}
	return v, nil
}

// ptrToOrgID converts a *string orgID to the storage representation:
// nil → "" (global scope), non-nil → the string value.
func ptrToOrgID(orgID *string) string {
	if orgID == nil {
		return ""
	}
	return *orgID
}

// ── Audit Log ────────────────────────────────────────────────────────────────

func (s *SQLiteStore) CreateAuditEntry(ctx context.Context, e *AuditEntry) error {
	if e.ID == "" {
		e.ID = ulid.Make().String()
	}
	if e.Timestamp == 0 {
		e.Timestamp = time.Now().Unix()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_entries (id, timestamp, actor_id, action, target_type, target_id, metadata, ip_address, request_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.Timestamp, e.ActorID, e.Action, e.TargetType, e.TargetID, e.Metadata, e.IPAddress, e.RequestID,
	)
	if err != nil {
		return fmt.Errorf("store.CreateAuditEntry: %w", err)
	}
	return nil
}

func (s *SQLiteStore) ListAuditEntries(ctx context.Context, opts AuditListOpts) ([]*AuditEntry, int64, error) {
	where, args := buildAuditWhere(opts)
	perPage := opts.PerPage
	if perPage <= 0 {
		perPage = 50
	}
	if perPage > 200 {
		perPage = 200
	}
	page := opts.Page
	if page <= 0 {
		page = 1
	}

	// Count total.
	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_entries"+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("store.ListAuditEntries: count: %w", err)
	}

	// Fetch page.
	query := "SELECT id, timestamp, actor_id, action, target_type, target_id, metadata, ip_address, request_id FROM audit_entries" + where + " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
	args = append(args, perPage, (page-1)*perPage)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("store.ListAuditEntries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []*AuditEntry
	for rows.Next() {
		e := &AuditEntry{}
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ActorID, &e.Action, &e.TargetType, &e.TargetID, &e.Metadata, &e.IPAddress, &e.RequestID); err != nil {
			return nil, 0, fmt.Errorf("store.ListAuditEntries: scan: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, total, nil
}

func buildAuditWhere(opts AuditListOpts) (string, []any) {
	var clauses []string
	var args []any
	if opts.ActorID != "" {
		clauses = append(clauses, "actor_id = ?")
		args = append(args, opts.ActorID)
	}
	if opts.Action != "" {
		clauses = append(clauses, "action = ?")
		args = append(args, opts.Action)
	}
	if opts.Since > 0 {
		clauses = append(clauses, "timestamp >= ?")
		args = append(args, opts.Since)
	}
	if opts.Until > 0 {
		clauses = append(clauses, "timestamp <= ?")
		args = append(args, opts.Until)
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// orgIDToPtr converts the storage representation back to *string:
// "" → nil (global scope), non-empty → pointer to the value.
func orgIDToPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

