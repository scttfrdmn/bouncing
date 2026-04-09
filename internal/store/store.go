package store

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by store methods when the requested record does not exist.
var ErrNotFound = errors.New("store: not found")

// IsNotFound reports whether err wraps ErrNotFound.
func IsNotFound(err error) bool { return errors.Is(err, ErrNotFound) }

// Store is the central storage interface. Every backend (SQLite, Turso) implements this.
type Store interface {
	// Users
	CreateUser(ctx context.Context, u *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	ListUsers(ctx context.Context, opts ListOpts) ([]*User, error)
	UpdateUser(ctx context.Context, u *User) error
	DeleteUser(ctx context.Context, id string) error
	CountActiveUsers(ctx context.Context, since time.Time) (int64, error)
	CountUsers(ctx context.Context, opts ListOpts) (int64, error)

	// OAuth
	CreateOAuthConnection(ctx context.Context, c *OAuthConnection) error
	GetOAuthConnection(ctx context.Context, provider, providerID string) (*OAuthConnection, error)
	ListOAuthConnections(ctx context.Context, userID string) ([]*OAuthConnection, error)

	// WebAuthn Credentials
	CreateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error
	GetWebAuthnCredentials(ctx context.Context, userID string) ([]*WebAuthnCredential, error)
	UpdateWebAuthnCredential(ctx context.Context, c *WebAuthnCredential) error
	DeleteWebAuthnCredential(ctx context.Context, id string) error

	// Roles
	CreateRole(ctx context.Context, r *Role) error
	GetRole(ctx context.Context, id string) (*Role, error)
	GetRoleByName(ctx context.Context, name string) (*Role, error)
	ListRoles(ctx context.Context) ([]*Role, error)
	UpdateRole(ctx context.Context, r *Role) error
	DeleteRole(ctx context.Context, id string) error

	// User-Role assignments
	AssignRole(ctx context.Context, userID, roleID string, orgID *string) error
	RevokeRole(ctx context.Context, userID, roleID string, orgID *string) error
	GetUserRoles(ctx context.Context, userID string) ([]*UserRole, error)

	// Organizations (v0.2+)
	CreateOrg(ctx context.Context, o *Org) error
	GetOrg(ctx context.Context, id string) (*Org, error)
	ListOrgs(ctx context.Context) ([]*Org, error)
	AddOrgMember(ctx context.Context, orgID, userID, roleID string) error
	RemoveOrgMember(ctx context.Context, orgID, userID string) error

	// Refresh Tokens
	CreateRefreshToken(ctx context.Context, t *RefreshToken) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, id string) error
	DeleteUserRefreshTokens(ctx context.Context, userID string) error

	// Allowed Domains
	ListAllowedDomains(ctx context.Context) ([]string, error)
	IsAllowedDomain(ctx context.Context, domain string) (bool, error)

	// Webhooks
	ListWebhooks(ctx context.Context) ([]*Webhook, error)
	CreateWebhook(ctx context.Context, w *Webhook) error
	DeleteWebhook(ctx context.Context, id string) error

	// TOS / Legal Acceptances (immutable — never deleted)
	CreateTOSAcceptance(ctx context.Context, a *TOSAcceptance) error
	GetTOSAcceptance(ctx context.Context, userID, version string) (*TOSAcceptance, error)
	ListTOSAcceptances(ctx context.Context, userID string) ([]*TOSAcceptance, error)

	// Audit Log (immutable — never deleted)
	CreateAuditEntry(ctx context.Context, e *AuditEntry) error
	ListAuditEntries(ctx context.Context, opts AuditListOpts) ([]*AuditEntry, int64, error)

	// Migrations
	Migrate(ctx context.Context) error
	Close() error
}

type ListOpts struct {
	Page    int
	PerPage int
	Status  string
	Role    string
	Query   string
}

type User struct {
	ID         string
	Email      string
	Name       string
	AvatarURL  string
	Status     string // "pending" | "active"
	AuthMethod string // "oauth:google", "passkey", etc.
	CreatedAt  int64
	LastLogin  int64
}

type OAuthConnection struct {
	ID         string
	UserID     string
	Provider   string
	ProviderID string
	Email      string
}

type WebAuthnCredential struct {
	ID         string
	UserID     string
	PublicKey  []byte
	SignCount  uint32
	Transports []string
	CreatedAt  int64
	LastUsed   int64
}

type Role struct {
	ID          string
	Name        string
	Permissions []string
}

type UserRole struct {
	UserID string
	RoleID string
	OrgID  *string
}

type Org struct {
	ID        string
	Name      string
	Slug      string
	CreatedAt int64
}

type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt int64
	CreatedAt int64
}

type Webhook struct {
	ID     string
	URL    string
	Events []string
	Secret string
}

type TOSAcceptance struct {
	ID         string
	UserID     string
	Version    string
	NameTyped  string
	AcceptedAt int64
	IPAddress  string
}

type AuditEntry struct {
	ID         string
	Timestamp  int64
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	Metadata   string // JSON blob
	IPAddress  string
	RequestID  string
}

type AuditListOpts struct {
	Page    int
	PerPage int
	ActorID string
	Action  string
	Since   int64
	Until   int64
}
