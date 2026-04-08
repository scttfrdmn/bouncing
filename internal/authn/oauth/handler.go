package oauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/scttfrdmn/bouncing/internal/authz"
	"github.com/scttfrdmn/bouncing/internal/session"
	"github.com/scttfrdmn/bouncing/internal/store"
)

// TokenIssuer abstracts the session layer for issuing access + refresh tokens.
type TokenIssuer interface {
	IssueAccessToken(ctx context.Context, u *store.User, roles []string, permissions []string) (string, error)
	IssueRefreshToken(ctx context.Context, userID string) (string, error)
}

// HooksDispatcher fires webhook events.
type HooksDispatcher interface {
	Dispatch(ctx context.Context, event string, payload any)
}

// LegalGate optionally intercepts the post-auth flow to collect TOS acceptance.
type LegalGate interface {
	NeedsAcceptance(ctx context.Context, userID string) bool
	IssuePendingCookie(w http.ResponseWriter, r *http.Request, userID string) error
}

// Handler processes OAuth begin/callback for one provider.
type Handler struct {
	provider    *Provider
	stateMgr    *StateManager
	store       store.Store
	policy      *authz.Policy
	engine      *authz.Engine
	issuer      *session.Issuer
	refreshMgr  *session.RefreshManager
	hooks       HooksDispatcher
	legalGate   LegalGate // may be nil
	redirectURL string
	errorURL    string
	log         *slog.Logger
}

// Config is the constructor parameters for Handler.
type Config struct {
	Provider    *Provider
	StateMgr    *StateManager
	Store       store.Store
	Policy      *authz.Policy
	Engine      *authz.Engine
	Issuer      *session.Issuer
	RefreshMgr  *session.RefreshManager
	Hooks       HooksDispatcher
	LegalGate   LegalGate
	RedirectURL string
	ErrorURL    string
	Log         *slog.Logger
}

// NewHandler creates an OAuth handler.
func NewHandler(cfg Config) *Handler {
	return &Handler{
		provider:    cfg.Provider,
		stateMgr:    cfg.StateMgr,
		store:       cfg.Store,
		policy:      cfg.Policy,
		engine:      cfg.Engine,
		issuer:      cfg.Issuer,
		refreshMgr:  cfg.RefreshMgr,
		hooks:       cfg.Hooks,
		legalGate:   cfg.LegalGate,
		redirectURL: cfg.RedirectURL,
		errorURL:    cfg.ErrorURL,
		log:         cfg.Log,
	}
}

// BeginOAuth redirects the browser to the provider's authorization endpoint.
// GET /auth/oauth/{provider}
func (h *Handler) BeginOAuth(w http.ResponseWriter, r *http.Request) {
	state, err := h.stateMgr.SetState(w, r)
	if err != nil {
		h.log.Error("oauth begin: set state", "provider", h.provider.Name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, h.provider.AuthCodeURL(state), http.StatusFound)
}

// CallbackOAuth completes the OAuth flow.
// GET /auth/oauth/{provider}/callback
func (h *Handler) CallbackOAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Validate CSRF state.
	if err := h.stateMgr.ValidateState(w, r, r.URL.Query().Get("state")); err != nil {
		h.redirectError(w, r, "invalid_state")
		return
	}

	// Exchange code → userinfo.
	info, err := h.provider.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		h.log.Error("oauth callback: exchange", "provider", h.provider.Name, "err", err)
		h.redirectError(w, r, "provider_error")
		return
	}

	// Look for an existing OAuth connection.
	conn, err := h.store.GetOAuthConnection(ctx, h.provider.Name, info.ProviderID)
	if err == nil {
		// Existing user — update last_login and issue tokens.
		u, uerr := h.store.GetUser(ctx, conn.UserID)
		if uerr != nil {
			h.log.Error("oauth callback: get user", "user_id", conn.UserID, "err", uerr)
			h.redirectError(w, r, "internal_error")
			return
		}
		u.LastLogin = time.Now().Unix()
		if err := h.store.UpdateUser(ctx, u); err != nil {
			h.log.Warn("oauth callback: update last_login", "err", err)
		}
		h.hooks.Dispatch(ctx, "user.login", map[string]any{
			"user_id": u.ID,
			"email":   u.Email,
			"method":  "oauth:" + h.provider.Name,
		})
		h.finishLogin(w, r, u, false)
		return
	}

	// New user — enforce access policy.
	if err := h.policy.Check(ctx, info.Email, h.store); err != nil {
		reason := "not_on_the_list"
		if errors.Is(err, authz.ErrDomainMismatch) {
			reason = "not_on_the_list"
		} else if errors.Is(err, authz.ErrNotInvited) {
			reason = "not_on_the_list"
		}
		h.redirectError(w, r, reason)
		return
	}

	// Resolve or create the user record.
	u, err := h.resolveUser(ctx, info)
	if err != nil {
		h.log.Error("oauth callback: resolve user", "err", err)
		h.redirectError(w, r, "internal_error")
		return
	}

	// Link the OAuth connection.
	oconn := &store.OAuthConnection{
		UserID:     u.ID,
		Provider:   h.provider.Name,
		ProviderID: info.ProviderID,
		Email:      info.Email,
	}
	if err := h.store.CreateOAuthConnection(ctx, oconn); err != nil {
		h.log.Error("oauth callback: create connection", "err", err)
		h.redirectError(w, r, "internal_error")
		return
	}

	h.hooks.Dispatch(ctx, "user.created", map[string]any{
		"user_id": u.ID,
		"email":   u.Email,
		"method":  "oauth:" + h.provider.Name,
	})

	h.finishLogin(w, r, u, true)
}

// resolveUser finds an existing pending user (invite-only) or creates a new active user.
func (h *Handler) resolveUser(ctx context.Context, info *UserInfo) (*store.User, error) {
	// Check for a pre-provisioned pending user (invite-only mode).
	if existing, err := h.store.GetUserByEmail(ctx, info.Email); err == nil && existing != nil && existing.Status == "pending" {
		existing.Status = "active"
		existing.Name = info.Name
		existing.AvatarURL = info.AvatarURL
		if err := h.store.UpdateUser(ctx, existing); err != nil {
			return nil, fmt.Errorf("resolveUser: update pending: %w", err)
		}
		return existing, nil
	}

	u := &store.User{
		Email:     info.Email,
		Name:      info.Name,
		AvatarURL: info.AvatarURL,
		Status:    "active",
	}
	if err := h.store.CreateUser(ctx, u); err != nil {
		return nil, fmt.Errorf("resolveUser: create: %w", err)
	}
	return u, nil
}

// finishLogin issues tokens (or redirects to legal gate) and sets auth cookies.
func (h *Handler) finishLogin(w http.ResponseWriter, r *http.Request, u *store.User, _ bool) {
	ctx := r.Context()

	// Legal gate check.
	if h.legalGate != nil && h.legalGate.NeedsAcceptance(ctx, u.ID) {
		if err := h.legalGate.IssuePendingCookie(w, r, u.ID); err != nil {
			h.log.Error("oauth finishLogin: legal gate cookie", "err", err)
			h.redirectError(w, r, "internal_error")
			return
		}
		http.Redirect(w, r, "/auth/agree", http.StatusFound)
		return
	}

	// Gather roles + permissions.
	userRoles, err := h.store.GetUserRoles(ctx, u.ID)
	if err != nil {
		h.log.Error("oauth finishLogin: get roles", "user_id", u.ID, "err", err)
		h.redirectError(w, r, "internal_error")
		return
	}

	roleNames, perms, err := h.resolveRolesAndPerms(ctx, userRoles)
	if err != nil {
		h.log.Error("oauth finishLogin: resolve permissions", "user_id", u.ID, "err", err)
		h.redirectError(w, r, "internal_error")
		return
	}

	claims := session.Claims{
		UserID:      u.ID,
		Email:       u.Email,
		Name:        u.Name,
		AvatarURL:   u.AvatarURL,
		Roles:       roleNames,
		Permissions: perms,
	}

	accessToken, err := h.issuer.Issue(ctx, claims)
	if err != nil {
		h.log.Error("oauth finishLogin: issue access token", "err", err)
		h.redirectError(w, r, "internal_error")
		return
	}

	refreshToken, err := h.refreshMgr.Issue(ctx, u.ID)
	if err != nil {
		h.log.Error("oauth finishLogin: issue refresh token", "err", err)
		h.redirectError(w, r, "internal_error")
		return
	}

	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	setAuthCookies(w, accessToken, refreshToken, secure)

	target := h.redirectURL
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// resolveRolesAndPerms loads Role objects for the user's assignments and merges permissions.
func (h *Handler) resolveRolesAndPerms(ctx context.Context, userRoles []*store.UserRole) ([]string, []string, error) {
	roleNames := make([]string, 0, len(userRoles))
	roles := make([]*store.Role, 0, len(userRoles))
	for _, ur := range userRoles {
		r, err := h.store.GetRole(ctx, ur.RoleID)
		if err != nil {
			return nil, nil, fmt.Errorf("GetRole(%s): %w", ur.RoleID, err)
		}
		roleNames = append(roleNames, r.Name)
		roles = append(roles, r)
	}
	perms := h.engine.MergePermissions(roles)
	return roleNames, perms, nil
}

func (h *Handler) redirectError(w http.ResponseWriter, r *http.Request, code string) {
	target := h.errorURL
	if target == "" {
		target = "/"
	}
	http.Redirect(w, r, target+"?error="+code, http.StatusFound)
}

// setAuthCookies writes the bouncing_access and bouncing_refresh cookies.
func setAuthCookies(w http.ResponseWriter, accessToken, refreshToken string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     "bouncing_access",
		Value:    accessToken,
		Path:     "/",
		MaxAge:   900,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "bouncing_refresh",
		Value:    refreshToken,
		Path:     "/auth/refresh",
		MaxAge:   7 * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

