package webauthn

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	gowa "github.com/go-webauthn/webauthn/webauthn"
	"github.com/oklog/ulid/v2"

	"github.com/scttfrdmn/bouncing/internal/authz"
	"github.com/scttfrdmn/bouncing/internal/session"
	"github.com/scttfrdmn/bouncing/internal/store"
)

const loginSessionCookie = "bouncing_wa_session"

// HooksDispatcher fires webhook events.
type HooksDispatcher interface {
	Dispatch(ctx context.Context, event string, payload any)
}

// Handler processes WebAuthn registration and authentication ceremonies.
type Handler struct {
	wa         *gowa.WebAuthn
	sessions   *SessionStore
	store      store.Store
	engine     *authz.Engine
	issuer     *session.Issuer
	refreshMgr *session.RefreshManager
	hooks      HooksDispatcher
	log        *slog.Logger
}

// Config is the constructor parameters for Handler.
type Config struct {
	WebAuthn   *gowa.WebAuthn
	Sessions   *SessionStore
	Store      store.Store
	Engine     *authz.Engine
	Issuer     *session.Issuer
	RefreshMgr *session.RefreshManager
	Hooks      HooksDispatcher
	Log        *slog.Logger
}

// NewHandler creates a WebAuthn handler.
func NewHandler(cfg Config) *Handler {
	return &Handler{
		wa:         cfg.WebAuthn,
		sessions:   cfg.Sessions,
		store:      cfg.Store,
		engine:     cfg.Engine,
		issuer:     cfg.Issuer,
		refreshMgr: cfg.RefreshMgr,
		hooks:      cfg.Hooks,
		log:        cfg.Log,
	}
}

// ── Registration ──────────────────────────────────────────────────────────────

// RegisterBegin starts a passkey registration ceremony.
// POST /auth/webauthn/register/begin
// Request body: {"user_id": "..."}
func (h *Handler) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "user_id required")
		return
	}

	u, err := h.store.GetUser(ctx, req.UserID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user_not_found", "user not found")
		return
	}

	creds, err := h.store.GetWebAuthnCredentials(ctx, u.ID)
	if err != nil {
		h.log.Error("webauthn register begin: get credentials", "user_id", u.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	wu := newWebAuthnUser(u, creds)
	options, sessionData, err := h.wa.BeginRegistration(wu)
	if err != nil {
		h.log.Error("webauthn register begin", "user_id", u.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	h.sessions.Save(u.ID, sessionData)
	writeJSON(w, http.StatusOK, options)
}

// RegisterFinish completes the passkey registration ceremony.
// POST /auth/webauthn/register/finish?user_id=...
// Request body: raw navigator.credentials.create() response
func (h *Handler) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "user_id required")
		return
	}

	u, err := h.store.GetUser(ctx, userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "user_not_found", "user not found")
		return
	}

	sessionData := h.sessions.Load(u.ID)
	if sessionData == nil {
		writeError(w, http.StatusBadRequest, "session_expired", "registration session expired")
		return
	}

	creds, err := h.store.GetWebAuthnCredentials(ctx, u.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	wu := newWebAuthnUser(u, creds)

	credential, err := h.wa.FinishRegistration(wu, *sessionData, r)
	if err != nil {
		h.log.Warn("webauthn register finish: verification failed", "user_id", u.ID, "err", err)
		writeError(w, http.StatusBadRequest, "verification_failed", "credential verification failed")
		return
	}

	storedCred := &store.WebAuthnCredential{
		UserID:    u.ID,
		PublicKey: credential.PublicKey,
		SignCount: credential.Authenticator.SignCount,
		CreatedAt: time.Now().Unix(),
	}
	if err := h.store.CreateWebAuthnCredential(ctx, storedCred); err != nil {
		h.log.Error("webauthn register finish: store credential", "user_id", u.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	h.hooks.Dispatch(ctx, "user.credential.added", map[string]any{
		"user_id":       u.ID,
		"credential_id": storedCred.ID,
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"credential_id": storedCred.ID,
		"created_at":    time.Unix(storedCred.CreatedAt, 0).UTC().Format(time.RFC3339),
	})
}

// ── Authentication ────────────────────────────────────────────────────────────

// LoginBegin starts a passkey authentication ceremony (discoverable/resident key).
// POST /auth/webauthn/login/begin
func (h *Handler) LoginBegin(w http.ResponseWriter, r *http.Request) {
	options, sessionData, err := h.wa.BeginDiscoverableLogin()
	if err != nil {
		h.log.Error("webauthn login begin", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	// Generate a unique session key and send it as a short-lived cookie.
	sessionKey := ulid.Make().String()
	h.sessions.Save(sessionKey, sessionData)

	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     loginSessionCookie,
		Value:    sessionKey,
		Path:     "/auth/webauthn/login",
		MaxAge:   300, // 5 minutes
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, options)
}

// LoginFinish completes the passkey authentication ceremony.
// POST /auth/webauthn/login/finish
func (h *Handler) LoginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	cookie, err := r.Cookie(loginSessionCookie)
	if err != nil {
		writeError(w, http.StatusBadRequest, "session_expired", "login session not found")
		return
	}
	// Clear the session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     loginSessionCookie,
		Value:    "",
		Path:     "/auth/webauthn/login",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	})

	sessionData := h.sessions.Load(cookie.Value)
	if sessionData == nil {
		writeError(w, http.StatusBadRequest, "session_expired", "login session expired")
		return
	}

	var resolvedUser *store.User
	discoverableHandler := func(rawID, userHandle []byte) (gowa.User, error) {
		userID, err := ulidFromBytes(userHandle)
		if err != nil {
			userID = string(userHandle)
		}

		u, err := h.store.GetUser(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("user not found: %w", err)
		}

		creds, err := h.store.GetWebAuthnCredentials(ctx, u.ID)
		if err != nil {
			return nil, fmt.Errorf("get credentials: %w", err)
		}

		resolvedUser = u
		return newWebAuthnUser(u, creds), nil
	}

	credential, err := h.wa.FinishDiscoverableLogin(discoverableHandler, *sessionData, r)
	if err != nil {
		h.log.Warn("webauthn login finish: verification failed", "err", err)
		writeError(w, http.StatusUnauthorized, "verification_failed", "authentication failed")
		return
	}

	if credential.Authenticator.CloneWarning {
		h.log.Warn("webauthn login finish: clone warning", "user_id", resolvedUser.ID)
		writeError(w, http.StatusUnauthorized, "cloned_authenticator_detected", "authenticator may be cloned")
		return
	}

	// Update sign count for the matched credential.
	storedCreds, _ := h.store.GetWebAuthnCredentials(ctx, resolvedUser.ID)
	for _, sc := range storedCreds {
		if string(sc.ID) == string(credential.ID) {
			sc.SignCount = credential.Authenticator.SignCount
			sc.LastUsed = time.Now().Unix()
			_ = h.store.UpdateWebAuthnCredential(ctx, sc)
			break
		}
	}

	userRoles, _ := h.store.GetUserRoles(ctx, resolvedUser.ID)
	roleNames, perms := h.mergeRolesAndPerms(ctx, userRoles)

	claims := session.Claims{
		UserID:      resolvedUser.ID,
		Email:       resolvedUser.Email,
		Name:        resolvedUser.Name,
		AvatarURL:   resolvedUser.AvatarURL,
		Roles:       roleNames,
		Permissions: perms,
	}

	accessToken, err := h.issuer.Issue(ctx, claims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	refreshToken, err := h.refreshMgr.Issue(ctx, resolvedUser.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	h.hooks.Dispatch(ctx, "user.login", map[string]any{
		"user_id": resolvedUser.ID,
		"email":   resolvedUser.Email,
		"method":  "webauthn",
	})

	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	setAuthCookies(w, accessToken, refreshToken, secure)

	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":          resolvedUser.ID,
			"email":       resolvedUser.Email,
			"name":        resolvedUser.Name,
			"roles":       roleNames,
			"permissions": perms,
		},
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    900,
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (h *Handler) mergeRolesAndPerms(ctx context.Context, userRoles []*store.UserRole) ([]string, []string) {
	roleNames := make([]string, 0, len(userRoles))
	roles := make([]*store.Role, 0, len(userRoles))
	for _, ur := range userRoles {
		r, err := h.store.GetRole(ctx, ur.RoleID)
		if err != nil {
			continue
		}
		roleNames = append(roleNames, r.Name)
		roles = append(roles, r)
	}
	return roleNames, h.engine.MergePermissions(roles)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]any{
		"error": map[string]any{
			"code":    errCode,
			"message": msg,
		},
	})
}

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

// ulidFromBytes reconstructs a ULID string ID from its 16-byte binary form.
func ulidFromBytes(b []byte) (string, error) {
	if len(b) != 16 {
		return "", fmt.Errorf("expected 16 bytes, got %d", len(b))
	}
	var id ulid.ULID
	copy(id[:], b)
	return id.String(), nil
}
