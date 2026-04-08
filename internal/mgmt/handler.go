package mgmt

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/scttfrdmn/bouncing/internal/authz"
	"github.com/scttfrdmn/bouncing/internal/store"
)

// HooksDispatcher fires webhook events.
type HooksDispatcher interface {
	Dispatch(ctx context.Context, event string, payload any)
}

// Handler implements the management API endpoints.
type Handler struct {
	store  store.Store
	engine *authz.Engine
	hooks  HooksDispatcher
	log    *slog.Logger
}

// Config is the constructor parameters for Handler.
type Config struct {
	Store  store.Store
	Engine *authz.Engine
	Hooks  HooksDispatcher
	Log    *slog.Logger
}

// NewHandler creates a management Handler.
func NewHandler(cfg Config) *Handler {
	return &Handler{
		store:  cfg.Store,
		engine: cfg.Engine,
		hooks:  cfg.Hooks,
		log:    cfg.Log,
	}
}

// ── Users ─────────────────────────────────────────────────────────────────────

type roleOutput struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type userRow struct {
	ID         string       `json:"id"`
	Email      string       `json:"email"`
	Name       string       `json:"name"`
	Status     string       `json:"status"`
	AuthMethod string       `json:"auth_method"`
	Roles      []roleOutput `json:"roles"`
	CreatedAt  int64        `json:"created_at"`
	LastLogin  int64        `json:"last_login"`
}

// ListUsers handles GET /manage/users
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	opts := store.ListOpts{
		Page:    intParam(q.Get("page"), 1),
		PerPage: intParam(q.Get("per_page"), 20),
		Status:  q.Get("status"),
		Role:    q.Get("role"),
		Query:   q.Get("q"),
	}

	users, err := h.store.ListUsers(ctx, opts)
	if err != nil {
		h.log.Error("ListUsers", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	total, err := h.store.CountUsers(ctx, opts)
	if err != nil {
		h.log.Error("CountUsers", "err", err)
		total = int64(len(users))
	}

	rows := make([]userRow, 0, len(users))
	for _, u := range users {
		userRoles, _ := h.store.GetUserRoles(ctx, u.ID)
		var roleOutputs []roleOutput
		for _, ur := range userRoles {
			role, err := h.store.GetRole(ctx, ur.RoleID)
			if err != nil {
				continue
			}
			roleOutputs = append(roleOutputs, roleOutput{ID: role.ID, Name: role.Name})
		}
		rows = append(rows, userRow{
			ID:         u.ID,
			Email:      u.Email,
			Name:       u.Name,
			Status:     u.Status,
			AuthMethod: u.AuthMethod,
			Roles:      roleOutputs,
			CreatedAt:  u.CreatedAt,
			LastLogin:  u.LastLogin,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"users":    rows,
		"total":    total,
		"page":     opts.Page,
		"per_page": opts.PerPage,
	})
}

// InviteUser handles POST /manage/users/invite
func (h *Handler) InviteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "email required")
		return
	}
	if !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "invalid_email_format", "invalid email format")
		return
	}

	u := &store.User{Email: req.Email, Name: req.Name, Status: "pending"}
	if err := h.store.CreateUser(ctx, u); err != nil {
		h.log.Error("InviteUser: create", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	if req.Role != "" {
		if err := h.assignRoleByName(ctx, u.ID, req.Role, nil); err != nil {
			h.log.Warn("InviteUser: assign role", "err", err)
		}
	}

	h.hooks.Dispatch(ctx, "user.invited", map[string]any{
		"user_id": u.ID,
		"email":   u.Email,
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":     u.ID,
		"email":  u.Email,
		"status": u.Status,
		"role":   req.Role,
	})
}

// BulkImport handles POST /manage/users/import
func (h *Handler) BulkImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		Users []struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"users"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid request body")
		return
	}

	created, skipped := 0, 0
	var errs []string

	for _, item := range req.Users {
		if !strings.Contains(item.Email, "@") {
			errs = append(errs, item.Email+": invalid email format")
			continue
		}
		u := &store.User{Email: item.Email, Status: "pending"}
		err := h.store.CreateUser(ctx, u)
		if err != nil {
			if isUniqueConstraint(err) {
				skipped++
				continue
			}
			errs = append(errs, item.Email+": "+err.Error())
			continue
		}
		if item.Role != "" {
			_ = h.assignRoleByName(ctx, u.ID, item.Role, nil)
		}
		created++
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"created": created,
		"skipped": skipped,
		"errors":  errs,
	})
}

// DeleteUser handles DELETE /manage/users/{id}
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "id required")
		return
	}

	if _, err := h.store.GetUser(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "user not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	// Count tokens before deletion.
	// We don't have a count method, so revoke and report 0 for now.
	_ = h.store.DeleteUserRefreshTokens(ctx, id)

	if err := h.store.DeleteUser(ctx, id); err != nil {
		h.log.Error("DeleteUser", "id", id, "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	h.hooks.Dispatch(ctx, "user.deleted", map[string]any{"user_id": id})

	writeJSON(w, http.StatusOK, map[string]any{
		"deleted":          true,
		"sessions_revoked": 0,
	})
}

// AssignRole handles POST /manage/users/{id}/roles
func (h *Handler) AssignRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("id")

	var req struct {
		Role  string  `json:"role"`
		OrgID *string `json:"org_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Role == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "role required")
		return
	}

	if err := h.assignRoleByName(ctx, userID, req.Role, req.OrgID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "role not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// RevokeRole handles DELETE /manage/users/{id}/roles/{role_id}
func (h *Handler) RevokeRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("id")
	roleID := r.PathValue("role_id")

	if err := h.store.RevokeRole(ctx, userID, roleID, nil); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ListRoles handles GET /manage/roles
func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	roles, err := h.store.ListRoles(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"roles": roles})
}

// CreateRole handles POST /manage/roles
func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "name required")
		return
	}

	// Sort + deduplicate permissions for determinism.
	sort.Strings(req.Permissions)
	req.Permissions = dedupeStrings(req.Permissions)

	role := &store.Role{Name: req.Name, Permissions: req.Permissions}
	if err := h.store.CreateRole(ctx, role); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, role)
}

// ListAgreements handles GET /manage/users/{id}/agreements
func (h *Handler) ListAgreements(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("id")

	acceptances, err := h.store.ListTOSAcceptances(ctx, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"agreements": acceptances})
}

// ── Organizations ─────────────────────────────────────────────────────────────

// CreateOrg handles POST /manage/orgs
func (h *Handler) CreateOrg(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "name required")
		return
	}

	o := &store.Org{Name: req.Name, Slug: req.Slug}
	if err := h.store.CreateOrg(ctx, o); err != nil {
		h.log.Error("CreateOrg", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, o)
}

// ListOrgs handles GET /manage/orgs
func (h *Handler) ListOrgs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgs, err := h.store.ListOrgs(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"orgs": orgs})
}

// AddOrgMember handles POST /manage/orgs/{org_id}/members
func (h *Handler) AddOrgMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("org_id")

	var req struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "user_id required")
		return
	}

	role, err := h.store.GetRoleByName(ctx, req.Role)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "role not found")
		return
	}

	if err := h.store.AddOrgMember(ctx, orgID, req.UserID, role.ID); err != nil {
		h.log.Error("AddOrgMember", "org_id", orgID, "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// RemoveOrgMember handles DELETE /manage/orgs/{org_id}/members/{uid}
func (h *Handler) RemoveOrgMember(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := r.PathValue("org_id")
	userID := r.PathValue("uid")

	if err := h.store.RemoveOrgMember(ctx, orgID, userID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ── Webhooks ──────────────────────────────────────────────────────────────────

// ListWebhooks handles GET /manage/webhooks
func (h *Handler) ListWebhooks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	whs, err := h.store.ListWebhooks(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": whs})
}

// CreateWebhook handles POST /manage/webhooks
func (h *Handler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
		Secret string   `json:"secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.URL == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "url required")
		return
	}
	if len(req.Events) == 0 {
		req.Events = []string{"*"}
	}

	wh := &store.Webhook{URL: req.URL, Events: req.Events, Secret: req.Secret}
	if err := h.store.CreateWebhook(ctx, wh); err != nil {
		h.log.Error("CreateWebhook", "err", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, wh)
}

// DeleteWebhook handles DELETE /manage/webhooks/{id}
func (h *Handler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	if err := h.store.DeleteWebhook(ctx, id); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (h *Handler) assignRoleByName(ctx context.Context, userID, roleName string, orgID *string) error {
	role, err := h.store.GetRoleByName(ctx, roleName)
	if err != nil {
		return err
	}
	return h.store.AssignRole(ctx, userID, role.ID, orgID)
}

func isUniqueConstraint(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "UNIQUE constraint failed") ||
		strings.Contains(s, "unique constraint")
}

func intParam(s string, def int) int {
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 1 {
		return def
	}
	return v
}

func dedupeStrings(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	out := ss[:0]
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func writeError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

func writeJSON(w http.ResponseWriter, statusCode int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(v)
}
