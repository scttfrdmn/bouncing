// Package dashboard provides an embedded HTMX + Go templates management UI.
package dashboard

import (
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/scttfrdmn/bouncing/internal/store"
)

//go:embed templates/*.html templates/partials/*.html
var templateFiles embed.FS

//go:embed static/*
var staticFiles embed.FS

// StaticFS returns the embedded static file system for serving CSS/JS.
func StaticFS() fs.FS {
	sub, _ := fs.Sub(staticFiles, "static")
	return sub
}

// Handler serves the management dashboard pages.
type Handler struct {
	store store.Store
	tmpl  *template.Template
	log   *slog.Logger
}

// NewHandler creates a dashboard Handler with parsed templates.
func NewHandler(st store.Store, log *slog.Logger) *Handler {
	funcMap := template.FuncMap{
		"joinPerms": func(perms []string) string { return strings.Join(perms, ", ") },
	}
	tmpl := template.Must(template.New("").Funcs(funcMap).ParseFS(templateFiles,
		"templates/*.html", "templates/partials/*.html",
	))
	return &Handler{store: st, tmpl: tmpl, log: log}
}

// ── Page handlers (full HTML) ────────────────────────────────────────────────

// Users handles GET /dashboard/ and GET /dashboard/users
func (h *Handler) Users(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opts := store.ListOpts{
		Page:    intParam(q.Get("page"), 1),
		PerPage: 50,
		Status:  q.Get("status"),
		Query:   q.Get("q"),
	}

	users, err := h.store.ListUsers(r.Context(), opts)
	if err != nil {
		h.serverError(w, "list users", err)
		return
	}
	total, _ := h.store.CountUsers(r.Context(), opts)

	h.render(w, "layout", map[string]any{
		"Title":  "Users",
		"Nav":    "users",
		"Users":  users,
		"Total":  total,
		"Page":   opts.Page,
		"Query":  opts.Query,
		"Status": opts.Status,
	})
}

// UserDetail handles GET /dashboard/users/{id}
func (h *Handler) UserDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")

	u, err := h.store.GetUser(ctx, id)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	userRoles, _ := h.store.GetUserRoles(ctx, id)
	type roleInfo struct {
		RoleID string
		Name   string
	}
	var roles []roleInfo
	for _, ur := range userRoles {
		name := ur.RoleID
		if role, err := h.store.GetRole(ctx, ur.RoleID); err == nil {
			name = role.Name
		}
		roles = append(roles, roleInfo{RoleID: ur.RoleID, Name: name})
	}

	allRoles, _ := h.store.ListRoles(ctx)
	agreements, _ := h.store.ListTOSAcceptances(ctx, id)

	h.render(w, "layout", map[string]any{
		"Title":          u.Email,
		"Nav":            "users",
		"User":           u,
		"Roles":          roles,
		"AvailableRoles": allRoles,
		"Agreements":     agreements,
	})
}

// Roles handles GET /dashboard/roles
func (h *Handler) Roles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.store.ListRoles(r.Context())
	if err != nil {
		h.serverError(w, "list roles", err)
		return
	}
	h.render(w, "layout", map[string]any{
		"Title": "Roles",
		"Nav":   "roles",
		"Roles": roles,
	})
}

// Orgs handles GET /dashboard/orgs
func (h *Handler) Orgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.store.ListOrgs(r.Context())
	if err != nil {
		h.serverError(w, "list orgs", err)
		return
	}
	h.render(w, "layout", map[string]any{
		"Title": "Organizations",
		"Nav":   "orgs",
		"Orgs":  orgs,
	})
}

// Webhooks handles GET /dashboard/webhooks
func (h *Handler) Webhooks(w http.ResponseWriter, r *http.Request) {
	webhooks, err := h.store.ListWebhooks(r.Context())
	if err != nil {
		h.serverError(w, "list webhooks", err)
		return
	}
	h.render(w, "layout", map[string]any{
		"Title":    "Webhooks",
		"Nav":      "webhooks",
		"Webhooks": webhooks,
	})
}

// Audit handles GET /dashboard/audit
func (h *Handler) Audit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opts := store.AuditListOpts{
		Page:    intParam(q.Get("page"), 1),
		PerPage: 50,
		ActorID: q.Get("actor_id"),
		Action:  q.Get("action"),
	}

	entries, total, err := h.store.ListAuditEntries(r.Context(), opts)
	if err != nil {
		h.serverError(w, "list audit", err)
		return
	}

	h.render(w, "layout", map[string]any{
		"Title":   "Audit Log",
		"Nav":     "audit",
		"Entries": entries,
		"Total":   total,
		"Page":    opts.Page,
		"ActorID": opts.ActorID,
		"Action":  opts.Action,
	})
}

// ── HTMX mutation handlers (return fragments) ────────────────────────────────

// DeleteUser handles DELETE /dashboard/users/{id}
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.DeleteUser(r.Context(), id); err != nil {
		h.log.Warn("dashboard: delete user", "id", id, "err", err)
	}
	w.WriteHeader(http.StatusOK) // HTMX removes the row via hx-swap="outerHTML"
}

// CreateRole handles POST /dashboard/roles
func (h *Handler) CreateRole(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	perms := splitAndTrim(r.FormValue("permissions"))

	role := &store.Role{Name: name, Permissions: perms}
	if err := h.store.CreateRole(r.Context(), role); err != nil {
		http.Error(w, "create role failed", http.StatusInternalServerError)
		return
	}
	h.renderPartial(w, "role_row", role)
}

// DeleteRole handles DELETE /dashboard/roles/{id}
func (h *Handler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_ = h.store.DeleteRole(r.Context(), id)
	w.WriteHeader(http.StatusOK)
}

// AssignRole handles POST /dashboard/users/{id}/roles
func (h *Handler) AssignRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("id")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	roleName := r.FormValue("role")
	role, err := h.store.GetRoleByName(ctx, roleName)
	if err != nil {
		http.Error(w, "role not found", http.StatusBadRequest)
		return
	}
	_ = h.store.AssignRole(ctx, userID, role.ID, nil)

	// Re-render the roles section.
	h.renderUserRolesSection(w, r, userID)
}

// RevokeRole handles DELETE /dashboard/users/{id}/roles/{role_id}
func (h *Handler) RevokeRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("id")
	roleID := r.PathValue("role_id")
	_ = h.store.RevokeRole(ctx, userID, roleID, nil)

	h.renderUserRolesSection(w, r, userID)
}

// CreateOrg handles POST /dashboard/orgs
func (h *Handler) CreateOrg(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	org := &store.Org{
		Name: strings.TrimSpace(r.FormValue("name")),
		Slug: strings.TrimSpace(r.FormValue("slug")),
	}
	if err := h.store.CreateOrg(r.Context(), org); err != nil {
		http.Error(w, "create org failed", http.StatusInternalServerError)
		return
	}
	h.renderPartial(w, "org_row", org)
}

// CreateWebhook handles POST /dashboard/webhooks
func (h *Handler) CreateWebhook(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	wh := &store.Webhook{
		URL:    strings.TrimSpace(r.FormValue("url")),
		Events: splitAndTrim(r.FormValue("events")),
		Secret: strings.TrimSpace(r.FormValue("secret")),
	}
	if err := h.store.CreateWebhook(r.Context(), wh); err != nil {
		http.Error(w, "create webhook failed", http.StatusInternalServerError)
		return
	}
	h.renderPartial(w, "webhook_row", wh)
}

// DeleteWebhook handles DELETE /dashboard/webhooks/{id}
func (h *Handler) DeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	_ = h.store.DeleteWebhook(r.Context(), id)
	w.WriteHeader(http.StatusOK)
}

// ── helpers ──────────────────────────────────────────────────────────────────

func (h *Handler) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		h.log.Error("dashboard: render", "template", name, "err", err)
	}
}

func (h *Handler) renderPartial(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, name, data); err != nil {
		h.log.Error("dashboard: render partial", "template", name, "err", err)
	}
}

func (h *Handler) renderUserRolesSection(w http.ResponseWriter, r *http.Request, userID string) {
	ctx := r.Context()
	userRoles, _ := h.store.GetUserRoles(ctx, userID)
	type roleInfo struct {
		RoleID string
		Name   string
	}
	var roles []roleInfo
	for _, ur := range userRoles {
		name := ur.RoleID
		if role, err := h.store.GetRole(ctx, ur.RoleID); err == nil {
			name = role.Name
		}
		roles = append(roles, roleInfo{RoleID: ur.RoleID, Name: name})
	}
	allRoles, _ := h.store.ListRoles(ctx)

	// Render just the roles section fragment.
	h.render(w, "layout", map[string]any{
		"Title":          "User",
		"Nav":            "users",
		"User":           &store.User{ID: userID},
		"Roles":          roles,
		"AvailableRoles": allRoles,
		"Agreements":     nil,
	})
}

func (h *Handler) serverError(w http.ResponseWriter, op string, err error) {
	h.log.Error("dashboard", "op", op, "err", err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
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

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
