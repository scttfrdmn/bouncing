// Package scim implements SCIM 2.0 provisioning endpoints for Users and Groups.
// These endpoints allow enterprise identity providers (Okta, Azure AD, Google
// Workspace) to push user changes in real time.
package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/scttfrdmn/bouncing/internal/store"
)

// SCIMStore is the subset of store.Store needed by the SCIM handler.
type SCIMStore interface {
	CreateUser(context.Context, *store.User) error
	GetUser(context.Context, string) (*store.User, error)
	UpdateUser(context.Context, *store.User) error
	DeleteUser(context.Context, string) error
	ListRoles(context.Context) ([]*store.Role, error)
}

// HooksDispatcher fires webhook events.
type HooksDispatcher interface {
	Dispatch(ctx context.Context, event string, payload any)
}

// Handler implements SCIM 2.0 resource endpoints.
type Handler struct {
	store SCIMStore
	hooks HooksDispatcher
	log   *slog.Logger
}

// NewHandler creates a SCIM handler.
func NewHandler(st SCIMStore, hooks HooksDispatcher, log *slog.Logger) *Handler {
	return &Handler{store: st, hooks: hooks, log: log}
}

// ── SCIM User Resource ───────────────────────────────────────────────────────

// CreateUser handles POST /scim/v2/Users
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req scimUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid JSON body")
		return
	}

	if req.UserName == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}
	if !validEmail(req.UserName) {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName must be a valid email")
		return
	}

	u := &store.User{
		Email:      req.UserName,
		Name:       req.DisplayName,
		Status:     "active",
		AuthMethod: "scim",
		CreatedAt:  time.Now().Unix(),
	}
	if !req.Active {
		u.Status = "suspended"
	}

	if err := h.store.CreateUser(r.Context(), u); err != nil {
		h.log.Warn("scim: create user", "email", req.UserName, "err", err)
		writeSCIMError(w, http.StatusConflict, "uniqueness", "user already exists")
		return
	}

	if h.hooks != nil {
		h.hooks.Dispatch(r.Context(), "user.created", map[string]any{
			"user_id": u.ID, "email": u.Email, "method": "scim",
		})
	}

	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(userToSCIM(u))
}

// GetUser handles GET /scim/v2/Users/{id}
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "noTarget", "user not found")
		return
	}

	w.Header().Set("Content-Type", scimContentType)
	_ = json.NewEncoder(w).Encode(userToSCIM(u))
}

// PatchUser handles PATCH /scim/v2/Users/{id}
func (h *Handler) PatchUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := h.store.GetUser(r.Context(), id)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "noTarget", "user not found")
		return
	}

	var req scimPatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid JSON body")
		return
	}

	for _, op := range req.Operations {
		switch op.Path {
		case "active":
			if active, ok := op.Value.(bool); ok {
				if active {
					u.Status = "active"
				} else {
					u.Status = "suspended"
				}
			}
		case "displayName":
			if name, ok := op.Value.(string); ok {
				u.Name = name
			}
		case "userName":
			if email, ok := op.Value.(string); ok {
				u.Email = email
			}
		}
	}

	if err := h.store.UpdateUser(r.Context(), u); err != nil {
		h.log.Warn("scim: update user", "id", id, "err", err)
		writeSCIMError(w, http.StatusInternalServerError, "internalError", "update failed")
		return
	}

	w.Header().Set("Content-Type", scimContentType)
	_ = json.NewEncoder(w).Encode(userToSCIM(u))
}

// DeleteUser handles DELETE /scim/v2/Users/{id}
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if err := h.store.DeleteUser(r.Context(), id); err != nil {
		writeSCIMError(w, http.StatusNotFound, "noTarget", "user not found")
		return
	}

	if h.hooks != nil {
		h.hooks.Dispatch(r.Context(), "user.deleted", map[string]any{"user_id": id, "method": "scim"})
	}

	w.WriteHeader(http.StatusNoContent)
}

// ── SCIM Group Resource ──────────────────────────────────────────────────────

// ListGroups handles GET /scim/v2/Groups — maps roles to SCIM Groups.
func (h *Handler) ListGroups(w http.ResponseWriter, r *http.Request) {
	roles, err := h.store.ListRoles(r.Context())
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "internalError", "list roles failed")
		return
	}

	groups := make([]scimGroup, 0, len(roles))
	for _, r := range roles {
		groups = append(groups, scimGroup{
			Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
			ID:          r.ID,
			DisplayName: r.Name,
		})
	}

	w.Header().Set("Content-Type", scimContentType)
	_ = json.NewEncoder(w).Encode(scimListResponse{
		Schemas:      []string{"urn:ietf:params:scim:api:messages:2.0:ListResponse"},
		TotalResults: len(groups),
		Resources:    groups,
	})
}

// ── SCIM types ───────────────────────────────────────────────────────────────

const scimContentType = "application/scim+json"

type scimUserRequest struct {
	Schemas     []string `json:"schemas"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName"`
	Active      bool     `json:"active"`
	ExternalID  string   `json:"externalId"`
}

type scimPatchRequest struct {
	Schemas    []string       `json:"schemas"`
	Operations []scimPatchOp `json:"Operations"`
}

type scimPatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

type scimUser struct {
	Schemas  []string `json:"schemas"`
	ID       string   `json:"id"`
	UserName string   `json:"userName"`
	Name     struct {
		Formatted string `json:"formatted"`
	} `json:"name"`
	DisplayName string `json:"displayName"`
	Active      bool   `json:"active"`
	Meta        struct {
		ResourceType string `json:"resourceType"`
		Created      string `json:"created"`
		Location     string `json:"location"`
	} `json:"meta"`
}

type scimGroup struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	DisplayName string   `json:"displayName"`
}

type scimListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	Resources    any      `json:"Resources"`
}

func userToSCIM(u *store.User) scimUser {
	su := scimUser{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:          u.ID,
		UserName:    u.Email,
		DisplayName: u.Name,
		Active:      u.Status == "active",
	}
	su.Name.Formatted = u.Name
	su.Meta.ResourceType = "User"
	su.Meta.Created = fmt.Sprintf("%d", u.CreatedAt)
	su.Meta.Location = "/scim/v2/Users/" + u.ID
	return su
}

func validEmail(email string) bool {
	at := strings.LastIndex(email, "@")
	return at > 0 && at < len(email)-1 && strings.Contains(email[at+1:], ".")
}

func writeSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"},
		"status":  status,
		"scimType": scimType,
		"detail":  detail,
	})
}
