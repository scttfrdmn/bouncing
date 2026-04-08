package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/scttfrdmn/bouncing/internal/session"
)

// handleRefresh rotates the refresh token and issues a new access token.
// POST /auth/refresh
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var rawToken string

	// Accept token from JSON body or cookie.
	if r.Header.Get("Content-Type") == "application/json" {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			rawToken = req.RefreshToken
		}
	}
	if rawToken == "" {
		if c, err := r.Cookie("bouncing_refresh"); err == nil {
			rawToken = c.Value
		}
	}
	if rawToken == "" {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidRequest, "refresh_token required")
		return
	}

	newRefresh, userID, err := s.refreshMgr.Rotate(ctx, rawToken)
	if err != nil {
		if errors.Is(err, session.ErrTokenReplayed) {
			writeError(w, http.StatusUnauthorized, ErrCodeTokenRevoked, "token replayed — all sessions revoked")
			return
		}
		if errors.Is(err, session.ErrTokenExpired) {
			writeError(w, http.StatusUnauthorized, ErrCodeSessionExpired, "refresh token expired")
			return
		}
		s.log.Error("handleRefresh: rotate", "err", err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternalError, "internal error")
		return
	}

	u, err := s.store.GetUser(ctx, userID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, ErrCodeUnauthorized, "user not found")
		return
	}

	roleNames, perms := s.resolveRolesPerms(r.Context(), u.ID)

	claims := session.Claims{
		UserID:      u.ID,
		Email:       u.Email,
		Name:        u.Name,
		AvatarURL:   u.AvatarURL,
		Roles:       roleNames,
		Permissions: perms,
	}

	accessToken, err := s.issuer.Issue(ctx, claims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, ErrCodeInternalError, "internal error")
		return
	}

	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     "bouncing_refresh",
		Value:    newRefresh,
		Path:     "/auth/refresh",
		MaxAge:   7 * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"refresh_token": newRefresh,
		"expires_in":    900,
	})
}

// handleLogout revokes the refresh token and clears auth cookies.
// POST /auth/logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if c, err := r.Cookie("bouncing_refresh"); err == nil {
		_ = s.refreshMgr.Revoke(ctx, c.Value)
	}

	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	for _, name := range []string{"bouncing_access", "bouncing_refresh"} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}

	logoutURL := s.cfg.Auth.LogoutURL
	if logoutURL == "" {
		logoutURL = "/"
	}
	http.Redirect(w, r, logoutURL, http.StatusFound)
}

// handleMe returns the current user's info from the JWT claims.
// GET /auth/me
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, ErrCodeUnauthorized, "not authenticated")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":          claims.UserID,
		"email":       claims.Email,
		"name":        claims.Name,
		"avatar_url":  claims.AvatarURL,
		"roles":       claims.Roles,
		"permissions": claims.Permissions,
		"org_id":      claims.OrgID,
	})
}

// resolveRolesPerms loads role names and merged permissions for a user.
func (s *Server) resolveRolesPerms(ctx context.Context, userID string) ([]string, []string) {
	userRoles, _ := s.store.GetUserRoles(ctx, userID)
	roleNames := make([]string, 0, len(userRoles))
	var allPerms []string
	for _, ur := range userRoles {
		role, err := s.store.GetRole(ctx, ur.RoleID)
		if err != nil {
			continue
		}
		roleNames = append(roleNames, role.Name)
		allPerms = append(allPerms, role.Permissions...)
	}
	// Deduplicate and sort permissions for deterministic JWT claims.
	sort.Strings(allPerms)
	perms := allPerms[:0]
	seen := make(map[string]struct{})
	for _, p := range allPerms {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			perms = append(perms, p)
		}
	}
	return roleNames, perms
}
