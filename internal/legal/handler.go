package legal

import (
	"context"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/scttfrdmn/bouncing/internal/authz"
	"github.com/scttfrdmn/bouncing/internal/i18n"
	"github.com/scttfrdmn/bouncing/internal/session"
	"github.com/scttfrdmn/bouncing/internal/store"
)

// HooksDispatcher fires webhook events.
type HooksDispatcher interface {
	Dispatch(ctx context.Context, event string, payload any)
}

// Handler serves the legal agreement form and records acceptance.
type Handler struct {
	gate       *Gate
	issuer     *session.Issuer
	refreshMgr *session.RefreshManager
	store      store.Store
	engine     *authz.Engine
	i18n       *i18n.Localizer
	log        *slog.Logger
}

// NewHandler creates a legal Handler.
func NewHandler(
	gate *Gate,
	issuer *session.Issuer,
	refreshMgr *session.RefreshManager,
	st store.Store,
	engine *authz.Engine,
	loc *i18n.Localizer,
	log *slog.Logger,
) *Handler {
	return &Handler{
		gate:       gate,
		issuer:     issuer,
		refreshMgr: refreshMgr,
		store:      st,
		engine:     engine,
		i18n:       loc,
		log:        log,
	}
}

var agreementTmpl = template.Must(template.New("agree").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Agreement Required</title>
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:4rem auto;padding:0 1rem}
input,button{display:block;margin:.5rem 0}button{padding:.5rem 1rem;cursor:pointer}</style>
</head>
<body>
<h1>Agreement Required</h1>
<p>Please review and accept the <a href="{{.DocumentURL}}" target="_blank">{{.DocumentLabel}}</a> to continue.</p>
<form method="POST" action="/auth/agree">
  <label>Your full name:<br><input type="text" name="name" required placeholder="Jane Smith"></label>
  <label>Date: <input type="text" name="date" value="{{.Today}}" readonly></label>
  <label><input type="checkbox" name="agreed" value="true" required>
    I agree to the {{.DocumentLabel}}</label>
  <button type="submit">Continue</button>
</form>
</body>
</html>
`))

// ShowAgreement renders the agreement form.
// GET /auth/agree
func (h *Handler) ShowAgreement(w http.ResponseWriter, r *http.Request) {
	if _, err := h.gate.ValidatePendingCookie(r); err != nil {
		http.Error(w, "session expired — please sign in again", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = agreementTmpl.Execute(w, map[string]string{
		"DocumentURL":   h.gate.DocumentURL(),
		"DocumentLabel": h.gate.DocumentLabel(),
		"Today":         time.Now().Format("2006-01-02"),
	})
}

// RecordAgreement processes the form submission.
// POST /auth/agree
func (h *Handler) RecordAgreement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, err := h.gate.ValidatePendingCookie(r)
	if err != nil {
		http.Error(w, "session expired — please sign in again", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	agreed := r.FormValue("agreed") == "true"

	if !agreed || name == "" {
		http.Error(w, "name and agreement required", http.StatusBadRequest)
		return
	}

	ipAddr := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ipAddr = strings.SplitN(xff, ",", 2)[0]
	}

	if err := h.gate.Record(ctx, userID, name, ipAddr); err != nil {
		h.log.Error("legal RecordAgreement: record", "user_id", userID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.gate.ClearPendingCookie(w, r)

	// Issue tokens now that the user has accepted.
	u, err := h.store.GetUser(ctx, userID)
	if err != nil {
		h.log.Error("legal RecordAgreement: get user", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	userRoles, _ := h.store.GetUserRoles(ctx, u.ID)
	roleNames := make([]string, 0, len(userRoles))
	storeRoles := make([]*store.Role, 0, len(userRoles))
	for _, ur := range userRoles {
		role, err := h.store.GetRole(ctx, ur.RoleID)
		if err != nil {
			continue
		}
		roleNames = append(roleNames, role.Name)
		storeRoles = append(storeRoles, role)
	}
	perms := h.engine.MergePermissions(storeRoles)

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
		h.log.Error("legal RecordAgreement: issue access token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	refreshToken, err := h.refreshMgr.Issue(ctx, u.ID)
	if err != nil {
		h.log.Error("legal RecordAgreement: issue refresh token", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	secure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	setAuthCookies(w, accessToken, refreshToken, secure)

	http.Redirect(w, r, "/", http.StatusFound)
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
