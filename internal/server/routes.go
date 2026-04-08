package server

import (
	"net/http"
)

// registerRoutes wires all application endpoints onto mux.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	authMiddleware := RequireAuth(s.issuer)
	apiKeyMiddleware := RequireAPIKey(s.apiKey.Validate)

	// ── JWKS ──────────────────────────────────────────────────────────────────
	mux.Handle("GET /.well-known/jwks.json", s.jwksHandler)
	mux.Handle("GET /auth/jwks", s.jwksHandler)

	// ── OAuth ─────────────────────────────────────────────────────────────────
	for _, h := range s.oauthHandlers {
		provider := h.ProviderName()
		mux.HandleFunc("GET /auth/oauth/"+provider, h.BeginOAuth)
		mux.HandleFunc("GET /auth/oauth/"+provider+"/callback", h.CallbackOAuth)
	}

	// ── WebAuthn ──────────────────────────────────────────────────────────────
	if s.webAuthnHandler != nil {
		mux.HandleFunc("POST /auth/webauthn/register/begin", s.webAuthnHandler.RegisterBegin)
		mux.HandleFunc("POST /auth/webauthn/register/finish", s.webAuthnHandler.RegisterFinish)
		mux.HandleFunc("POST /auth/webauthn/login/begin", s.webAuthnHandler.LoginBegin)
		mux.HandleFunc("POST /auth/webauthn/login/finish", s.webAuthnHandler.LoginFinish)
	}

	// ── Session endpoints ─────────────────────────────────────────────────────
	mux.HandleFunc("POST /auth/refresh", s.handleRefresh)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.Handle("GET /auth/me", authMiddleware(http.HandlerFunc(s.handleMe)))
	mux.HandleFunc("GET /auth/providers", s.handleProviders)

	// ── Legal gate ────────────────────────────────────────────────────────────
	if s.legalHandler != nil {
		mux.HandleFunc("GET /auth/agree", s.legalHandler.ShowAgreement)
		mux.HandleFunc("POST /auth/agree", s.legalHandler.RecordAgreement)
	}

	// ── Management API ────────────────────────────────────────────────────────
	mgmt := http.NewServeMux()
	mgmt.HandleFunc("GET /manage/users", s.mgmtHandler.ListUsers)
	mgmt.HandleFunc("POST /manage/users/invite", s.mgmtHandler.InviteUser)
	mgmt.HandleFunc("POST /manage/users/import", s.mgmtHandler.BulkImport)
	mgmt.HandleFunc("DELETE /manage/users/{id}", s.mgmtHandler.DeleteUser)
	mgmt.HandleFunc("POST /manage/users/{id}/roles", s.mgmtHandler.AssignRole)
	mgmt.HandleFunc("DELETE /manage/users/{id}/roles/{role_id}", s.mgmtHandler.RevokeRole)
	mgmt.HandleFunc("GET /manage/roles", s.mgmtHandler.ListRoles)
	mgmt.HandleFunc("POST /manage/roles", s.mgmtHandler.CreateRole)
	mgmt.HandleFunc("GET /manage/users/{id}/agreements", s.mgmtHandler.ListAgreements)

	// ── Org routes ────────────────────────────────────────────────────────────
	mgmt.HandleFunc("POST /manage/orgs", s.mgmtHandler.CreateOrg)
	mgmt.HandleFunc("GET /manage/orgs", s.mgmtHandler.ListOrgs)
	mgmt.HandleFunc("POST /manage/orgs/{org_id}/members", s.mgmtHandler.AddOrgMember)
	mgmt.HandleFunc("DELETE /manage/orgs/{org_id}/members/{uid}", s.mgmtHandler.RemoveOrgMember)

	// ── Webhook CRUD ──────────────────────────────────────────────────────────
	mgmt.HandleFunc("GET /manage/webhooks", s.mgmtHandler.ListWebhooks)
	mgmt.HandleFunc("POST /manage/webhooks", s.mgmtHandler.CreateWebhook)
	mgmt.HandleFunc("DELETE /manage/webhooks/{id}", s.mgmtHandler.DeleteWebhook)

	mux.Handle("/manage/", apiKeyMiddleware(mgmt))
}
