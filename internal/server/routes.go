package server

import (
	"net/http"
)

// registerRoutes wires all application endpoints onto mux.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	authMiddleware := RequireAuth(s.issuer)
	apiKeyMiddleware := RequireAPIKey(s.apiKey.Validate)
	rl := s.rateLimiter.Middleware

	// ── JWKS (not rate-limited — cacheable public endpoint) ───────────────────
	mux.Handle("GET /.well-known/jwks.json", s.jwksHandler)

	// ── Auth routes (rate-limited) ────────────────────────────────────────────
	authMux := http.NewServeMux()

	// JWKS alias under /auth/
	authMux.Handle("GET /auth/jwks", s.jwksHandler)

	// OAuth
	for _, h := range s.oauthHandlers {
		provider := h.ProviderName()
		authMux.HandleFunc("GET /auth/oauth/"+provider, h.BeginOAuth)
		authMux.HandleFunc("GET /auth/oauth/"+provider+"/callback", h.CallbackOAuth)
	}

	// WebAuthn
	if s.webAuthnHandler != nil {
		authMux.HandleFunc("POST /auth/webauthn/register/begin", s.webAuthnHandler.RegisterBegin)
		authMux.HandleFunc("POST /auth/webauthn/register/finish", s.webAuthnHandler.RegisterFinish)
		authMux.HandleFunc("POST /auth/webauthn/login/begin", s.webAuthnHandler.LoginBegin)
		authMux.HandleFunc("POST /auth/webauthn/login/finish", s.webAuthnHandler.LoginFinish)
	}

	// Session
	authMux.HandleFunc("POST /auth/refresh", s.handleRefresh)
	authMux.HandleFunc("POST /auth/logout", s.handleLogout)
	authMux.Handle("GET /auth/me", authMiddleware(http.HandlerFunc(s.handleMe)))
	authMux.HandleFunc("GET /auth/providers", s.handleProviders)

	// Legal gate
	if s.legalHandler != nil {
		authMux.HandleFunc("GET /auth/agree", s.legalHandler.ShowAgreement)
		authMux.HandleFunc("POST /auth/agree", s.legalHandler.RecordAgreement)
	}

	mux.Handle("/auth/", rl(authMux))

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
	mgmt.HandleFunc("PUT /manage/roles/{id}", s.mgmtHandler.UpdateRole)
	mgmt.HandleFunc("DELETE /manage/roles/{id}", s.mgmtHandler.DeleteRoleByID)
	mgmt.HandleFunc("GET /manage/users/{id}/roles", s.mgmtHandler.ListUserRoles)
	mgmt.HandleFunc("GET /manage/users/{id}/agreements", s.mgmtHandler.ListAgreements)

	// ── Org routes ────────────────────────────────────────────────────────────
	mgmt.HandleFunc("POST /manage/orgs", s.mgmtHandler.CreateOrg)
	mgmt.HandleFunc("GET /manage/orgs", s.mgmtHandler.ListOrgs)
	mgmt.HandleFunc("POST /manage/orgs/{org_id}/members", s.mgmtHandler.AddOrgMember)
	mgmt.HandleFunc("DELETE /manage/orgs/{org_id}/members/{uid}", s.mgmtHandler.RemoveOrgMember)

	// ── Audit Log ─────────────────────────────────────────────────────────────
	mgmt.HandleFunc("GET /manage/audit", s.mgmtHandler.ListAuditEntries)

	// ── Webhook CRUD ──────────────────────────────────────────────────────────
	mgmt.HandleFunc("GET /manage/webhooks", s.mgmtHandler.ListWebhooks)
	mgmt.HandleFunc("POST /manage/webhooks", s.mgmtHandler.CreateWebhook)
	mgmt.HandleFunc("DELETE /manage/webhooks/{id}", s.mgmtHandler.DeleteWebhook)

	mux.Handle("/manage/", apiKeyMiddleware(mgmt))
}
