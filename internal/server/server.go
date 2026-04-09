package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	gowa "github.com/go-webauthn/webauthn/webauthn"

	"github.com/scttfrdmn/bouncing/internal/authn/oauth"
	authnwebauthn "github.com/scttfrdmn/bouncing/internal/authn/webauthn"
	"github.com/scttfrdmn/bouncing/internal/authz"
	"github.com/scttfrdmn/bouncing/internal/config"
	"github.com/scttfrdmn/bouncing/internal/hooks"
	"github.com/scttfrdmn/bouncing/internal/i18n"
	"github.com/scttfrdmn/bouncing/internal/legal"
	"github.com/scttfrdmn/bouncing/internal/mgmt"
	"github.com/scttfrdmn/bouncing/internal/session"
	"github.com/scttfrdmn/bouncing/internal/store"
)

// oauthHandlerIface is the subset of oauth.Handler used by routes.
type oauthHandlerIface interface {
	ProviderName() string
	BeginOAuth(w http.ResponseWriter, r *http.Request)
	CallbackOAuth(w http.ResponseWriter, r *http.Request)
}

// Server holds all wired-up application dependencies.
type Server struct {
	cfg             *config.Config
	store           store.Store
	log             *slog.Logger
	issuer          *session.Issuer
	refreshMgr      *session.RefreshManager
	jwksHandler     http.Handler
	oauthHandlers   []oauthHandlerIface
	webAuthnHandler *authnwebauthn.Handler
	legalHandler    *legal.Handler
	mgmtHandler     *mgmt.Handler
	apiKey          *mgmt.APIKey
	hooks           *hooks.Dispatcher
	i18n            *i18n.Localizer
	rateLimiter     *RateLimiter
	stop            chan struct{} // closed on shutdown
}

// New constructs a fully wired Server. It bootstraps the API key if
// BOUNCING_API_KEY is not set in the environment.
func New(cfg *config.Config, st store.Store, log *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, store: st, log: log, stop: make(chan struct{})}

	// ── Keys + JWT issuer ─────────────────────────────────────────────────────
	ring, err := session.LoadAll(cfg.Signing.KeysDir)
	if err != nil {
		return nil, fmt.Errorf("server.New: keys: %w", err)
	}
	s.issuer = session.NewIssuer(ring, cfg.Session.AccessTokenTTL, cfg.BaseURL)
	s.refreshMgr = session.NewRefreshManager(st, cfg.Session.RefreshTokenTTL)

	jwksH, err := session.NewJWKSHandler(ring)
	if err != nil {
		return nil, fmt.Errorf("server.New: jwks: %w", err)
	}
	s.jwksHandler = jwksH

	// ── Access policy ─────────────────────────────────────────────────────────
	policy := authz.NewPolicy(cfg.Access.Mode, cfg.Access.AllowedDomains)
	engine := &authz.Engine{}

	// ── API key ───────────────────────────────────────────────────────────────
	rawAPIKey := os.Getenv("BOUNCING_API_KEY")
	if rawAPIKey == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("server.New: generate api key: %w", err)
		}
		rawAPIKey = "bnc_api_" + base64.RawURLEncoding.EncodeToString(b)
		log.Warn("BOUNCING_API_KEY not set — generated ephemeral key; save it now",
			"api_key", rawAPIKey)
	}
	s.apiKey = mgmt.NewAPIKey(rawAPIKey)

	// ── Hooks dispatcher ──────────────────────────────────────────────────────
	s.hooks = hooks.NewDispatcher(cfg.Webhooks, log)
	s.hooks.WithStore(st)

	// ── i18n ──────────────────────────────────────────────────────────────────
	loc, err := i18n.New(cfg.I18n.DefaultLocale)
	if err != nil {
		return nil, fmt.Errorf("server.New: i18n: %w", err)
	}
	s.i18n = loc

	// ── Legal gate (optional) ─────────────────────────────────────────────────
	var legalGate oauth.LegalGate
	if cfg.Legal != nil && cfg.Legal.Enabled {
		g := legal.NewGate(st, cfg.Legal, log)
		legalGateImpl := g
		legalGate = legalGateImpl
		s.legalHandler = legal.NewHandler(g, s.issuer, s.refreshMgr, st, engine, s.hooks, s.i18n, log)
	}

	// ── OAuth providers ───────────────────────────────────────────────────────
	for name, provCfg := range cfg.Auth.Methods.OAuth {
		redirectURL := strings.TrimRight(cfg.BaseURL, "/") + "/auth/oauth/" + name + "/callback"
		prov, err := oauth.NewProvider(name, provCfg.ClientID, provCfg.ClientSecret, redirectURL)
		if err != nil {
			return nil, fmt.Errorf("server.New: oauth provider %q: %w", name, err)
		}

		// HMAC secret for state: derive from API key hash
		stateMgr := oauth.NewStateManager([]byte(rawAPIKey))

		errorURL := cfg.Auth.ErrorURL
		if errorURL == "" {
			errorURL = "/"
		}

		h := oauth.NewHandler(oauth.Config{
			Provider:    prov,
			StateMgr:    stateMgr,
			Store:       st,
			Policy:      policy,
			Engine:      engine,
			Issuer:      s.issuer,
			RefreshMgr:  s.refreshMgr,
			Hooks:       s.hooks,
			LegalGate:   legalGate,
			RedirectURL: cfg.Auth.RedirectURL,
			ErrorURL:    errorURL,
			Log:         log,
		})
		s.oauthHandlers = append(s.oauthHandlers, &namedOAuthHandler{name: name, Handler: h})
	}

	// ── WebAuthn ──────────────────────────────────────────────────────────────
	if cfg.Auth.Methods.Passkeys.Enabled {
		waCfg := &gowa.Config{
			RPDisplayName: cfg.Auth.Methods.Passkeys.RPName,
			RPID:          cfg.Auth.Methods.Passkeys.RPID,
			RPOrigins:     cfg.Auth.Methods.Passkeys.Origins,
		}
		wa, err := gowa.New(waCfg)
		if err != nil {
			return nil, fmt.Errorf("server.New: webauthn: %w", err)
		}
		sessions := authnwebauthn.NewSessionStore(s.stop)
		s.webAuthnHandler = authnwebauthn.NewHandler(authnwebauthn.Config{
			WebAuthn:   wa,
			Sessions:   sessions,
			Store:      st,
			Engine:     engine,
			Issuer:     s.issuer,
			RefreshMgr: s.refreshMgr,
			Hooks:      s.hooks,
			Log:        log,
		})
	}

	// ── Rate limiter ──────────────────────────────────────────────────────────
	s.rateLimiter = NewRateLimiter(cfg.RateLimit.Rate, cfg.RateLimit.Burst, s.stop)

	// ── Management handler ────────────────────────────────────────────────────
	s.mgmtHandler = mgmt.NewHandler(mgmt.Config{
		Store:  st,
		Engine: engine,
		Hooks:  s.hooks,
		Log:    log,
	})

	return s, nil
}

// Start runs the HTTP server until the process receives SIGTERM or SIGINT.
// It performs a 5-second graceful shutdown.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	corsOrigins := s.cfg.Auth.CORSOrigins
	handler := RequestID(Logger(s.log)(CORS(corsOrigins)(mux)))

	srv := &http.Server{
		Addr:         s.cfg.Listen,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		s.log.Info("bouncing listening", "addr", s.cfg.Listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-sigCtx.Done():
		s.log.Info("shutting down")
		close(s.stop) // signal background goroutines

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// HTTPHandler returns the server's mux wrapped in middleware, for use in tests.
func (s *Server) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	s.registerRoutes(mux)
	return RequestID(CORS(nil)(mux))
}

// namedOAuthHandler wraps oauth.Handler to expose the provider name for routing.
type namedOAuthHandler struct {
	name string
	*oauth.Handler
}

func (h *namedOAuthHandler) ProviderName() string { return h.name }
