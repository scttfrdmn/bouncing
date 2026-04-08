// Package server exposes the public entry point for constructing a bouncing
// HTTP server.
//
// External consumers (e.g. bouncing-managed) inject any store.Store
// implementation — including custom backends like Turso — and receive a fully
// wired *Server ready to call Start on.
package server

import (
	"log/slog"

	iserver "github.com/scttfrdmn/bouncing/internal/server"
	"github.com/scttfrdmn/bouncing/pkg/config"
	"github.com/scttfrdmn/bouncing/pkg/store"
)

// Server is the bouncing HTTP server.
type Server = iserver.Server

// New constructs a Server from cfg and the given store implementation.
// Any backend that satisfies store.Store — SQLite, Turso, or otherwise — is
// accepted.
func New(cfg *config.Config, st store.Store, log *slog.Logger) (*Server, error) {
	return iserver.New(cfg, st, log)
}
