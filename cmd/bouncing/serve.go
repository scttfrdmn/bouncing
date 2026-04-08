package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/scttfrdmn/bouncing/internal/config"
	"github.com/scttfrdmn/bouncing/internal/server"
	"github.com/scttfrdmn/bouncing/internal/store"
)

func runServe(args []string) error {
	cfgPath := "bouncing.yaml"
	if len(args) > 0 {
		cfgPath = args[0]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logLevel := slog.LevelInfo
	if os.Getenv("BOUNCING_DEBUG") != "" {
		logLevel = slog.LevelDebug
	}
	logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	log := slog.New(logHandler)

	if cfg.Store.Driver != "" && cfg.Store.Driver != "sqlite" {
		return fmt.Errorf("store driver %q is not supported in this build (open-core supports sqlite only)", cfg.Store.Driver)
	}
	st, err := store.NewSQLite(cfg.Store.Path)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	if err := st.Migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	srv, err := server.New(cfg, st, log)
	if err != nil {
		return fmt.Errorf("init server: %w", err)
	}

	return srv.Start(context.Background())
}
