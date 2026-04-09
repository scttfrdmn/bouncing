package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/scttfrdmn/bouncing/internal/config"
	"github.com/scttfrdmn/bouncing/internal/directory"
	"github.com/scttfrdmn/bouncing/internal/store"
)

func runDirectory(args []string) error {
	if len(args) == 0 {
		printDirectoryUsage()
		return nil
	}

	switch args[0] {
	case "sync":
		return runDirectorySync(args[1:])
	case "help", "--help", "-h":
		printDirectoryUsage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "bouncing directory: unknown command %q\n\n", args[0])
		printDirectoryUsage()
		return fmt.Errorf("unknown directory command %q", args[0])
	}
}

func runDirectorySync(args []string) error {
	cfgPath := "bouncing.yaml"
	if len(args) > 0 {
		cfgPath = args[0]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	if cfg.Directory == nil {
		return fmt.Errorf("directory sync is not configured (add a 'directory:' block to bouncing.yaml)")
	}

	dc := cfg.Directory
	if dc.Provider != "google" {
		return fmt.Errorf("unsupported directory provider %q (only 'google' is supported)", dc.Provider)
	}

	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	st, err := store.NewSQLite(cfg.Store.Path)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer func() { _ = st.Close() }()

	if err := st.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	provider, err := directory.NewGoogleProvider(ctx, dc)
	if err != nil {
		return fmt.Errorf("init google provider: %w", err)
	}

	syncer := directory.New(provider, st, nil, cfg.Access.Mode, log)

	result, err := syncer.Run(ctx)
	if err != nil {
		return fmt.Errorf("sync: %w", err)
	}

	fmt.Printf("sync complete — created: %d, updated: %d, skipped: %d\n",
		result.Created, result.Updated, result.Skipped)
	return nil
}

func printDirectoryUsage() {
	fmt.Println(`bouncing directory — directory sync commands

Usage:
  bouncing directory sync [config.yaml]   Sync users from configured directory provider`)
}
