package main

import (
	"fmt"
	"os"

	"github.com/scttfrdmn/bouncing/internal/config"
	"github.com/scttfrdmn/bouncing/internal/session"
)

func runKeys(args []string) error {
	if len(args) == 0 {
		printKeysUsage()
		return nil
	}

	switch args[0] {
	case "rotate":
		return runKeysRotate(args[1:])
	case "list":
		return runKeysList(args[1:])
	case "help", "--help", "-h":
		printKeysUsage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "bouncing keys: unknown command %q\n\n", args[0])
		printKeysUsage()
		return fmt.Errorf("unknown keys command %q", args[0])
	}
}

func runKeysRotate(args []string) error {
	cfgPath := "bouncing.yaml"
	if len(args) > 0 {
		cfgPath = args[0]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ring, err := session.Rotate(cfg.Signing.KeysDir)
	if err != nil {
		return fmt.Errorf("rotate: %w", err)
	}

	fmt.Printf("new signing key: %s\n", ring.Current.KID)
	fmt.Printf("total keys in ring: %d\n", len(ring.Keys))
	fmt.Println("restart the server to use the new key")
	return nil
}

func runKeysList(args []string) error {
	cfgPath := "bouncing.yaml"
	if len(args) > 0 {
		cfgPath = args[0]
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ring, err := session.LoadAll(cfg.Signing.KeysDir)
	if err != nil {
		return fmt.Errorf("load keys: %w", err)
	}

	for i, ks := range ring.Keys {
		marker := "  "
		if i == 0 {
			marker = "* "
		}
		fmt.Printf("%s%s\n", marker, ks.KID)
	}
	return nil
}

func printKeysUsage() {
	fmt.Println(`bouncing keys — signing key management

Usage:
  bouncing keys rotate [config.yaml]   Generate a new signing keypair
  bouncing keys list [config.yaml]     List all signing keys (* = current)`)
}
