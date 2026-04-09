package main

import (
	"fmt"
	"os"
	"runtime"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = runServe(os.Args[2:])
	case "init":
		err = runInit(os.Args[2:])
	case "users":
		err = runUsers(os.Args[2:])
	case "directory":
		err = runDirectory(os.Args[2:])
	case "keys":
		err = runKeys(os.Args[2:])
	case "version":
		fmt.Printf("bouncing %s (%s) built %s go%s\n", version, commit, date, runtime.Version())
		return
	case "help", "--help", "-h":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "bouncing: unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`bouncing — open-source auth service

Usage:
  bouncing serve [config.yaml]   Start the auth server
  bouncing init                  Interactively create bouncing.yaml
  bouncing users add <email>     Add a user
  bouncing users remove <id>     Remove a user
  bouncing users list            List all users
  bouncing users import <file>   Bulk import from CSV
  bouncing directory sync        Sync users from directory provider
  bouncing keys rotate           Generate a new signing keypair
  bouncing keys list             List all signing keys
  bouncing version               Print version information`)
}
