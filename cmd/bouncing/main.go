package main

import (
	"fmt"
	"os"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("bouncing %s (%s) built %s go%s\n", version, commit, date, goVersion())
		return
	}

	fmt.Fprintln(os.Stderr, "bouncing: not implemented yet")
	os.Exit(1)
}

func goVersion() string {
	return "1.26.1"
}
