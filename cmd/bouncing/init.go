package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func runInit(_ []string) error {
	if _, err := os.Stat("bouncing.yaml"); err == nil {
		fmt.Print("bouncing.yaml already exists. Overwrite? [y/N]: ")
		var yn string
		_, _ = fmt.Scanln(&yn)
		if strings.ToLower(yn) != "y" {
			fmt.Println("aborted")
			return nil
		}
	}

	sc := bufio.NewScanner(os.Stdin)

	listen := prompt(sc, "Listen address", ":8080")
	baseURL := prompt(sc, "Base URL", "http://localhost:8080")
	dbPath := prompt(sc, "SQLite database path", "bouncing.db")
	keysDir := prompt(sc, "Signing keys directory", ".keys")
	accessMode := promptChoice(sc, "Access mode", []string{"open", "domain-restricted", "invite-only"}, "open")

	var allowedDomains string
	if accessMode == "domain-restricted" {
		allowedDomains = prompt(sc, "Allowed domains (comma-separated, e.g. @mycompany.com)", "")
	}

	redirectURL := prompt(sc, "Redirect URL after login", "/")
	logoutURL := prompt(sc, "Logout redirect URL", "/")

	yml := fmt.Sprintf(`listen: %q
base_url: %q

store:
  driver: sqlite
  path: %q

signing:
  algorithm: ed25519
  keys_dir: %q

access:
  mode: %s
`, listen, baseURL, dbPath, keysDir, accessMode)

	if accessMode == "domain-restricted" && allowedDomains != "" {
		yml += "  allowed_domains:\n"
		for _, d := range strings.Split(allowedDomains, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				yml += fmt.Sprintf("    - %q\n", d)
			}
		}
	}

	yml += fmt.Sprintf(`
auth:
  redirect_url: %q
  logout_url: %q
  methods:
    oauth: {}
    passkeys:
      enabled: false

session:
  access_token_ttl: 15m
  refresh_token_ttl: 168h

i18n:
  default_locale: en
`, redirectURL, logoutURL)

	if err := os.WriteFile("bouncing.yaml", []byte(yml), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	fmt.Println("✓ bouncing.yaml created")
	fmt.Println("  Set BOUNCING_API_KEY before starting the server.")
	fmt.Printf("  Run: bouncing serve\n")
	return nil
}

func prompt(sc *bufio.Scanner, label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	sc.Scan()
	v := strings.TrimSpace(sc.Text())
	if v == "" {
		return def
	}
	return v
}

func promptChoice(sc *bufio.Scanner, label string, choices []string, def string) string {
	fmt.Printf("%s (%s) [%s]: ", label, strings.Join(choices, "/"), def)
	sc.Scan()
	v := strings.TrimSpace(sc.Text())
	if v == "" {
		return def
	}
	for _, c := range choices {
		if strings.EqualFold(v, c) {
			return c
		}
	}
	fmt.Printf("invalid choice %q; using %q\n", v, def)
	return def
}
