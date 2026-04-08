package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/scttfrdmn/bouncing/internal/config"
	"github.com/scttfrdmn/bouncing/internal/store"
)

func runUsers(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: bouncing users <add|remove|list|import> [flags]")
	}

	cfg, err := config.Load("bouncing.yaml")
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	st, err := store.NewSQLite(cfg.Store.Path)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	if err := st.Migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	subargs := args[1:]
	switch args[0] {
	case "add":
		return usersAdd(st, subargs)
	case "remove":
		return usersRemove(st, subargs)
	case "list":
		return usersList(st, subargs)
	case "import":
		return usersImport(st, subargs)
	default:
		return fmt.Errorf("unknown users subcommand: %q", args[0])
	}
}

func usersAdd(st store.Store, args []string) error {
	fs := flag.NewFlagSet("users add", flag.ContinueOnError)
	role := fs.String("role", "", "role name to assign")
	name := fs.String("name", "", "display name")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: bouncing users add <email> [--role <role>] [--name <name>]")
	}
	email := fs.Arg(0)

	u := &store.User{Email: email, Name: *name, Status: "active"}
	if err := st.CreateUser(context.Background(), u); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	if *role != "" {
		r, err := st.GetRoleByName(context.Background(), *role)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: role %q not found: %v\n", *role, err)
		} else {
			_ = st.AssignRole(context.Background(), u.ID, r.ID, nil)
		}
	}

	fmt.Printf("created: %s (%s)\n", u.ID, email)
	return nil
}

func usersRemove(st store.Store, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: bouncing users remove <user-id>")
	}
	id := args[0]

	ctx := context.Background()
	_ = st.DeleteUserRefreshTokens(ctx, id)
	if err := st.DeleteUser(ctx, id); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	fmt.Printf("deleted: %s\n", id)
	return nil
}

func usersList(st store.Store, args []string) error {
	fs := flag.NewFlagSet("users list", flag.ContinueOnError)
	status := fs.String("status", "", "filter by status (pending|active)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	users, err := st.ListUsers(context.Background(), store.ListOpts{
		PerPage: 100,
		Status:  *status,
	})
	if err != nil {
		return fmt.Errorf("list users: %w", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tEMAIL\tNAME\tSTATUS")
	for _, u := range users {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", u.ID, u.Email, u.Name, u.Status)
	}
	return w.Flush()
}

func usersImport(st store.Store, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: bouncing users import <file.csv>")
	}

	f, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return fmt.Errorf("read csv: %w", err)
	}

	created, skipped := 0, 0
	for i, row := range records {
		if i == 0 {
			// Skip header row if it looks like a header.
			if strings.ToLower(row[0]) == "email" {
				continue
			}
		}
		if len(row) < 1 {
			continue
		}
		email := strings.TrimSpace(row[0])
		roleName := ""
		if len(row) >= 2 {
			roleName = strings.TrimSpace(row[1])
		}

		u := &store.User{Email: email, Status: "pending"}
		err := st.CreateUser(context.Background(), u)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint") {
				skipped++
				continue
			}
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", email, err)
			continue
		}

		if roleName != "" {
			if role, err := st.GetRoleByName(context.Background(), roleName); err == nil {
				_ = st.AssignRole(context.Background(), u.ID, role.ID, nil)
			}
		}
		created++
	}

	fmt.Printf("imported: created=%d skipped=%d\n", created, skipped)
	return nil
}
