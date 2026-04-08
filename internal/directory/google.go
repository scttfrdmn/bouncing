package directory

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"

	"github.com/scttfrdmn/bouncing/internal/config"
)

// GoogleProvider fetches users from Google Workspace using the Admin SDK.
// It requires a service account with domain-wide delegation and the
// https://www.googleapis.com/auth/admin.directory.user.readonly scope.
type GoogleProvider struct {
	domain string
	svc    *admin.Service
}

// NewGoogleProvider creates a GoogleProvider from the given DirectoryConfig.
// The service account key file (JSON) is read from cfg.ServiceAccount, and
// cfg.AdminEmail is impersonated for domain-wide delegation.
func NewGoogleProvider(ctx context.Context, cfg *config.DirectoryConfig) (*GoogleProvider, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("directory.NewGoogleProvider: domain is required")
	}
	if cfg.ServiceAccount == "" {
		return nil, fmt.Errorf("directory.NewGoogleProvider: service_account path is required")
	}
	if cfg.AdminEmail == "" {
		return nil, fmt.Errorf("directory.NewGoogleProvider: admin_email is required for domain-wide delegation")
	}

	keyData, err := os.ReadFile(cfg.ServiceAccount)
	if err != nil {
		return nil, fmt.Errorf("directory.NewGoogleProvider: read service account: %w", err)
	}

	jwtCfg, err := google.JWTConfigFromJSON(keyData,
		admin.AdminDirectoryUserReadonlyScope,
	)
	if err != nil {
		return nil, fmt.Errorf("directory.NewGoogleProvider: parse service account: %w", err)
	}
	jwtCfg.Subject = cfg.AdminEmail // domain-wide delegation

	// Build the JWT token source without the impersonation flag in the config
	// so the Subject field above handles impersonation.
	tokenSource := (&jwt.Config{
		Email:      jwtCfg.Email,
		PrivateKey: jwtCfg.PrivateKey,
		Subject:    jwtCfg.Subject,
		Scopes:     jwtCfg.Scopes,
		TokenURL:   jwtCfg.TokenURL,
	}).TokenSource(ctx)

	svc, err := admin.NewService(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return nil, fmt.Errorf("directory.NewGoogleProvider: create admin service: %w", err)
	}

	return &GoogleProvider{domain: cfg.Domain, svc: svc}, nil
}

// ListUsers returns all non-deleted users in the Google Workspace domain.
func (g *GoogleProvider) ListUsers(ctx context.Context) ([]*DirectoryUser, error) {
	var users []*DirectoryUser

	err := g.svc.Users.List().
		Context(ctx).
		Domain(g.domain).
		Projection("full").
		OrderBy("email").
		Pages(ctx, func(resp *admin.Users) error {
			for _, u := range resp.Users {
				du := &DirectoryUser{
					Email:     u.PrimaryEmail,
					Suspended: u.Suspended,
				}
				if u.Name != nil {
					du.Name = u.Name.FullName
				}
				if u.ThumbnailPhotoUrl != "" {
					du.AvatarURL = u.ThumbnailPhotoUrl
				}
				users = append(users, du)
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("directory.GoogleProvider.ListUsers: %w", err)
	}

	return users, nil
}
