package main

import (
	"context"
	"fmt"
	"time"

	log "github.com/go-pkgz/lgr"

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/server"
	"github.com/umputun/stash/app/store"
)

// SharedOptions contains options shared between all commands
type SharedOptions struct {
	DB string `short:"d" long:"db" env:"STASH_DB" default:"stash.db" description:"database URL (sqlite file or postgres://...)"`

	Git struct {
		Path   string `long:"path" env:"PATH" default:".history" description:"git repository path"`
		Branch string `long:"branch" env:"BRANCH" default:"master" description:"git branch"`
		Remote string `long:"remote" env:"REMOTE" description:"git remote name (optional)"`
	} `group:"git" namespace:"git" env-namespace:"STASH_GIT"`

	Debug bool `long:"dbg" env:"DEBUG" description:"debug mode"`
}

// ServerCmd implements the server subcommand
type ServerCmd struct {
	DB string `short:"d" long:"db" env:"STASH_DB" default:"stash.db" description:"database URL (sqlite file or postgres://...)"`

	Git struct {
		Path    string `long:"path" env:"PATH" default:".history" description:"git repository path"`
		Branch  string `long:"branch" env:"BRANCH" default:"master" description:"git branch"`
		Remote  string `long:"remote" env:"REMOTE" description:"git remote name (optional)"`
		Enabled bool   `long:"enabled" env:"ENABLED" description:"enable git tracking"`
		Push    bool   `long:"push" env:"PUSH" description:"auto-push after commits"`
	} `group:"git" namespace:"git" env-namespace:"STASH_GIT"`

	Server struct {
		Address     string        `long:"address" env:"ADDRESS" default:":8080" description:"server listen address"`
		ReadTimeout time.Duration `long:"read-timeout" env:"READ_TIMEOUT" default:"5s" description:"read timeout"`
		BaseURL     string        `long:"base-url" env:"BASE_URL" description:"base URL path for reverse proxy (e.g., /stash)"`
	} `group:"server" namespace:"server" env-namespace:"STASH_SERVER"`

	Auth struct {
		PasswordHash string        `long:"password-hash" env:"PASSWORD_HASH" description:"bcrypt hash for admin password (enables auth)"`
		Tokens       []string      `long:"token" env:"AUTH_TOKEN" env-delim:"," description:"API token with prefix permissions (token:prefix:rw)"`
		LoginTTL     time.Duration `long:"login-ttl" env:"LOGIN_TTL" default:"24h" description:"login session TTL"`
	} `group:"auth" namespace:"auth" env-namespace:"STASH_AUTH"`

	Debug bool `long:"dbg" env:"DEBUG" description:"debug mode"`

	ctx    context.Context
	cancel context.CancelFunc
}

// Execute runs the server command
func (s *ServerCmd) Execute(_ []string) error {
	setupLogs(s.Debug)

	defer func() {
		if x := recover(); x != nil {
			log.Printf("[WARN] run time panic:\n%v", x)
			panic(x)
		}
	}()

	if s.ctx == nil {
		s.ctx, s.cancel = context.WithCancel(context.Background())
		signals(s.cancel)
	}

	return s.run(s.ctx)
}

func (s *ServerCmd) run(ctx context.Context) error {
	baseURL, err := validateBaseURL(s.Server.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}

	log.Printf("[INFO] starting stash server on %s", s.Server.Address)
	if baseURL != "" {
		log.Printf("[INFO] base URL: %s", baseURL)
	}
	if s.Auth.PasswordHash != "" {
		log.Printf("[INFO] authentication enabled with %d API token(s)", len(s.Auth.Tokens))
	}
	if s.Git.Enabled {
		log.Printf("[INFO] git tracking enabled, path: %s, branch: %s", s.Git.Path, s.Git.Branch)
	}

	// initialize storage
	kvStore, err := store.New(s.DB)
	if err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}
	defer kvStore.Close()

	// initialize and start HTTP server
	srv, err := server.New(kvStore, server.Config{
		Address:      s.Server.Address,
		ReadTimeout:  s.Server.ReadTimeout,
		Version:      revision,
		PasswordHash: s.Auth.PasswordHash,
		AuthTokens:   s.Auth.Tokens,
		LoginTTL:     s.Auth.LoginTTL,
		BaseURL:      baseURL,
		GitPush:      s.Git.Push,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize server: %w", err)
	}

	// initialize git store if enabled
	if s.Git.Enabled {
		gitStore, gitErr := git.New(git.Config{
			Path:   s.Git.Path,
			Branch: s.Git.Branch,
			Remote: s.Git.Remote,
		})
		if gitErr != nil {
			return fmt.Errorf("failed to initialize git store: %w", gitErr)
		}
		srv.SetGitStore(gitStore)
	}

	if err := srv.Run(ctx); err != nil {
		return fmt.Errorf("server failed: %w", err)
	}
	return nil
}

// RestoreCmd implements the restore subcommand
type RestoreCmd struct {
	SharedOptions

	Rev string `long:"rev" required:"true" description:"git revision to restore (commit/tag/branch)"`
}

// Execute runs the restore command
func (r *RestoreCmd) Execute(_ []string) error {
	setupLogs(r.Debug)
	log.Printf("[INFO] restoring from revision %s", r.Rev)
	log.Printf("[INFO] git path: %s, db: %s", r.Git.Path, r.DB)

	// initialize git store
	gitStore, err := git.New(git.Config{
		Path:   r.Git.Path,
		Branch: r.Git.Branch,
		Remote: r.Git.Remote,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize git store: %w", err)
	}

	// pull from remote if configured
	if r.Git.Remote != "" {
		log.Printf("[INFO] pulling from remote %s", r.Git.Remote)
		if pullErr := gitStore.Pull(); pullErr != nil {
			log.Printf("[WARN] pull failed: %v", pullErr)
		}
	}

	// checkout specified revision
	log.Printf("[INFO] checking out revision %s", r.Rev)
	if chkErr := gitStore.Checkout(r.Rev); chkErr != nil {
		return fmt.Errorf("failed to checkout revision %s: %w", r.Rev, chkErr)
	}

	// read all key-value pairs from git
	kvPairs, readErr := gitStore.ReadAll()
	if readErr != nil {
		return fmt.Errorf("failed to read keys from git: %w", readErr)
	}

	// initialize database store
	kvStore, dbErr := store.New(r.DB)
	if dbErr != nil {
		return fmt.Errorf("failed to initialize store: %w", dbErr)
	}
	defer kvStore.Close()

	// clear all keys from database
	existingKeys, listErr := kvStore.List()
	if listErr != nil {
		return fmt.Errorf("failed to list existing keys: %w", listErr)
	}
	for _, k := range existingKeys {
		if delErr := kvStore.Delete(k.Key); delErr != nil {
			log.Printf("[WARN] failed to delete key %s: %v", k.Key, delErr)
		}
	}
	log.Printf("[INFO] cleared %d existing keys", len(existingKeys))

	// insert all key-value pairs from git
	var restored int
	for key, value := range kvPairs {
		if setErr := kvStore.Set(key, value); setErr != nil {
			log.Printf("[WARN] failed to restore key %s: %v", key, setErr)
			continue
		}
		restored++
	}

	log.Printf("[INFO] restored %d keys from revision %s", restored, r.Rev)
	fmt.Printf("restored %d keys from revision %s\n", restored, r.Rev)
	return nil
}
