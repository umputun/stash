package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	log "github.com/go-pkgz/lgr"
	"github.com/jessevdk/go-flags"

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/server"
	"github.com/umputun/stash/app/store"
	"github.com/umputun/stash/app/validator"
)

var opts struct {
	DB string `short:"d" long:"db" env:"STASH_DB" default:"stash.db" description:"database URL (sqlite file or postgres://...)"`

	Git struct {
		Enabled bool   `long:"enabled" env:"ENABLED" description:"enable git tracking"`
		Path    string `long:"path" env:"PATH" default:".history" description:"git repository path"`
		Branch  string `long:"branch" env:"BRANCH" default:"master" description:"git branch"`
		Remote  string `long:"remote" env:"REMOTE" description:"git remote name (optional)"`
		Push    bool   `long:"push" env:"PUSH" description:"auto-push after commits"`
		SSHKey  string `long:"ssh-key" env:"SSH_KEY" description:"SSH private key path for git push"`
	} `group:"git" namespace:"git" env-namespace:"STASH_GIT"`

	Server struct {
		Address         string        `long:"address" env:"ADDRESS" default:":8080" description:"server listen address"`
		ReadTimeout     time.Duration `long:"read-timeout" env:"READ_TIMEOUT" default:"5s" description:"read timeout"`
		WriteTimeout    time.Duration `long:"write-timeout" env:"WRITE_TIMEOUT" default:"30s" description:"write timeout"`
		IdleTimeout     time.Duration `long:"idle-timeout" env:"IDLE_TIMEOUT" default:"30s" description:"idle timeout"`
		ShutdownTimeout time.Duration `long:"shutdown-timeout" env:"SHUTDOWN_TIMEOUT" default:"5s" description:"graceful shutdown timeout"`
		BaseURL         string        `long:"base-url" env:"BASE_URL" description:"base URL path for reverse proxy (e.g., /stash)"`
		PageSize        int           `long:"page-size" env:"PAGE_SIZE" default:"50" description:"keys per page in web UI, 0 to disable"`
	} `group:"server" namespace:"server" env-namespace:"STASH_SERVER"`

	Limits struct {
		BodySize         int64 `long:"body-size" env:"BODY_SIZE" default:"1048576" description:"max body size in bytes"`
		RequestsPerSec   int64 `long:"requests-per-sec" env:"REQUESTS_PER_SEC" default:"1000" description:"max requests per second"`
		LoginConcurrency int64 `long:"login-concurrency" env:"LOGIN_CONCURRENCY" default:"5" description:"max concurrent login attempts"`
	} `group:"limits" namespace:"limits" env-namespace:"STASH_LIMITS"`

	Cache struct {
		Enabled bool `long:"enabled" env:"ENABLED" description:"enable in-memory cache for reads"`
		MaxKeys int  `long:"max-keys" env:"MAX_KEYS" default:"1000" description:"maximum number of cached keys"`
	} `group:"cache" namespace:"cache" env-namespace:"STASH_CACHE"`

	Auth struct {
		File     string        `long:"file" env:"FILE" description:"path to auth config file (stash-auth.yml)"`
		LoginTTL time.Duration `long:"login-ttl" env:"LOGIN_TTL" default:"24h" description:"login session TTL"`
	} `group:"auth" namespace:"auth" env-namespace:"STASH_AUTH"`

	ServerCmd struct {
	} `command:"server" description:"run the stash server"`

	RestoreCmd struct {
		Rev string `long:"rev" required:"true" description:"git revision to restore (commit/tag/branch)"`
	} `command:"restore" description:"restore database from a git revision"`

	Debug   bool `long:"dbg" env:"DEBUG" description:"debug mode"`
	Version bool `long:"version" description:"show version and exit"`
}

var revision = "unknown"

func main() {
	fmt.Printf("stash %s\n", revision)

	p := flags.NewParser(&opts, flags.Default)

	if _, err := p.Parse(); err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if opts.Version {
		os.Exit(0)
	}

	setupLogs(opts.Debug)

	defer func() {
		if x := recover(); x != nil {
			log.Printf("[WARN] run time panic:\n%v", x)
			panic(x)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	signals(cancel)

	var err error
	switch {
	case p.Active != nil && p.Find("server") == p.Active:
		err = runServer(ctx)
	case p.Active != nil && p.Find("restore") == p.Active:
		err = runRestore()
	default:
		p.WriteHelp(os.Stderr)
		os.Exit(2)
	}

	if err != nil {
		log.Printf("[ERROR] %v", err)
		os.Exit(1)
	}
}

func runServer(ctx context.Context) error {
	baseURL, err := validateBaseURL(opts.Server.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}

	log.Printf("[INFO] starting stash server on %s", opts.Server.Address)
	if baseURL != "" {
		log.Printf("[INFO] base URL: %s", baseURL)
	}
	if opts.Auth.File != "" {
		log.Printf("[INFO] authentication enabled from %s", opts.Auth.File)
	}
	if opts.Git.Enabled {
		log.Printf("[INFO] git tracking enabled, path: %s, branch: %s", opts.Git.Path, opts.Git.Branch)
	}
	if opts.Cache.Enabled {
		log.Printf("[INFO] cache enabled, max keys: %d", opts.Cache.MaxKeys)
	}

	// initialize storage
	var kvStore store.Interface
	kvStore, err = store.New(opts.DB)
	if err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}

	// wrap with cache if enabled
	if opts.Cache.Enabled {
		kvStore, err = store.NewCached(kvStore, opts.Cache.MaxKeys)
		if err != nil {
			return fmt.Errorf("failed to initialize cache: %w", err)
		}
	}
	defer kvStore.Close()

	// initialize and start HTTP server
	srv, err := server.New(kvStore, validator.NewService(), server.Config{
		Address:          opts.Server.Address,
		ReadTimeout:      opts.Server.ReadTimeout,
		WriteTimeout:     opts.Server.WriteTimeout,
		IdleTimeout:      opts.Server.IdleTimeout,
		ShutdownTimeout:  opts.Server.ShutdownTimeout,
		Version:          revision,
		AuthFile:         opts.Auth.File,
		LoginTTL:         opts.Auth.LoginTTL,
		BaseURL:          baseURL,
		GitPush:          opts.Git.Push,
		BodySizeLimit:    opts.Limits.BodySize,
		RequestsPerSec:   opts.Limits.RequestsPerSec,
		LoginConcurrency: opts.Limits.LoginConcurrency,
		PageSize:         opts.Server.PageSize,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize server: %w", err)
	}

	// initialize git store if enabled
	if opts.Git.Enabled {
		gitStore, gitErr := git.New(git.Config{
			Path:   opts.Git.Path,
			Branch: opts.Git.Branch,
			Remote: opts.Git.Remote,
			SSHKey: opts.Git.SSHKey,
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

func runRestore() error {
	log.Printf("[INFO] restoring from revision %s", opts.RestoreCmd.Rev)
	log.Printf("[INFO] git path: %s, db: %s", opts.Git.Path, opts.DB)

	// initialize git store
	gitStore, err := git.New(git.Config{
		Path:   opts.Git.Path,
		Branch: opts.Git.Branch,
		Remote: opts.Git.Remote,
		SSHKey: opts.Git.SSHKey,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize git store: %w", err)
	}

	// pull from remote if configured
	if opts.Git.Remote != "" {
		log.Printf("[INFO] pulling from remote %s", opts.Git.Remote)
		if pullErr := gitStore.Pull(); pullErr != nil {
			log.Printf("[WARN] pull failed: %v", pullErr)
		}
	}

	// checkout specified revision
	log.Printf("[INFO] checking out revision %s", opts.RestoreCmd.Rev)
	if chkErr := gitStore.Checkout(opts.RestoreCmd.Rev); chkErr != nil {
		return fmt.Errorf("failed to checkout revision %s: %w", opts.RestoreCmd.Rev, chkErr)
	}

	// read all key-value pairs from git
	kvPairs, readErr := gitStore.ReadAll()
	if readErr != nil {
		return fmt.Errorf("failed to read keys from git: %w", readErr)
	}

	// initialize database store
	kvStore, dbErr := store.New(opts.DB)
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

	// insert all key-value pairs from git with their formats
	var restored int
	for key, kv := range kvPairs {
		if setErr := kvStore.Set(key, kv.Value, kv.Format); setErr != nil {
			log.Printf("[WARN] failed to restore key %s: %v", key, setErr)
			continue
		}
		restored++
	}

	log.Printf("[INFO] restored %d keys from revision %s", restored, opts.RestoreCmd.Rev)
	fmt.Printf("restored %d keys from revision %s\n", restored, opts.RestoreCmd.Rev)
	return nil
}

// validateBaseURL validates and normalizes the base URL.
// Returns empty string for empty input, ensures it starts with / and has no trailing /.
func validateBaseURL(baseURL string) (string, error) {
	if baseURL == "" {
		return "", nil
	}
	if !strings.HasPrefix(baseURL, "/") {
		return "", fmt.Errorf("base URL must start with /")
	}
	return strings.TrimSuffix(baseURL, "/"), nil
}

func setupLogs(debug bool) {
	log.Setup(log.Msec)
	if debug {
		log.Setup(log.Debug, log.CallerFunc, log.CallerPkg, log.CallerFile)
	}
}

func signals(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	go func() {
		stacktrace := make([]byte, 8192)
		for sig := range sigChan {
			switch sig {
			case syscall.SIGQUIT:
				length := runtime.Stack(stacktrace, true)
				fmt.Println(string(stacktrace[:length]))
			case syscall.SIGTERM, syscall.SIGINT:
				cancel()
			}
		}
	}()
	signal.Notify(sigChan, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
}
