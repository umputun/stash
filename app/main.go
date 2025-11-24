package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	log "github.com/go-pkgz/lgr"
	"github.com/jessevdk/go-flags"

	"github.com/umputun/stash/app/server"
	"github.com/umputun/stash/app/store"
)

var opts struct {
	DB string `short:"d" long:"db" env:"STASH_DB" default:"stash.db" description:"database URL (sqlite file or postgres://...)"`

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

	Debug   bool `long:"dbg" env:"DEBUG" description:"debug mode"`
	Version bool `long:"version" description:"show version and exit"`
}

var revision = "unknown"

func main() {
	fmt.Printf("stash %s\n", revision)

	p := flags.NewParser(&opts, flags.PassDoubleDash|flags.HelpFlag)
	if _, err := p.Parse(); err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && flagsErr.Type == flags.ErrHelp {
			p.WriteHelp(os.Stderr)
			os.Exit(2)
		}
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	if opts.Version {
		os.Exit(0)
	}

	setupLogs()

	defer func() {
		if x := recover(); x != nil {
			log.Printf("[WARN] run time panic:\n%v", x)
			panic(x)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	signals(cancel)

	if err := run(ctx); err != nil {
		log.Printf("[ERROR] failed: %v", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	baseURL, err := validateBaseURL(opts.Server.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid base URL: %w", err)
	}

	log.Printf("[INFO] starting stash server on %s", opts.Server.Address)
	if baseURL != "" {
		log.Printf("[INFO] base URL: %s", baseURL)
	}
	if opts.Auth.PasswordHash != "" {
		log.Printf("[INFO] authentication enabled with %d API token(s)", len(opts.Auth.Tokens))
	}

	// initialize storage
	kvStore, err := store.New(opts.DB)
	if err != nil {
		return fmt.Errorf("failed to initialize store: %w", err)
	}
	defer kvStore.Close()

	// initialize and start HTTP server
	srv, err := server.New(kvStore, server.Config{
		Address:      opts.Server.Address,
		ReadTimeout:  opts.Server.ReadTimeout,
		Version:      revision,
		PasswordHash: opts.Auth.PasswordHash,
		AuthTokens:   opts.Auth.Tokens,
		LoginTTL:     opts.Auth.LoginTTL,
		BaseURL:      baseURL,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize server: %w", err)
	}

	if err := srv.Run(ctx); err != nil {
		return fmt.Errorf("server failed: %w", err)
	}
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

func setupLogs() io.Writer {
	log.Setup(log.Msec)
	if opts.Debug {
		log.Setup(log.Debug, log.CallerFunc, log.CallerPkg, log.CallerFile)
	}
	return os.Stdout
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
