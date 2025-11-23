package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	log "github.com/go-pkgz/lgr"
	"github.com/umputun/go-flags"

	"github.com/umputun/stash/app/server"
	"github.com/umputun/stash/app/store"
)

var opts struct {
	DB string `short:"d" long:"db" env:"STASH_DB" default:"stash.db" description:"database URL (sqlite file or postgres://...)"`

	Server struct {
		Address     string `long:"address" env:"ADDRESS" default:":8484" description:"server listen address"`
		ReadTimeout int    `long:"read-timeout" env:"READ_TIMEOUT" default:"5" description:"read timeout in seconds"`
	} `group:"server" namespace:"server" env-namespace:"STASH_SERVER"`

	Auth struct {
		PasswordHash string   `long:"password-hash" env:"PASSWORD_HASH" description:"bcrypt hash for admin password (enables auth)"`
		Tokens       []string `long:"token" env:"AUTH_TOKEN" env-delim:"," description:"API token with prefix permissions (token:prefix:rw)"`
		LoginTTL     int      `long:"login-ttl" env:"LOGIN_TTL" default:"1440" description:"login session TTL in minutes"`
	} `group:"auth" namespace:"auth" env-namespace:"STASH_AUTH"`

	Discovery struct {
		TTLCheckInterval  int `long:"ttl-check-interval" env:"TTL_CHECK_INTERVAL" default:"5" description:"TTL expiration check interval in seconds"`
		HTTPCheckInterval int `long:"http-check-interval" env:"HTTP_CHECK_INTERVAL" default:"10" description:"HTTP health check interval in seconds"`
		HTTPCheckTimeout  int `long:"http-check-timeout" env:"HTTP_CHECK_TIMEOUT" default:"5" description:"HTTP health check timeout in seconds"`
	} `group:"discovery" namespace:"discovery" env-namespace:"STASH_DISCOVERY"`

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
	log.Printf("[INFO] starting stash server on %s", opts.Server.Address)
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
	srv, err := server.New(kvStore, kvStore, server.Config{
		Address:      opts.Server.Address,
		ReadTimeout:  time.Duration(opts.Server.ReadTimeout) * time.Second,
		Version:      revision,
		PasswordHash: opts.Auth.PasswordHash,
		AuthTokens:   opts.Auth.Tokens,
		LoginTTL:     time.Duration(opts.Auth.LoginTTL) * time.Minute,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize server: %w", err)
	}

	// start health checker for service discovery
	healthChecker := server.NewHealthChecker(kvStore, server.HealthCheckerConfig{
		TTLCheckInterval:  time.Duration(opts.Discovery.TTLCheckInterval) * time.Second,
		HTTPCheckInterval: time.Duration(opts.Discovery.HTTPCheckInterval) * time.Second,
		HTTPCheckTimeout:  time.Duration(opts.Discovery.HTTPCheckTimeout) * time.Second,
	})
	go healthChecker.Run(ctx)

	if err := srv.Run(ctx); err != nil {
		return fmt.Errorf("server failed: %w", err)
	}
	return nil
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
