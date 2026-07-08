// Command gateway runs the MCP auth gateway.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/samsungds/mcp-auth-gateway/internal/auth"
	"github.com/samsungds/mcp-auth-gateway/internal/config"
	"github.com/samsungds/mcp-auth-gateway/internal/identity"
	"github.com/samsungds/mcp-auth-gateway/internal/server"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.yaml", "path to config file")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(configPath, logger); err != nil {
		logger.Error("gateway exited with error", "error", err)
		os.Exit(1)
	}
}

func run(configPath string, logger *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	secret := cfg.InternalSecret()
	signer, err := identity.NewSigner(cfg.InternalIdentity, secret)
	if err != nil {
		return err
	}

	cache := auth.NewKeyCache(cfg.Auth.DiscoveryURL, cfg.Auth.Issuer, cfg.Auth.JWKSCacheTTL.Std(), nil)
	verifier := auth.NewVerifier(cfg.Auth, cache)

	gw, err := server.New(cfg, verifier, signer, logger)
	if err != nil {
		return err
	}

	// Warm the JWKS cache; log but do not fail hard so /readyz can report status.
	warmCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := gw.WarmUp(warmCtx); err != nil {
		logger.Warn("initial JWKS warm-up failed; will retry on demand", "error", err)
	}
	cancel()

	httpServer := &http.Server{
		Addr:              cfg.Server.ListenAddr,
		Handler:           gw,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("mcp-auth-gateway listening", "addr", cfg.Server.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case <-stop:
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	}
}
