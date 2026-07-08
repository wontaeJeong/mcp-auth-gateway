// Package server wires configuration, auth, identity and proxying into an HTTP
// handler tree.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/samsungds/mcp-auth-gateway/internal/auth"
	"github.com/samsungds/mcp-auth-gateway/internal/config"
	"github.com/samsungds/mcp-auth-gateway/internal/identity"
	"github.com/samsungds/mcp-auth-gateway/internal/proxy"
)

// Gateway is the top-level HTTP handler.
type Gateway struct {
	cfg      *config.Config
	verifier *auth.Verifier
	signer   *identity.Signer
	logger   *slog.Logger
	mux      *http.ServeMux
}

// routedServer bundles per-server config with its ready-to-use proxy.
type routedServer struct {
	cfg   config.MCPServer
	proxy *httputil.ReverseProxy
}

// New constructs a Gateway. It does not perform network I/O; call
// Verifier().Cache().Refresh to warm the JWKS cache.
func New(cfg *config.Config, verifier *auth.Verifier, signer *identity.Signer, logger *slog.Logger) (*Gateway, error) {
	if logger == nil {
		logger = slog.Default()
	}
	g := &Gateway{
		cfg:      cfg,
		verifier: verifier,
		signer:   signer,
		logger:   logger,
		mux:      http.NewServeMux(),
	}
	if err := g.routes(); err != nil {
		return nil, err
	}
	return g, nil
}

func (g *Gateway) Verifier() *auth.Verifier { return g.verifier }

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mux.ServeHTTP(w, r)
}

func (g *Gateway) routes() error {
	g.mux.HandleFunc("GET /healthz", g.handleHealthz)
	g.mux.HandleFunc("GET /readyz", g.handleReadyz)

	for _, srv := range g.cfg.Servers {
		rp, err := proxy.New(srv)
		if err != nil {
			return err
		}
		rs := &routedServer{cfg: srv, proxy: rp}

		// Protected Resource Metadata (RFC 9728), path-scoped per resource.
		g.mux.HandleFunc("GET "+srv.MetadataPath(), g.metadataHandler(srv))

		// MCP endpoints: exact base path and subtree.
		base := srv.ExternalBasePath()
		g.mux.Handle(base, g.protect(rs))
		g.mux.Handle(base+"/", g.protect(rs))
	}
	return nil
}

func (g *Gateway) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (g *Gateway) handleReadyz(w http.ResponseWriter, r *http.Request) {
	// If the JWKS cache never warmed up (e.g. Keycloak was briefly unreachable
	// at startup), retry here so the probe self-heals once Keycloak recovers.
	// Without this, a pod stuck NotReady never receives real /mock/mcp traffic
	// either, so nothing would ever trigger a retry.
	if !g.verifier.Cache().Ready() {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		if err := g.verifier.Cache().Refresh(ctx); err != nil {
			g.logger.Warn("readyz: JWKS refresh failed", "error", err)
		}
		cancel()
	}

	checks := map[string]bool{
		"config":          g.cfg != nil && len(g.cfg.Servers) > 0,
		"jwks":            g.verifier.Cache().Ready(),
		"internal_secret": g.signer != nil,
	}
	ready := true
	for _, ok := range checks {
		if !ok {
			ready = false
			break
		}
	}
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]interface{}{
		"ready":  ready,
		"checks": checks,
	})
}

func (g *Gateway) metadataHandler(srv config.MCPServer) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"resource":              srv.PublicResource,
			"authorization_servers": []string{g.cfg.Auth.Issuer},
			"scopes_supported":      srv.RequiredScopes,
		})
	}
}

// protect verifies the caller, strips spoofable headers, mints an internal
// identity token and proxies to the backend.
func (g *Gateway) protect(rs *routedServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r.Header.Get("Authorization"))
		id, err := g.verifier.Verify(r.Context(), token, rs.cfg)
		if err != nil {
			g.writeAuthError(w, rs.cfg, err)
			return
		}

		requestID := newRequestID()
		internalToken, err := g.signer.Sign(id, rs.cfg.BackendIdentityAudience, requestID)
		if err != nil {
			g.logger.Error("failed to mint internal identity token", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":   "internal_error",
				"message": "failed to establish backend identity",
			})
			return
		}

		// Strip any client-supplied identity headers, then set trusted values.
		proxy.StripClientHeaders(r.Header)
		r.Header.Set("X-MCP-Identity", internalToken)
		r.Header.Set("X-MCP-Request-ID", requestID)
		r.Header.Set("X-MCP-LoginID", id.LoginID)
		r.Header.Set("X-MCP-Subject", id.Subject)

		g.logger.Info("proxying mcp request",
			"server", rs.cfg.Name,
			"loginid", id.LoginID,
			"request_id", requestID,
			"path", r.URL.Path,
		)
		rs.proxy.ServeHTTP(w, r)
	})
}

func (g *Gateway) writeAuthError(w http.ResponseWriter, srv config.MCPServer, err error) {
	ae, ok := auth.AsAuthError(err)
	if !ok {
		ae = &auth.AuthError{Status: http.StatusUnauthorized, Code: "unauthorized", Message: err.Error()}
	}
	if ae.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", g.wwwAuthenticate(srv))
	}
	writeJSON(w, ae.Status, map[string]string{
		"error":   ae.Code,
		"message": ae.Message,
	})
}

func (g *Gateway) wwwAuthenticate(srv config.MCPServer) string {
	metadataURL := strings.TrimRight(publicOrigin(srv.PublicResource), "/") + srv.MetadataPath()
	scope := strings.Join(srv.RequiredScopes, " ")
	return fmt.Sprintf(`Bearer realm="mcp", resource_metadata=%q, scope=%q`, metadataURL, scope)
}

// publicOrigin returns the scheme://host of a public resource URL.
func publicOrigin(resource string) string {
	if i := strings.Index(resource, "://"); i >= 0 {
		rest := resource[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return resource[:i+3] + rest[:j]
		}
		return resource
	}
	return resource
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if len(header) >= len(prefix) && strings.EqualFold(header[:len(prefix)], prefix) {
		return strings.TrimSpace(header[len(prefix):])
	}
	return ""
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-unknown"
	}
	return hex.EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// WarmUp refreshes the JWKS cache; used at startup and readiness.
func (g *Gateway) WarmUp(ctx context.Context) error {
	return g.verifier.Cache().Refresh(ctx)
}
