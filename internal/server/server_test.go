package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/samsungds/mcp-auth-gateway/internal/auth"
	"github.com/samsungds/mcp-auth-gateway/internal/config"
	"github.com/samsungds/mcp-auth-gateway/internal/identity"
	"github.com/samsungds/mcp-auth-gateway/internal/server"
)

const (
	testResource = "https://gateway.mcp.aidev.samsungds.net/mock/mcp"
	testScope    = "mcp:mock:use"
	testKID      = "test-key-1"
	testSecret   = "super-secret-internal-signing-key"
	backendAud   = "mock-mcp-server"
)

// oidcMock is a fake Keycloak: it serves an OIDC discovery document and a JWKS.
type oidcMock struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	issuer string
}

func newOIDCMock(t *testing.T) *oidcMock {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	m := &oidcMock{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":   m.issuer,
			"jwks_uri": m.issuer + "/protocol/openid-connect/certs",
		})
	})
	mux.HandleFunc("/protocol/openid-connect/certs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(m.jwks())
	})
	m.server = httptest.NewServer(mux)
	m.issuer = m.server.URL
	t.Cleanup(m.server.Close)
	return m
}

func (m *oidcMock) jwks() map[string]interface{} {
	pub := m.key.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	eBytes := []byte{0x01, 0x00, 0x01} // 65537
	e := base64.RawURLEncoding.EncodeToString(eBytes)
	return map[string]interface{}{
		"keys": []map[string]interface{}{
			{"kty": "RSA", "kid": testKID, "alg": "RS256", "use": "sig", "n": n, "e": e},
		},
	}
}

type tokenOpts struct {
	issuer  string
	aud     interface{}
	scope   string
	loginid string
	sub     string
	groups  []string
	exp     time.Time
	kid     string
	signKey *rsa.PrivateKey
}

func (m *oidcMock) mintToken(t *testing.T, o tokenOpts) string {
	t.Helper()
	if o.issuer == "" {
		o.issuer = m.issuer
	}
	if o.aud == nil {
		o.aud = []string{testResource}
	}
	if o.exp.IsZero() {
		o.exp = time.Now().Add(5 * time.Minute)
	}
	if o.kid == "" {
		o.kid = testKID
	}
	if o.signKey == nil {
		o.signKey = m.key
	}
	if o.sub == "" {
		o.sub = "user-sub-123"
	}
	claims := jwt.MapClaims{
		"iss": o.issuer,
		"aud": o.aud,
		"sub": o.sub,
		"exp": o.exp.Unix(),
		"iat": time.Now().Unix(),
		"nbf": time.Now().Add(-time.Minute).Unix(),
	}
	if o.scope != "" {
		claims["scope"] = o.scope
	}
	if o.loginid != "" {
		claims["loginid"] = o.loginid
	}
	if o.groups != nil {
		claims["groups"] = o.groups
	}
	claims["preferred_username"] = "alice"
	claims["email"] = "alice@example.com"

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = o.kid
	signed, err := tok.SignedString(o.signKey)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// backendCapture records what the backend received.
type backendCapture struct {
	mu      sync.Mutex
	path    string
	headers http.Header
	body    string
}

func (b *backendCapture) snapshot() (string, http.Header, string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.path, b.headers.Clone(), b.body
}

// testEnv holds the assembled gateway and its dependencies.
type testEnv struct {
	gateway *server.Gateway
	oidc    *oidcMock
	backend *httptest.Server
	capture *backendCapture
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvOpts(t, true)
}

func newTestEnvOpts(t *testing.T, warmUp bool) *testEnv {
	t.Helper()
	oidc := newOIDCMock(t)

	capture := &backendCapture{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capture.mu.Lock()
		capture.path = r.URL.Path
		capture.headers = r.Header.Clone()
		capture.body = string(body)
		capture.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(backend.Close)

	cfg := &config.Config{
		Server: config.ServerConfig{ListenAddr: ":0"},
		Auth: config.AuthConfig{
			Issuer:        oidc.issuer,
			DiscoveryURL:  oidc.issuer + "/.well-known/openid-configuration",
			LoginIDClaim:  "loginid",
			GroupsClaim:   "groups",
			UsernameClaim: "preferred_username",
			EmailClaim:    "email",
			JWKSCacheTTL:  config.Duration(10 * time.Minute),
		},
		InternalIdentity: config.InternalIdentityConfig{
			Issuer:     "mcp-auth-gateway",
			TTL:        config.Duration(60 * time.Second),
			SigningAlg: "HS256",
			SecretEnv:  "MCP_INTERNAL_JWT_SECRET",
		},
		Servers: []config.MCPServer{
			{
				Name:                    "mock",
				ExternalPathPrefix:      "/mock",
				MCPPath:                 "/mcp",
				PublicResource:          testResource,
				Audience:                testResource,
				BackendURL:              backend.URL,
				BackendIdentityAudience: backendAud,
				StripExternalPathPrefix: true,
				RequiredScopes:          []string{testScope},
				AllowedGroups:           []string{},
			},
		},
	}

	signer, err := identity.NewSigner(cfg.InternalIdentity, testSecret)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	cache := auth.NewKeyCache(cfg.Auth.DiscoveryURL, cfg.Auth.Issuer, cfg.Auth.JWKSCacheTTL.Std(), nil)
	verifier := auth.NewVerifier(cfg.Auth, cache)
	gw, err := server.New(cfg, verifier, signer, nil)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	if warmUp {
		if err := gw.WarmUp(context.Background()); err != nil {
			t.Fatalf("warm up: %v", err)
		}
	}
	return &testEnv{gateway: gw, oidc: oidc, backend: backend, capture: capture}
}

func (e *testEnv) do(t *testing.T, method, path, token string, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	e.gateway.ServeHTTP(rr, req)
	return rr
}

func TestProtectedResourceMetadata(t *testing.T) {
	env := newTestEnv(t)
	rr := env.do(t, http.MethodGet, "/.well-known/oauth-protected-resource/mock/mcp", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var doc struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Resource != testResource {
		t.Errorf("resource = %q, want %q", doc.Resource, testResource)
	}
	if len(doc.ScopesSupported) != 1 || doc.ScopesSupported[0] != testScope {
		t.Errorf("scopes_supported = %v, want [%q]", doc.ScopesSupported, testScope)
	}
	if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != env.oidc.issuer {
		t.Errorf("authorization_servers = %v", doc.AuthorizationServers)
	}
}

func TestMissingToken401(t *testing.T) {
	env := newTestEnv(t)
	rr := env.do(t, http.MethodPost, "/mock/mcp", "", `{"jsonrpc":"2.0"}`)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	wa := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(wa, `realm="mcp"`) {
		t.Errorf("WWW-Authenticate missing realm: %q", wa)
	}
	if !strings.Contains(wa, `resource_metadata="https://gateway.mcp.aidev.samsungds.net/.well-known/oauth-protected-resource/mock/mcp"`) {
		t.Errorf("WWW-Authenticate resource_metadata wrong: %q", wa)
	}
	if !strings.Contains(wa, `scope="mcp:mock:use"`) {
		t.Errorf("WWW-Authenticate scope wrong: %q", wa)
	}
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body.Error != "unauthorized" {
		t.Errorf("error = %q, want unauthorized", body.Error)
	}
}

func TestIssuerMismatch401(t *testing.T) {
	env := newTestEnv(t)
	tok := env.oidc.mintToken(t, tokenOpts{
		issuer: "https://evil.example.com/realms/mcp", scope: testScope, loginid: "alice01",
	})
	rr := env.do(t, http.MethodPost, "/mock/mcp", tok, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestAudienceMismatch401(t *testing.T) {
	env := newTestEnv(t)
	tok := env.oidc.mintToken(t, tokenOpts{
		aud: []string{"https://gateway.mcp.aidev.samsungds.net/other/mcp"}, scope: testScope, loginid: "alice01",
	})
	rr := env.do(t, http.MethodPost, "/mock/mcp", tok, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestInsufficientScope403(t *testing.T) {
	env := newTestEnv(t)
	tok := env.oidc.mintToken(t, tokenOpts{scope: "openid profile", loginid: "alice01"})
	rr := env.do(t, http.MethodPost, "/mock/mcp", tok, "")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body.Error != "forbidden" {
		t.Errorf("error = %q, want forbidden", body.Error)
	}
}

func TestMissingLoginID401(t *testing.T) {
	env := newTestEnv(t)
	tok := env.oidc.mintToken(t, tokenOpts{scope: testScope, loginid: ""})
	rr := env.do(t, http.MethodPost, "/mock/mcp", tok, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestExpiredToken401(t *testing.T) {
	env := newTestEnv(t)
	tok := env.oidc.mintToken(t, tokenOpts{
		scope: testScope, loginid: "alice01", exp: time.Now().Add(-time.Minute),
	})
	rr := env.do(t, http.MethodPost, "/mock/mcp", tok, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestBadSignature401(t *testing.T) {
	env := newTestEnv(t)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := env.oidc.mintToken(t, tokenOpts{
		scope: testScope, loginid: "alice01", signKey: otherKey,
	})
	rr := env.do(t, http.MethodPost, "/mock/mcp", tok, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestValidTokenProxies(t *testing.T) {
	env := newTestEnv(t)
	tok := env.oidc.mintToken(t, tokenOpts{
		scope: "openid " + testScope, loginid: "alice01", groups: []string{"g1", "g2"},
	})
	rr := env.do(t, http.MethodPost, "/mock/mcp", tok, `{"jsonrpc":"2.0","method":"ping"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Errorf("backend body not returned: %s", rr.Body.String())
	}

	path, headers, body := env.capture.snapshot()

	// 8. path rewrite /mock/mcp -> /mcp
	if path != "/mcp" {
		t.Errorf("backend path = %q, want /mcp", path)
	}
	if body != `{"jsonrpc":"2.0","method":"ping"}` {
		t.Errorf("backend body = %q", body)
	}

	// 9. Authorization must not reach backend.
	if got := headers.Get("Authorization"); got != "" {
		t.Errorf("backend received Authorization header: %q", got)
	}

	// gateway-set trusted headers present.
	if headers.Get("X-MCP-Identity") == "" {
		t.Error("backend missing X-MCP-Identity")
	}
	if headers.Get("X-MCP-Request-ID") == "" {
		t.Error("backend missing X-MCP-Request-ID")
	}
	if got := headers.Get("X-MCP-LoginID"); got != "alice01" {
		t.Errorf("X-MCP-LoginID = %q, want alice01", got)
	}

	// 11. backend can verify the internal identity JWT.
	claims := verifyInternalToken(t, headers.Get("X-MCP-Identity"))
	if claims["loginid"] != "alice01" {
		t.Errorf("internal loginid = %v", claims["loginid"])
	}
	if claims["aud"] != backendAud {
		t.Errorf("internal aud = %v, want %s", claims["aud"], backendAud)
	}
	if claims["iss"] != "mcp-auth-gateway" {
		t.Errorf("internal iss = %v", claims["iss"])
	}
	if claims["sub"] != "user-sub-123" {
		t.Errorf("internal sub = %v", claims["sub"])
	}
	if claims["request_id"] != headers.Get("X-MCP-Request-ID") {
		t.Errorf("internal request_id mismatch: %v vs %v", claims["request_id"], headers.Get("X-MCP-Request-ID"))
	}
}

func TestSubtreePathRewrite(t *testing.T) {
	env := newTestEnv(t)
	tok := env.oidc.mintToken(t, tokenOpts{scope: testScope, loginid: "alice01"})
	rr := env.do(t, http.MethodGet, "/mock/mcp/tools/list", tok, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	path, _, _ := env.capture.snapshot()
	if path != "/mcp/tools/list" {
		t.Errorf("backend path = %q, want /mcp/tools/list", path)
	}
}

func TestSpoofedIdentityHeadersStripped(t *testing.T) {
	env := newTestEnv(t)
	tok := env.oidc.mintToken(t, tokenOpts{scope: testScope, loginid: "alice01"})

	req := httptest.NewRequest(http.MethodPost, "/mock/mcp", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-MCP-Identity", "forged.jwt.value")
	req.Header.Set("X-MCP-LoginID", "attacker")
	req.Header.Set("X-MCP-Subject", "attacker-sub")
	req.Header.Set("X-MCP-Request-ID", "forged-req-id")
	rr := httptest.NewRecorder()
	env.gateway.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}

	_, headers, _ := env.capture.snapshot()
	if got := headers.Get("X-MCP-Identity"); got == "forged.jwt.value" {
		t.Fatal("forged X-MCP-Identity was not replaced")
	}
	if got := headers.Get("X-MCP-LoginID"); got != "alice01" {
		t.Errorf("X-MCP-LoginID = %q, want alice01 (forged not stripped)", got)
	}
	if got := headers.Get("X-MCP-Request-ID"); got == "forged-req-id" {
		t.Error("forged X-MCP-Request-ID was not replaced")
	}
	// The replaced identity must be a valid gateway-signed token.
	claims := verifyInternalToken(t, headers.Get("X-MCP-Identity"))
	if claims["loginid"] != "alice01" {
		t.Errorf("internal loginid = %v, want alice01", claims["loginid"])
	}
}

func TestUnknownPathPrefix404(t *testing.T) {
	env := newTestEnv(t)
	tok := env.oidc.mintToken(t, tokenOpts{scope: testScope, loginid: "alice01"})
	rr := env.do(t, http.MethodPost, "/unknown/mcp", tok, "")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

func TestHealthAndReady(t *testing.T) {
	env := newTestEnv(t)
	if rr := env.do(t, http.MethodGet, "/healthz", "", ""); rr.Code != http.StatusOK {
		t.Errorf("healthz = %d", rr.Code)
	}
	rr := env.do(t, http.MethodGet, "/readyz", "", "")
	if rr.Code != http.StatusOK {
		t.Errorf("readyz = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
}

// TestReadyzSelfHeals verifies that /readyz retries the JWKS fetch when the
// cache never warmed up (e.g. Keycloak was briefly unreachable at startup),
// so a NotReady pod can recover without relying on real /mock/mcp traffic to
// trigger a refresh.
func TestReadyzSelfHeals(t *testing.T) {
	env := newTestEnvOpts(t, false)
	if env.gateway.Verifier().Cache().Ready() {
		t.Fatal("expected cache to start not ready")
	}
	rr := env.do(t, http.MethodGet, "/readyz", "", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("readyz = %d, want 200 after self-heal; body=%s", rr.Code, rr.Body.String())
	}
	if !env.gateway.Verifier().Cache().Ready() {
		t.Fatal("cache still not ready after /readyz self-heal")
	}
}

// verifyInternalToken validates the HS256 gateway-signed identity token as a
// backend would, returning its claims.
func verifyInternalToken(t *testing.T, raw string) jwt.MapClaims {
	t.Helper()
	if raw == "" {
		t.Fatal("empty internal token")
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(tok *jwt.Token) (interface{}, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodHMAC); !ok {
			t.Fatalf("unexpected internal signing method: %s", tok.Method.Alg())
		}
		return []byte(testSecret), nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	if err != nil {
		t.Fatalf("verify internal token: %v", err)
	}
	return claims
}
