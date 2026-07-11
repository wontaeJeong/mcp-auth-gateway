package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestValidateServerSecurityRequirements(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*MCPServer)
		want   string
	}{
		{
			name: "missing backend identity audience",
			mutate: func(s *MCPServer) {
				s.BackendIdentityAudience = ""
			},
			want: "backend_identity_audience is required",
		},
		{
			name: "whitespace backend identity audience",
			mutate: func(s *MCPServer) {
				s.BackendIdentityAudience = "  \t"
			},
			want: "backend_identity_audience is required",
		},
		{
			name: "missing required scopes",
			mutate: func(s *MCPServer) {
				s.RequiredScopes = nil
			},
			want: "required_scopes must contain at least one scope",
		},
		{
			name: "empty required scope",
			mutate: func(s *MCPServer) {
				s.RequiredScopes = []string{""}
			},
			want: "required_scopes contains an empty scope",
		},
		{
			name: "whitespace required scope",
			mutate: func(s *MCPServer) {
				s.RequiredScopes = []string{" \t "}
			},
			want: "required_scopes contains an empty scope",
		},
		{
			name: "duplicate required scope",
			mutate: func(s *MCPServer) {
				s.RequiredScopes = []string{"mcp:mock:use", "mcp:mock:use"}
			},
			want: "required_scopes contains duplicate scope",
		},
		{
			name: "required scope containing internal space",
			mutate: func(s *MCPServer) {
				s.RequiredScopes = []string{"mcp:mock use"}
			},
			want: "required_scopes entry must be one OAuth scope token",
		},
		{
			name: "required scope containing internal tab",
			mutate: func(s *MCPServer) {
				s.RequiredScopes = []string{"mcp:mock\tuse"}
			},
			want: "required_scopes entry must be one OAuth scope token",
		},
		{
			name: "required scope containing quote",
			mutate: func(s *MCPServer) {
				s.RequiredScopes = []string{`mcp:"mock`}
			},
			want: "required_scopes entry must be one OAuth scope token",
		},
		{
			name: "relative public resource",
			mutate: func(s *MCPServer) {
				s.PublicResource = "/mock/mcp"
			},
			want: "public_resource must be an absolute http/https URI",
		},
		{
			name: "non-http public resource",
			mutate: func(s *MCPServer) {
				s.PublicResource = "ftp://gateway.example.com/mock/mcp"
			},
			want: "public_resource must be an absolute http/https URI",
		},
		{
			name: "public resource with userinfo",
			mutate: func(s *MCPServer) {
				s.PublicResource = "https://user:pass@gateway.example.com/mock/mcp"
			},
			want: "public_resource must not contain userinfo, query, or fragment",
		},
		{
			name: "public resource with query",
			mutate: func(s *MCPServer) {
				s.PublicResource = "https://gateway.example.com/mock/mcp?tenant=one"
			},
			want: "public_resource must not contain userinfo, query, or fragment",
		},
		{
			name: "public resource with fragment",
			mutate: func(s *MCPServer) {
				s.PublicResource = "https://gateway.example.com/mock/mcp#tools"
			},
			want: "public_resource must not contain userinfo, query, or fragment",
		},
		{
			name: "missing allowed origins",
			mutate: func(s *MCPServer) {
				s.AllowedOrigins = nil
			},
			want: "allowed_origins must contain at least one origin",
		},
		{
			name: "null allowed origin",
			mutate: func(s *MCPServer) {
				s.AllowedOrigins = []string{"null"}
			},
			want: "allowed_origins contains invalid origin",
		},
		{
			name: "non-http allowed origin",
			mutate: func(s *MCPServer) {
				s.AllowedOrigins = []string{"ftp://gateway.example.com"}
			},
			want: "allowed_origins contains invalid origin",
		},
		{
			name: "allowed origin with path",
			mutate: func(s *MCPServer) {
				s.AllowedOrigins = []string{"https://gateway.example.com/path"}
			},
			want: "allowed_origins contains invalid origin",
		},
		{
			name: "allowed origin with query",
			mutate: func(s *MCPServer) {
				s.AllowedOrigins = []string{"https://gateway.example.com?tenant=one"}
			},
			want: "allowed_origins contains invalid origin",
		},
		{
			name: "allowed origin with fragment",
			mutate: func(s *MCPServer) {
				s.AllowedOrigins = []string{"https://gateway.example.com#tools"}
			},
			want: "allowed_origins contains invalid origin",
		},
		{
			name: "allowed origin with userinfo",
			mutate: func(s *MCPServer) {
				s.AllowedOrigins = []string{"https://user:pass@gateway.example.com"}
			},
			want: "allowed_origins contains invalid origin",
		},
		{
			name: "duplicate allowed origin",
			mutate: func(s *MCPServer) {
				s.AllowedOrigins = []string{"https://gateway.example.com", "https://gateway.example.com"}
			},
			want: "allowed_origins contains duplicate origin",
		},
		{
			name: "public resource origin not allowed",
			mutate: func(s *MCPServer) {
				s.AllowedOrigins = []string{"https://other.example.com"}
			},
			want: "allowed_origins must include public_resource origin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg.Servers[0])

			err := cfg.validate()
			if err == nil {
				t.Fatalf("validate() error = nil, want error containing %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validate() error = %q, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestValidateTrimsRequiredScopes(t *testing.T) {
	cfg := validConfig()
	cfg.Servers[0].RequiredScopes = []string{"  mcp:mock:use\t"}

	if err := cfg.validate(); err != nil {
		t.Fatalf("validate() error = %v, want nil", err)
	}
	if got := cfg.Servers[0].RequiredScopes[0]; got != "mcp:mock:use" {
		t.Fatalf("required scope = %q, want mcp:mock:use", got)
	}
}

func TestCheckedInConfigLoads(t *testing.T) {
	if _, err := Load("../../config.yaml"); err != nil {
		t.Fatalf("Load(config.yaml) error = %v", err)
	}
}

func TestLoadRejectsUnknownFieldsAndAdditionalDocuments(t *testing.T) {
	raw, err := yaml.Marshal(validConfig())
	if err != nil {
		t.Fatalf("yaml.Marshal() error = %v", err)
	}
	tests := []struct {
		name   string
		suffix string
	}{
		{name: "unknown field", suffix: "unknown_security_option: true\n"},
		{name: "additional document", suffix: "---\nserver:\n  listen_addr: ':9999'\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, append(raw, tt.suffix...), 0o600); err != nil {
				t.Fatalf("os.WriteFile() error = %v", err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load() error = nil, want strict YAML rejection")
			}
		})
	}
}

func TestValidateStructuralURLs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "relative issuer",
			mutate: func(c *Config) {
				c.Auth.Issuer = "/realms/mcp"
			},
			want: "auth.issuer must be an absolute http/https URL",
		},
		{
			name: "issuer userinfo",
			mutate: func(c *Config) {
				c.Auth.Issuer = "https://user:pass@auth.example.com/realms/mcp"
			},
			want: "auth.issuer must not contain userinfo, query, or fragment",
		},
		{
			name: "non-http discovery URL",
			mutate: func(c *Config) {
				c.Auth.DiscoveryURL = "file:///tmp/discovery.json"
			},
			want: "auth.discovery_url must be an absolute http/https URL",
		},
		{
			name: "discovery fragment",
			mutate: func(c *Config) {
				c.Auth.DiscoveryURL = "https://auth.example.com/discovery#fragment"
			},
			want: "auth.discovery_url must not contain userinfo, query, or fragment",
		},
		{
			name: "relative audience",
			mutate: func(c *Config) {
				c.Servers[0].Audience = "/mock/mcp"
			},
			want: "audience must be an absolute http/https URL",
		},
		{
			name: "relative backend URL",
			mutate: func(c *Config) {
				c.Servers[0].BackendURL = "mock-mcp-server:8080"
			},
			want: "backend_url must be an absolute http/https URL",
		},
		{
			name: "backend URL query",
			mutate: func(c *Config) {
				c.Servers[0].BackendURL = "http://mock-mcp-server:8080?tenant=one"
			},
			want: "backend_url must not contain userinfo, query, or fragment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			err := cfg.validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validate() error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestValidateAllowsLocalHTTPURLs(t *testing.T) {
	cfg := validConfig()
	cfg.Auth.Issuer = "http://127.0.0.1:8081/realms/mcp"
	cfg.Auth.DiscoveryURL = "http://127.0.0.1:8081/realms/mcp/.well-known/openid-configuration"
	cfg.Servers[0].PublicResource = "http://localhost:8080/mock/mcp"
	cfg.Servers[0].Audience = "http://localhost:8080/mock/mcp"
	cfg.Servers[0].BackendURL = "http://127.0.0.1:9090/base"
	cfg.Servers[0].AllowedOrigins = []string{"http://localhost:8080"}

	if err := cfg.validate(); err != nil {
		t.Fatalf("validate() rejected local HTTP URLs: %v", err)
	}
}

func TestValidateTTLs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "negative JWKS TTL",
			mutate: func(c *Config) {
				c.Auth.JWKSCacheTTL = Duration(-time.Second)
			},
			want: "auth.jwks_cache_ttl must be positive",
		},
		{
			name: "negative internal TTL",
			mutate: func(c *Config) {
				c.InternalIdentity.TTL = Duration(-time.Second)
			},
			want: "internal_identity.ttl must be positive",
		},
		{
			name: "internal TTL over maximum",
			mutate: func(c *Config) {
				c.InternalIdentity.TTL = Duration(5*time.Minute + time.Nanosecond)
			},
			want: "internal_identity.ttl must not exceed 5m0s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			err := cfg.validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validate() error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestLoadRejectsExplicitZeroTTLs(t *testing.T) {
	checkedIn, err := os.ReadFile("../../config.yaml")
	if err != nil {
		t.Fatalf("os.ReadFile(config.yaml) error = %v", err)
	}
	tests := []struct {
		name string
		old  string
	}{
		{name: "JWKS TTL", old: `jwks_cache_ttl: "10m"`},
		{name: "internal TTL", old: `ttl: "60s"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := strings.Replace(string(checkedIn), tt.old, strings.Split(tt.old, ":")[0]+`: "0s"`, 1)
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatalf("os.WriteFile() error = %v", err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("Load() error = nil, want explicit zero TTL rejection")
			}
		})
	}
}

func validConfig() Config {
	return Config{
		Auth: AuthConfig{
			Issuer:       "https://auth.example.com/realms/mcp",
			DiscoveryURL: "https://auth.example.com/realms/mcp/.well-known/openid-configuration",
			JWKSCacheTTL: Duration(10 * time.Minute),
		},
		InternalIdentity: InternalIdentityConfig{
			Issuer: "mcp-auth-gateway", TTL: Duration(time.Minute), SigningAlg: "HS256",
		},
		Servers: []MCPServer{
			{
				Name:                    "mock",
				ExternalPathPrefix:      "/mock",
				MCPPath:                 "/mcp",
				PublicResource:          "https://gateway.example.com/mock/mcp",
				Audience:                "https://gateway.example.com/mock/mcp",
				BackendURL:              "http://mock-mcp-server:8080",
				BackendIdentityAudience: "mock-mcp-server",
				RequiredScopes:          []string{"mcp:mock:use"},
				AllowedOrigins:          []string{"https://gateway.example.com"},
			},
		},
	}
}
