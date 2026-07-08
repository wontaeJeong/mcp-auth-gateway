// Package config loads and validates the gateway configuration.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level gateway configuration.
type Config struct {
	Server           ServerConfig           `yaml:"server"`
	Auth             AuthConfig             `yaml:"auth"`
	InternalIdentity InternalIdentityConfig `yaml:"internal_identity"`
	Servers          []MCPServer            `yaml:"servers"`
}

// ServerConfig holds HTTP listener settings.
type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

// Duration is a time.Duration that unmarshals from YAML strings ("10m") or a
// plain number of seconds.
type Duration time.Duration

// UnmarshalYAML supports both "10m"-style strings and numeric seconds.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err == nil && s != "" {
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("invalid duration %q: %w", s, err)
		}
		*d = Duration(parsed)
		return nil
	}
	var secs float64
	if err := node.Decode(&secs); err != nil {
		return fmt.Errorf("duration must be a string or number: %w", err)
	}
	*d = Duration(time.Duration(secs * float64(time.Second)))
	return nil
}

// Std returns the value as a time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// AuthConfig holds Keycloak / OIDC verification settings.
type AuthConfig struct {
	Issuer        string   `yaml:"issuer"`
	DiscoveryURL  string   `yaml:"discovery_url"`
	LoginIDClaim  string   `yaml:"loginid_claim"`
	GroupsClaim   string   `yaml:"groups_claim"`
	UsernameClaim string   `yaml:"username_claim"`
	EmailClaim    string   `yaml:"email_claim"`
	JWKSCacheTTL  Duration `yaml:"jwks_cache_ttl"`
}

// InternalIdentityConfig configures the gateway-signed identity token.
type InternalIdentityConfig struct {
	Issuer         string   `yaml:"issuer"`
	AudiencePrefix string   `yaml:"audience_prefix"`
	TTL            Duration `yaml:"ttl"`
	SigningAlg     string   `yaml:"signing_alg"`
	SecretEnv      string   `yaml:"secret_env"`
}

// MCPServer describes a single backend MCP server routed by path prefix.
type MCPServer struct {
	Name                    string   `yaml:"name"`
	ExternalPathPrefix      string   `yaml:"external_path_prefix"`
	MCPPath                 string   `yaml:"mcp_path"`
	PublicResource          string   `yaml:"public_resource"`
	Audience                string   `yaml:"audience"`
	BackendURL              string   `yaml:"backend_url"`
	BackendIdentityAudience string   `yaml:"backend_identity_audience"`
	StripExternalPathPrefix bool     `yaml:"strip_external_path_prefix"`
	RequiredScopes          []string `yaml:"required_scopes"`
	AllowedGroups           []string `yaml:"allowed_groups"`
}

// ExternalBasePath returns the full external MCP path, e.g. "/mock/mcp".
func (s MCPServer) ExternalBasePath() string {
	return strings.TrimRight(s.ExternalPathPrefix, "/") + ensureLeadingSlash(s.MCPPath)
}

// MetadataPath returns the protected-resource-metadata path for this server,
// e.g. "/.well-known/oauth-protected-resource/mock/mcp".
func (s MCPServer) MetadataPath() string {
	return "/.well-known/oauth-protected-resource" + s.ExternalBasePath()
}

func ensureLeadingSlash(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

// Load reads, parses and validates a config file, applying defaults.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.ListenAddr == "" {
		c.Server.ListenAddr = ":8080"
	}
	if c.Auth.LoginIDClaim == "" {
		c.Auth.LoginIDClaim = "loginid"
	}
	if c.Auth.GroupsClaim == "" {
		c.Auth.GroupsClaim = "groups"
	}
	if c.Auth.UsernameClaim == "" {
		c.Auth.UsernameClaim = "preferred_username"
	}
	if c.Auth.EmailClaim == "" {
		c.Auth.EmailClaim = "email"
	}
	if c.Auth.JWKSCacheTTL == 0 {
		c.Auth.JWKSCacheTTL = Duration(10 * time.Minute)
	}
	if c.Auth.DiscoveryURL == "" && c.Auth.Issuer != "" {
		c.Auth.DiscoveryURL = strings.TrimRight(c.Auth.Issuer, "/") + "/.well-known/openid-configuration"
	}
	if c.InternalIdentity.Issuer == "" {
		c.InternalIdentity.Issuer = "mcp-auth-gateway"
	}
	if c.InternalIdentity.TTL == 0 {
		c.InternalIdentity.TTL = Duration(60 * time.Second)
	}
	if c.InternalIdentity.SigningAlg == "" {
		c.InternalIdentity.SigningAlg = "HS256"
	}
	if c.InternalIdentity.SecretEnv == "" {
		c.InternalIdentity.SecretEnv = "MCP_INTERNAL_JWT_SECRET"
	}
	for i := range c.Servers {
		if c.Servers[i].MCPPath == "" {
			c.Servers[i].MCPPath = "/mcp"
		}
	}
}

func (c *Config) validate() error {
	if c.Auth.Issuer == "" {
		return fmt.Errorf("auth.issuer is required")
	}
	if c.Auth.DiscoveryURL == "" {
		return fmt.Errorf("auth.discovery_url is required")
	}
	if len(c.Servers) == 0 {
		return fmt.Errorf("at least one server must be configured")
	}
	seen := map[string]bool{}
	for i, s := range c.Servers {
		if s.Name == "" {
			return fmt.Errorf("servers[%d].name is required", i)
		}
		if s.ExternalPathPrefix == "" {
			return fmt.Errorf("servers[%q].external_path_prefix is required", s.Name)
		}
		if s.BackendURL == "" {
			return fmt.Errorf("servers[%q].backend_url is required", s.Name)
		}
		if s.Audience == "" {
			return fmt.Errorf("servers[%q].audience is required", s.Name)
		}
		if s.PublicResource == "" {
			return fmt.Errorf("servers[%q].public_resource is required", s.Name)
		}
		base := s.ExternalBasePath()
		if seen[base] {
			return fmt.Errorf("duplicate external path %q", base)
		}
		seen[base] = true
	}
	return nil
}

// InternalSecret resolves the internal signing secret from the environment.
func (c *Config) InternalSecret() string {
	return os.Getenv(c.InternalIdentity.SecretEnv)
}
