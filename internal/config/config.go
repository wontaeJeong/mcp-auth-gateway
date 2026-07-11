// Package config loads and validates the gateway configuration.
package config

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
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

// MaxInternalIdentityTTL limits the lifetime of credentials crossing the
// gateway-to-backend trust boundary.
const MaxInternalIdentityTTL = 5 * time.Minute

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
	AllowedOrigins          []string `yaml:"allowed_origins"`
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
	cfg := Config{
		Auth: AuthConfig{JWKSCacheTTL: Duration(10 * time.Minute)},
		InternalIdentity: InternalIdentityConfig{
			TTL: Duration(60 * time.Second),
		},
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parse config: multiple YAML documents are not allowed")
		}
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
	if c.Auth.DiscoveryURL == "" && c.Auth.Issuer != "" {
		c.Auth.DiscoveryURL = strings.TrimRight(c.Auth.Issuer, "/") + "/.well-known/openid-configuration"
	}
	if c.InternalIdentity.Issuer == "" {
		c.InternalIdentity.Issuer = "mcp-auth-gateway"
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
	if strings.TrimSpace(c.Auth.Issuer) == "" {
		return fmt.Errorf("auth.issuer is required")
	}
	if _, err := parseHTTPURL("auth.issuer", c.Auth.Issuer); err != nil {
		return err
	}
	if strings.TrimSpace(c.Auth.DiscoveryURL) == "" {
		return fmt.Errorf("auth.discovery_url is required")
	}
	if _, err := parseHTTPURL("auth.discovery_url", c.Auth.DiscoveryURL); err != nil {
		return err
	}
	if c.Auth.JWKSCacheTTL.Std() <= 0 {
		return fmt.Errorf("auth.jwks_cache_ttl must be positive")
	}
	if c.InternalIdentity.TTL.Std() <= 0 {
		return fmt.Errorf("internal_identity.ttl must be positive")
	}
	if c.InternalIdentity.TTL.Std() > MaxInternalIdentityTTL {
		return fmt.Errorf("internal_identity.ttl must not exceed %s", MaxInternalIdentityTTL)
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
		if strings.TrimSpace(s.BackendURL) == "" {
			return fmt.Errorf("servers[%q].backend_url is required", s.Name)
		}
		if _, err := parseHTTPURL(fmt.Sprintf("servers[%q].backend_url", s.Name), s.BackendURL); err != nil {
			return err
		}
		if strings.TrimSpace(s.BackendIdentityAudience) == "" {
			return fmt.Errorf("servers[%q].backend_identity_audience is required", s.Name)
		}
		if strings.TrimSpace(s.Audience) == "" {
			return fmt.Errorf("servers[%q].audience is required", s.Name)
		}
		if _, err := parseHTTPURL(fmt.Sprintf("servers[%q].audience", s.Name), s.Audience); err != nil {
			return err
		}
		if strings.TrimSpace(s.PublicResource) == "" {
			return fmt.Errorf("servers[%q].public_resource is required", s.Name)
		}
		resourceURL, err := parseHTTPURI(fmt.Sprintf("servers[%q].public_resource", s.Name), s.PublicResource)
		if err != nil {
			return err
		}
		if len(s.AllowedOrigins) == 0 {
			return fmt.Errorf("servers[%q].allowed_origins must contain at least one origin", s.Name)
		}
		origins := make(map[string]bool, len(s.AllowedOrigins))
		for _, origin := range s.AllowedOrigins {
			if !IsSerializedHTTPOrigin(origin) {
				return fmt.Errorf("servers[%q].allowed_origins contains invalid origin %q", s.Name, origin)
			}
			if origins[origin] {
				return fmt.Errorf("servers[%q].allowed_origins contains duplicate origin %q", s.Name, origin)
			}
			origins[origin] = true
		}
		publicOrigin := resourceURL.Scheme + "://" + resourceURL.Host
		if !origins[publicOrigin] {
			return fmt.Errorf("servers[%q].allowed_origins must include public_resource origin %q", s.Name, publicOrigin)
		}
		if len(s.RequiredScopes) == 0 {
			return fmt.Errorf("servers[%q].required_scopes must contain at least one scope", s.Name)
		}
		scopes := make(map[string]bool, len(s.RequiredScopes))
		for j, scope := range s.RequiredScopes {
			scope = strings.TrimSpace(scope)
			if scope == "" {
				return fmt.Errorf("servers[%q].required_scopes contains an empty scope", s.Name)
			}
			if !isOAuthScopeToken(scope) {
				return fmt.Errorf("servers[%q].required_scopes entry must be one OAuth scope token: %q", s.Name, scope)
			}
			if scopes[scope] {
				return fmt.Errorf("servers[%q].required_scopes contains duplicate scope %q", s.Name, scope)
			}
			scopes[scope] = true
			c.Servers[i].RequiredScopes[j] = scope
		}
		base := s.ExternalBasePath()
		if seen[base] {
			return fmt.Errorf("duplicate external path %q", base)
		}
		seen[base] = true
	}
	return nil
}

func parseHTTPURL(name, raw string) (*url.URL, error) {
	return parseHTTPReference(name, raw, "URL")
}

func parseHTTPURI(name, raw string) (*url.URL, error) {
	return parseHTTPReference(name, raw, "URI")
}

func parseHTTPReference(name, raw, kind string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || raw != strings.TrimSpace(raw) || !parsed.IsAbs() ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.Hostname() == "" || parsed.Opaque != "" {
		return nil, fmt.Errorf("%s must be an absolute http/https %s", name, kind)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("%s must not contain userinfo, query, or fragment", name)
	}
	return parsed, nil
}

// IsSerializedHTTPOrigin reports whether origin is exactly an http/https
// origin serialized as scheme://host, with no other URI components.
func IsSerializedHTTPOrigin(origin string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Hostname() == "" {
		return false
	}
	if parsed.User != nil || parsed.Opaque != "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(origin, "#") {
		return false
	}
	return origin == parsed.Scheme+"://"+parsed.Host
}

func isOAuthScopeToken(scope string) bool {
	for i := 0; i < len(scope); i++ {
		b := scope[i]
		if b != 0x21 && (b < 0x23 || b > 0x5b) && (b < 0x5d || b > 0x7e) {
			return false
		}
	}
	return scope != ""
}

// InternalSecret resolves the internal signing secret from the environment.
func (c *Config) InternalSecret() string {
	return os.Getenv(c.InternalIdentity.SecretEnv)
}
