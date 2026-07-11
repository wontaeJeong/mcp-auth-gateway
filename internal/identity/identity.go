// Package identity mints the short-lived, gateway-signed identity token that is
// forwarded to backend MCP servers via the X-MCP-Identity header.
package identity

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/samsungds/mcp-auth-gateway/internal/auth"
	"github.com/samsungds/mcp-auth-gateway/internal/config"
)

const maxInternalIdentityTTL = config.MaxInternalIdentityTTL

// Signer creates internal identity JWTs (HS256, MVP).
type Signer struct {
	issuer string
	ttl    time.Duration
	secret []byte
	now    func() time.Time
}

// NewSigner builds a Signer from config. The HS256 secret must contain at least
// 32 raw bytes.
func NewSigner(cfg config.InternalIdentityConfig, secret string) (*Signer, error) {
	if len([]byte(secret)) < 32 {
		return nil, fmt.Errorf("internal identity signing secret must contain at least 32 bytes")
	}
	if cfg.SigningAlg != "" && cfg.SigningAlg != "HS256" {
		return nil, fmt.Errorf("unsupported internal signing_alg %q (only HS256 supported)", cfg.SigningAlg)
	}
	ttl := cfg.TTL.Std()
	if ttl == 0 {
		ttl = 60 * time.Second
	}
	if ttl < 0 {
		return nil, fmt.Errorf("internal identity TTL must be positive")
	}
	if ttl > maxInternalIdentityTTL {
		return nil, fmt.Errorf("internal identity TTL must not exceed %s", maxInternalIdentityTTL)
	}
	return &Signer{
		issuer: cfg.Issuer,
		ttl:    ttl,
		secret: []byte(secret),
		now:    time.Now,
	}, nil
}

// Sign produces a signed identity token for the given caller, audience and
// request ID.
func (s *Signer) Sign(id *auth.Identity, audience, requestID string) (string, error) {
	now := s.now()
	claims := jwt.MapClaims{
		"iss":        s.issuer,
		"aud":        audience,
		"sub":        id.Subject,
		"loginid":    id.LoginID,
		"groups":     nonNil(id.Groups),
		"scopes":     nonNil(id.Scopes),
		"request_id": requestID,
		"iat":        now.Unix(),
		"nbf":        now.Unix(),
		"exp":        now.Add(s.ttl).Unix(),
	}
	if id.Username != "" {
		claims["username"] = id.Username
	}
	if id.Email != "" {
		claims["email"] = id.Email
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
