package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/samsungds/mcp-auth-gateway/internal/config"
)

// AuthError is an authentication/authorization failure carrying the HTTP status
// that should be returned to the client.
type AuthError struct {
	Status     int
	Code       string
	Message    string
	OAuthError string
}

func (e *AuthError) Error() string { return e.Message }

func missingCredentials(msg string) *AuthError {
	return &AuthError{Status: http.StatusUnauthorized, Code: "unauthorized", Message: msg}
}

func invalidToken(msg string) *AuthError {
	return &AuthError{
		Status:     http.StatusUnauthorized,
		Code:       "unauthorized",
		Message:    msg,
		OAuthError: "invalid_token",
	}
}

func forbidden(msg string) *AuthError {
	return &AuthError{Status: http.StatusForbidden, Code: "forbidden", Message: msg}
}

func insufficientScope(msg string) *AuthError {
	return &AuthError{
		Status:     http.StatusForbidden,
		Code:       "forbidden",
		Message:    msg,
		OAuthError: "insufficient_scope",
	}
}

// AsAuthError extracts an *AuthError from err, if present.
func AsAuthError(err error) (*AuthError, bool) {
	var ae *AuthError
	if errors.As(err, &ae) {
		return ae, true
	}
	return nil, false
}

// Identity is the verified caller identity extracted from a valid access token.
type Identity struct {
	Subject  string
	LoginID  string
	Username string
	Email    string
	Groups   []string
	Scopes   []string
}

// Verifier validates Keycloak access tokens against a JWKS and extracts the
// caller identity per server requirements.
type Verifier struct {
	cfg   config.AuthConfig
	cache *KeyCache
}

// NewVerifier constructs a Verifier backed by the given key cache.
func NewVerifier(cfg config.AuthConfig, cache *KeyCache) *Verifier {
	return &Verifier{cfg: cfg, cache: cache}
}

// Cache exposes the underlying key cache (used for readiness checks).
func (v *Verifier) Cache() *KeyCache { return v.cache }

// Verify validates the raw bearer token and enforces the per-server audience,
// scope, and group requirements. On success it returns the caller Identity.
func (v *Verifier) Verify(ctx context.Context, rawToken string, srv config.MCPServer) (*Identity, error) {
	if strings.TrimSpace(rawToken) == "" {
		return nil, missingCredentials("Bearer access token is required")
	}

	keyFunc := func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		return v.cache.keyByIDForAlgorithm(ctx, kid, t.Method.Alg())
	}

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(rawToken, claims, keyFunc,
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, invalidToken("invalid access token: " + sanitizeJWTError(err))
	}

	// Audience must contain the server's resource identifier.
	if !audienceContains(claims["aud"], srv.Audience) {
		return nil, invalidToken("token audience does not include " + srv.Audience)
	}

	subject, ok := claims["sub"].(string)
	if !ok || strings.TrimSpace(subject) == "" {
		return nil, invalidToken("required claim sub must be a non-empty string")
	}

	// loginid claim is mandatory and must be non-empty.
	loginID := stringClaim(claims, v.cfg.LoginIDClaim)
	if strings.TrimSpace(loginID) == "" {
		return nil, invalidToken("required claim " + v.cfg.LoginIDClaim + " is missing")
	}

	scopes := parseScopes(claims["scope"])
	if missing := missingScopes(scopes, srv.RequiredScopes); len(missing) > 0 {
		return nil, insufficientScope("missing required scope(s): " + strings.Join(missing, " "))
	}

	groups := stringSliceClaim(claims, v.cfg.GroupsClaim)
	if len(srv.AllowedGroups) > 0 && !anyIntersect(groups, srv.AllowedGroups) {
		return nil, forbidden("caller is not a member of an allowed group")
	}

	return &Identity{
		Subject:  subject,
		LoginID:  loginID,
		Username: stringClaim(claims, v.cfg.UsernameClaim),
		Email:    stringClaim(claims, v.cfg.EmailClaim),
		Groups:   groups,
		Scopes:   scopes,
	}, nil
}

// sanitizeJWTError maps jwt validation errors to short, non-leaking messages.
func sanitizeJWTError(err error) string {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return "token expired"
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return "token not valid yet"
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return "issuer mismatch"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "signature invalid"
	case errors.Is(err, jwt.ErrTokenMalformed):
		return "malformed token"
	default:
		return "signature or claim validation failed"
	}
}

func audienceContains(raw interface{}, want string) bool {
	switch v := raw.(type) {
	case string:
		return v == want
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == want {
				return true
			}
		}
	}
	return false
}

func stringClaim(claims jwt.MapClaims, name string) string {
	if name == "" {
		return ""
	}
	if s, ok := claims[name].(string); ok {
		return s
	}
	return ""
}

func stringSliceClaim(claims jwt.MapClaims, name string) []string {
	if name == "" {
		return []string{}
	}
	switch v := claims[name].(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	default:
		return []string{}
	}
}

func parseScopes(raw interface{}) []string {
	s, ok := raw.(string)
	if !ok {
		return []string{}
	}
	return strings.Fields(s)
}

func missingScopes(have, required []string) []string {
	set := map[string]bool{}
	for _, s := range have {
		set[s] = true
	}
	var missing []string
	for _, r := range required {
		if !set[r] {
			missing = append(missing, r)
		}
	}
	return missing
}

func anyIntersect(a, b []string) bool {
	set := map[string]bool{}
	for _, s := range a {
		set[s] = true
	}
	for _, s := range b {
		if set[s] {
			return true
		}
	}
	return false
}
