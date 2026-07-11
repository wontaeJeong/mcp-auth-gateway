package identity

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/samsungds/mcp-auth-gateway/internal/auth"
	"github.com/samsungds/mcp-auth-gateway/internal/config"
)

func TestNewSignerRequiresAtLeast32RawSecretBytes(t *testing.T) {
	cfg := config.InternalIdentityConfig{
		Issuer: "mcp-auth-gateway", TTL: config.Duration(time.Minute), SigningAlg: "HS256",
	}
	if _, err := NewSigner(cfg, strings.Repeat("a", 31)); err == nil {
		t.Fatal("NewSigner() accepted a 31-byte secret")
	}
	if _, err := NewSigner(cfg, strings.Repeat("a", 32)); err != nil {
		t.Fatalf("NewSigner() rejected a 32-byte secret: %v", err)
	}
	if _, err := NewSigner(cfg, strings.Repeat("가", 11)); err != nil {
		t.Fatalf("NewSigner() rejected a 33-byte UTF-8 secret: %v", err)
	}
}

func TestNewSignerRejectsUnboundedTTL(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
	}{
		{name: "negative", ttl: -time.Second},
		{name: "over maximum", ttl: maxInternalIdentityTTL + time.Nanosecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.InternalIdentityConfig{
				Issuer: "mcp-auth-gateway", TTL: config.Duration(tt.ttl), SigningAlg: "HS256",
			}
			if _, err := NewSigner(cfg, strings.Repeat("a", 32)); err == nil {
				t.Fatalf("NewSigner() accepted TTL %s", tt.ttl)
			}
		})
	}
}

func TestSignIncludesNotBeforeClaim(t *testing.T) {
	fixedNow := time.Now().Truncate(time.Second)
	signer, err := NewSigner(config.InternalIdentityConfig{
		Issuer: "mcp-auth-gateway", TTL: config.Duration(time.Minute), SigningAlg: "HS256",
	}, strings.Repeat("a", 32))
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	signer.now = func() time.Time { return fixedNow }
	raw, err := signer.Sign(&auth.Identity{Subject: "subject", LoginID: "alice"}, "backend", "request")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (interface{}, error) {
		return []byte(strings.Repeat("a", 32)), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		t.Fatalf("ParseWithClaims() error = %v", err)
	}
	if got := int64(claims["nbf"].(float64)); got != fixedNow.Unix() {
		t.Fatalf("nbf = %d, want %d", got, fixedNow.Unix())
	}
}

func TestSignOmitsEmptyOptionalIdentityClaims(t *testing.T) {
	signer, err := NewSigner(config.InternalIdentityConfig{
		Issuer: "mcp-auth-gateway", TTL: config.Duration(time.Minute), SigningAlg: "HS256",
	}, strings.Repeat("a", 32))
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	raw, err := signer.Sign(&auth.Identity{Subject: "subject", LoginID: "alice"}, "backend", "request")
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (interface{}, error) {
		return []byte(strings.Repeat("a", 32)), nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		t.Fatalf("ParseWithClaims() error = %v", err)
	}
	for _, claim := range []string{"username", "email"} {
		if value, present := claims[claim]; present {
			t.Fatalf("optional claim %q = %#v, want omitted", claim, value)
		}
	}
}
