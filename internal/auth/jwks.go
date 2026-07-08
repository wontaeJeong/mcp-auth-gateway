package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// discoveryDocument is the subset of the OIDC discovery response we need.
type discoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// jwk is a single JSON Web Key (RSA only).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// KeyCache fetches and caches an OIDC provider's JWKS, refreshing on TTL expiry
// or when a requested key ID is unknown (handling key rotation).
type KeyCache struct {
	httpClient *http.Client
	ttl        time.Duration

	discoveryURL string
	expectIssuer string

	mu        sync.RWMutex
	jwksURI   string
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
	ready     bool
}

// NewKeyCache creates a KeyCache. It performs no network I/O until Refresh or
// KeyFunc is called.
func NewKeyCache(discoveryURL, expectIssuer string, ttl time.Duration, client *http.Client) *KeyCache {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &KeyCache{
		httpClient:   client,
		ttl:          ttl,
		discoveryURL: discoveryURL,
		expectIssuer: expectIssuer,
		keys:         map[string]*rsa.PublicKey{},
	}
}

// Ready reports whether the cache has successfully loaded keys at least once.
func (c *KeyCache) Ready() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ready && len(c.keys) > 0
}

// Refresh forces a discovery + JWKS reload.
func (c *KeyCache) Refresh(ctx context.Context) error {
	return c.reload(ctx)
}

func (c *KeyCache) reload(ctx context.Context) error {
	doc, err := c.fetchDiscovery(ctx)
	if err != nil {
		return err
	}
	if c.expectIssuer != "" && doc.Issuer != c.expectIssuer {
		return fmt.Errorf("discovery issuer %q does not match configured issuer %q", doc.Issuer, c.expectIssuer)
	}
	if doc.JWKSURI == "" {
		return fmt.Errorf("discovery document has no jwks_uri")
	}
	keys, err := c.fetchJWKS(ctx, doc.JWKSURI)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("jwks contained no usable keys")
	}
	c.mu.Lock()
	c.jwksURI = doc.JWKSURI
	c.keys = keys
	c.fetchedAt = time.Now()
	c.ready = true
	c.mu.Unlock()
	return nil
}

func (c *KeyCache) fetchDiscovery(ctx context.Context) (*discoveryDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var doc discoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse discovery: %w", err)
	}
	return &doc, nil
}

func (c *KeyCache) fetchJWKS(ctx context.Context, uri string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := k.toRSAPublicKey()
		if err != nil {
			continue
		}
		out[k.Kid] = pub
	}
	return out, nil
}

func (k jwk) toRSAPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	// Exponent is a big-endian unsigned integer; pad to 8 bytes for uint64.
	var ePadded [8]byte
	copy(ePadded[8-len(eBytes):], eBytes)
	e := int(binary.BigEndian.Uint64(ePadded[:]))
	if e == 0 {
		return nil, fmt.Errorf("invalid zero exponent")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// keyByID returns the public key for kid, refreshing the cache if the key is
// unknown or the TTL has expired.
func (c *KeyCache) keyByID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	stale := time.Since(c.fetchedAt) > c.ttl
	ready := c.ready
	c.mu.RUnlock()

	if ok && !stale {
		return key, nil
	}
	if !ready || !ok || stale {
		if err := c.reload(ctx); err != nil {
			// If we already had the key cached, tolerate refresh failure.
			if ok {
				return key, nil
			}
			return nil, err
		}
	}
	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no signing key found for kid %q", kid)
	}
	return key, nil
}
