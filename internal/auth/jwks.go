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
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	maxUnknownKIDs        = 128
	maxUnknownKIDTTL      = 30 * time.Second
	maxStaleIfError       = time.Hour
	refreshFailureBackoff = 5 * time.Second
	sharedRefreshTimeout  = 10 * time.Second
	maxProviderBody       = 1 << 20
	minimumRSAModulus     = 2048
	maximumRedirectCount  = 10
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

type cachedKey struct {
	publicKey *rsa.PublicKey
	algorithm string
}

// KeyCache fetches and caches an OIDC provider's JWKS, refreshing on TTL expiry
// or when a requested key ID is unknown (handling key rotation).
type KeyCache struct {
	httpClient *http.Client
	ttl        time.Duration

	discoveryURL string
	expectIssuer string

	mu                  sync.RWMutex
	jwksURI             string
	keys                map[string]cachedKey
	unknownKIDs         map[string]time.Time
	unknownRefreshAfter time.Time
	refreshRetryAfter   time.Time
	refreshRetryErr     error
	staleIfErrorUntil   time.Time
	fetchedAt           time.Time
	generation          uint64
	ready               bool

	refreshMu sync.Mutex
	refresh   *refreshCall
}

type refreshCall struct {
	done chan struct{}
	err  error
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
		keys:         map[string]cachedKey{},
		unknownKIDs:  map[string]time.Time{},
	}
}

// Ready reports whether the cache has successfully loaded keys at least once.
func (c *KeyCache) Ready() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	fresh := now.Before(c.fetchedAt.Add(c.ttl))
	staleIfError := now.Before(c.staleIfErrorUntil)
	return c.ready && len(c.keys) > 0 && (fresh || staleIfError)
}

// Refresh requests a discovery + JWKS reload.
func (c *KeyCache) Refresh(ctx context.Context) error {
	return c.reload(ctx)
}

func (c *KeyCache) reload(ctx context.Context) error {
	return c.reloadIfCurrent(ctx, 0, false)
}

func (c *KeyCache) reloadIfUnchanged(ctx context.Context, generation uint64) error {
	return c.reloadIfCurrent(ctx, generation, true)
}

func (c *KeyCache) reloadIfCurrent(ctx context.Context, generation uint64, conditional bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.refreshMu.Lock()
	if active := c.refresh; active != nil {
		c.refreshMu.Unlock()
		select {
		case <-active.done:
			return active.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.mu.RLock()
	unchanged := c.generation == generation
	retryAfter := c.refreshRetryAfter
	retryErr := c.refreshRetryErr
	c.mu.RUnlock()
	if conditional && !unchanged {
		c.refreshMu.Unlock()
		return nil
	}
	if time.Now().Before(retryAfter) {
		c.refreshMu.Unlock()
		return retryErr
	}
	active := &refreshCall{done: make(chan struct{})}
	c.refresh = active
	c.refreshMu.Unlock()

	go c.executeRefresh(active)
	select {
	case <-active.done:
		return active.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *KeyCache) executeRefresh(active *refreshCall) {
	timeout := c.httpClient.Timeout
	if timeout <= 0 {
		timeout = sharedRefreshTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	err := c.load(ctx)
	cancel()

	now := time.Now()
	c.mu.Lock()
	if err == nil {
		c.refreshRetryAfter = time.Time{}
		c.refreshRetryErr = nil
		c.staleIfErrorUntil = time.Time{}
	} else {
		c.refreshRetryAfter = now.Add(refreshFailureBackoff)
		c.refreshRetryErr = err
		freshUntil := c.fetchedAt.Add(c.ttl)
		staleDeadline := freshUntil.Add(maxStaleIfError)
		if c.ready && len(c.keys) > 0 && !now.Before(freshUntil) && now.Before(staleDeadline) {
			c.staleIfErrorUntil = staleDeadline
		} else {
			c.staleIfErrorUntil = time.Time{}
		}
	}
	c.mu.Unlock()
	c.refreshMu.Lock()
	active.err = err
	c.refresh = nil
	close(active.done)
	c.refreshMu.Unlock()
}

func (c *KeyCache) load(ctx context.Context) error {
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
	if err := validateProviderURL(doc.JWKSURI); err != nil {
		return fmt.Errorf("discovery jwks_uri: %w", err)
	}
	if !sameProviderOrigin(c.discoveryURL, doc.JWKSURI) {
		return fmt.Errorf("discovery jwks_uri must use the discovery URL origin")
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
	c.unknownKIDs = map[string]time.Time{}
	c.fetchedAt = time.Now()
	c.generation++
	c.ready = true
	c.staleIfErrorUntil = time.Time{}
	c.mu.Unlock()
	return nil
}

func (c *KeyCache) fetchDiscovery(ctx context.Context) (*discoveryDocument, error) {
	if err := validateProviderURL(c.discoveryURL); err != nil {
		return nil, fmt.Errorf("discovery URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.doProviderRequest(req)
	if err != nil {
		return nil, fmt.Errorf("fetch discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}
	body, err := readProviderBody(resp.Body)
	if err != nil {
		return nil, err
	}
	var doc discoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse discovery: %w", err)
	}
	return &doc, nil
}

func (c *KeyCache) fetchJWKS(ctx context.Context, uri string) (map[string]cachedKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.doProviderRequest(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks returned status %d", resp.StatusCode)
	}
	body, err := readProviderBody(resp.Body)
	if err != nil {
		return nil, err
	}
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	out := map[string]cachedKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || strings.TrimSpace(k.Kid) == "" ||
			(k.Use != "" && k.Use != "sig") || !supportedRSAAlgorithm(k.Alg) {
			continue
		}
		pub, err := k.toRSAPublicKey()
		if err != nil {
			continue
		}
		if _, duplicate := out[k.Kid]; duplicate {
			return nil, fmt.Errorf("jwks contains duplicate kid %q", k.Kid)
		}
		out[k.Kid] = cachedKey{publicKey: pub, algorithm: k.Alg}
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
	if n.Sign() <= 0 || n.BitLen() < minimumRSAModulus {
		return nil, fmt.Errorf("invalid RSA modulus")
	}
	// Exponent is a big-endian unsigned integer; pad to 8 bytes for uint64.
	if len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, fmt.Errorf("invalid RSA exponent length")
	}
	var ePadded [8]byte
	copy(ePadded[8-len(eBytes):], eBytes)
	e64 := binary.BigEndian.Uint64(ePadded[:])
	maxInt := uint64(^uint(0) >> 1)
	if e64 > maxInt || e64 < 3 || e64%2 == 0 {
		return nil, fmt.Errorf("invalid RSA exponent")
	}
	e := int(e64)
	return &rsa.PublicKey{N: n, E: e}, nil
}

// keyByID returns the public key for kid, refreshing the cache if the key is
// unknown or the TTL has expired.
func (c *KeyCache) keyByID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	return c.keyByIDForAlgorithm(ctx, kid, "")
}

func (c *KeyCache) keyByIDForAlgorithm(ctx context.Context, kid, tokenAlgorithm string) (*rsa.PublicKey, error) {
	if strings.TrimSpace(kid) == "" {
		return nil, fmt.Errorf("token header has no signing key ID")
	}
	now := time.Now()
	c.mu.RLock()
	key, ok := c.keys[kid]
	stale := now.Sub(c.fetchedAt) > c.ttl
	ready := c.ready
	unknownUntil, knownMissing := c.unknownKIDs[kid]
	unknownRefreshAfter := c.unknownRefreshAfter
	generation := c.generation
	c.mu.RUnlock()

	if ok && !stale {
		return key.forAlgorithm(tokenAlgorithm)
	}
	if !ok && knownMissing && now.Before(unknownUntil) {
		return nil, fmt.Errorf("no signing key found for kid %q", kid)
	}
	if !ok && now.Before(unknownRefreshAfter) {
		return nil, fmt.Errorf("no signing key found for kid %q", kid)
	}
	if !ready || !ok || stale {
		if err := c.reloadIfUnchanged(ctx, generation); err != nil {
			// If we already had the key cached, tolerate refresh failure.
			if ok {
				c.mu.RLock()
				withinStaleGrace := time.Now().Before(c.staleIfErrorUntil)
				c.mu.RUnlock()
				if withinStaleGrace {
					return key.forAlgorithm(tokenAlgorithm)
				}
			}
			return nil, err
		}
	}
	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		c.rememberUnknownKID(kid, time.Now())
		return nil, fmt.Errorf("no signing key found for kid %q", kid)
	}
	return key.forAlgorithm(tokenAlgorithm)
}

func (c *KeyCache) rememberUnknownKID(kid string, now time.Time) {
	ttl := c.ttl
	if ttl <= 0 || ttl > maxUnknownKIDTTL {
		ttl = maxUnknownKIDTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for cachedKID, expiry := range c.unknownKIDs {
		if !now.Before(expiry) {
			delete(c.unknownKIDs, cachedKID)
		}
	}
	if _, exists := c.unknownKIDs[kid]; !exists && len(c.unknownKIDs) >= maxUnknownKIDs {
		var oldestKID string
		var oldestExpiry time.Time
		for cachedKID, expiry := range c.unknownKIDs {
			if oldestKID == "" || expiry.Before(oldestExpiry) {
				oldestKID = cachedKID
				oldestExpiry = expiry
			}
		}
		delete(c.unknownKIDs, oldestKID)
	}
	c.unknownKIDs[kid] = now.Add(ttl)
	c.unknownRefreshAfter = now.Add(ttl)
}

func (k cachedKey) forAlgorithm(tokenAlgorithm string) (*rsa.PublicKey, error) {
	if k.algorithm != "" && tokenAlgorithm != "" && k.algorithm != tokenAlgorithm {
		return nil, fmt.Errorf("signing key algorithm %q does not match token algorithm %q", k.algorithm, tokenAlgorithm)
	}
	return k.publicKey, nil
}

func readProviderBody(body io.Reader) ([]byte, error) {
	limited := io.LimitReader(body, maxProviderBody+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxProviderBody {
		return nil, fmt.Errorf("response body exceeds %d bytes", maxProviderBody)
	}
	return data, nil
}

func validateProviderURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || raw != strings.TrimSpace(raw) || !parsed.IsAbs() ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
		parsed.Hostname() == "" || parsed.Opaque != "" {
		return fmt.Errorf("must be an absolute http/https URL")
	}
	if parsed.User != nil || parsed.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("must not contain userinfo or fragment")
	}
	return nil
}

func (c *KeyCache) doProviderRequest(req *http.Request) (*http.Response, error) {
	client := *c.httpClient
	configuredCheckRedirect := client.CheckRedirect
	client.CheckRedirect = func(redirected *http.Request, via []*http.Request) error {
		if !sameProviderOrigin(c.discoveryURL, redirected.URL.String()) {
			return fmt.Errorf("provider redirect must remain on the discovery URL origin")
		}
		if len(via) >= maximumRedirectCount {
			return fmt.Errorf("stopped after %d redirects", maximumRedirectCount)
		}
		if configuredCheckRedirect != nil {
			return configuredCheckRedirect(redirected, via)
		}
		return nil
	}
	return client.Do(req)
}

func sameProviderOrigin(left, right string) bool {
	leftURL, leftErr := url.Parse(left)
	rightURL, rightErr := url.Parse(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	return strings.EqualFold(leftURL.Scheme, rightURL.Scheme) &&
		strings.EqualFold(normalizedHost(leftURL), normalizedHost(rightURL))
}

func normalizedHost(parsed *url.URL) string {
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		switch parsed.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return host + ":" + port
}

func supportedRSAAlgorithm(algorithm string) bool {
	switch algorithm {
	case "", "RS256", "RS384", "RS512":
		return true
	default:
		return false
	}
}
