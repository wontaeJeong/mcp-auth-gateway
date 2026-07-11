package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestJWKRejectsMalformedRSAValuesWithoutPanicking(t *testing.T) {
	validKey := mustRSAKey(t)
	validModulus := base64.RawURLEncoding.EncodeToString(validKey.N.Bytes())
	validExponent := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
	tests := []struct {
		name string
		jwk  jwk
	}{
		{
			name: "oversized exponent",
			jwk: jwk{
				N: validModulus,
				E: base64.RawURLEncoding.EncodeToString(make([]byte, 9)),
			},
		},
		{
			name: "empty modulus",
			jwk:  jwk{N: "", E: validExponent},
		},
		{
			name: "even exponent",
			jwk: jwk{
				N: validModulus,
				E: base64.RawURLEncoding.EncodeToString([]byte{2}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("toRSAPublicKey() panicked: %v", recovered)
				}
			}()
			if _, err := tt.jwk.toRSAPublicKey(); err == nil {
				t.Fatal("toRSAPublicKey() error = nil, want malformed key rejection")
			}
		})
	}
}

func TestRefreshCoalescesConcurrentCalls(t *testing.T) {
	key := mustRSAKey(t)
	var discoveryRequests atomic.Int32
	var jwksRequests atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/discovery":
			discoveryRequests.Add(1)
			once.Do(func() { close(started) })
			<-release
			_ = json.NewEncoder(w).Encode(discoveryDocument{
				Issuer: provider.URL, JWKSURI: provider.URL + "/jwks",
			})
		case "/jwks":
			jwksRequests.Add(1)
			_ = json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{rsaJWK("active", &key.PublicKey)}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)

	cache := NewKeyCache(provider.URL+"/discovery", provider.URL, time.Minute, provider.Client())
	const callers = 16
	errs := make(chan error, callers)
	for range callers {
		go func() { errs <- cache.Refresh(context.Background()) }()
	}
	<-started
	time.Sleep(25 * time.Millisecond)
	close(release)
	for range callers {
		if err := <-errs; err != nil {
			t.Fatalf("Refresh() error = %v", err)
		}
	}

	if got := discoveryRequests.Load(); got != 1 {
		t.Fatalf("discovery requests = %d, want 1 coalesced request", got)
	}
	if got := jwksRequests.Load(); got != 1 {
		t.Fatalf("JWKS requests = %d, want 1 coalesced request", got)
	}
}

func TestRefreshContinuesAfterLeaderCancellation(t *testing.T) {
	key := mustRSAKey(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var discoveryRequests atomic.Int32

	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/discovery":
			discoveryRequests.Add(1)
			once.Do(func() { close(started) })
			<-release
			_ = json.NewEncoder(w).Encode(discoveryDocument{
				Issuer: provider.URL, JWKSURI: provider.URL + "/jwks",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{rsaJWK("active", &key.PublicKey)}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)

	cache := NewKeyCache(provider.URL+"/discovery", provider.URL, time.Minute, provider.Client())
	leaderContext, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() { leaderErr <- cache.Refresh(leaderContext) }()
	<-started
	preCanceled, cancelPreCanceled := context.WithCancel(context.Background())
	cancelPreCanceled()
	if err := cache.Refresh(preCanceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled Refresh() error = %v, want context cancellation", err)
	}
	waiterErr := make(chan error, 1)
	go func() { waiterErr <- cache.Refresh(context.Background()) }()
	time.Sleep(10 * time.Millisecond)
	cancelLeader()
	if err := <-leaderErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader Refresh() error = %v, want context cancellation", err)
	}
	close(release)
	if err := <-waiterErr; err != nil {
		t.Fatalf("waiter Refresh() error = %v, want shared refresh success", err)
	}
	if got := discoveryRequests.Load(); got != 1 {
		t.Fatalf("discovery requests = %d, want 1 shared request", got)
	}
}

func TestUnknownKIDNegativeCacheOnlyFollowsSuccessfulRefresh(t *testing.T) {
	key := mustRSAKey(t)
	var mu sync.Mutex
	jwksStatus := http.StatusOK
	var jwksRequests int

	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/discovery":
			_ = json.NewEncoder(w).Encode(discoveryDocument{
				Issuer: provider.URL, JWKSURI: provider.URL + "/jwks",
			})
		case "/jwks":
			mu.Lock()
			jwksRequests++
			status := jwksStatus
			mu.Unlock()
			if status != http.StatusOK {
				http.Error(w, "unavailable", status)
				return
			}
			_ = json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{rsaJWK("active", &key.PublicKey)}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)

	cache := NewKeyCache(provider.URL+"/discovery", provider.URL, time.Minute, provider.Client())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("initial Refresh() error = %v", err)
	}
	if _, err := cache.keyByID(context.Background(), "unknown-after-success"); err == nil {
		t.Fatal("keyByID(unknown-after-success) error = nil")
	}
	if _, err := cache.keyByID(context.Background(), "unknown-after-success"); err == nil {
		t.Fatal("second keyByID(unknown-after-success) error = nil")
	}
	if got := currentJWKSRequests(&mu, &jwksRequests); got != 2 {
		t.Fatalf("JWKS requests after cached miss = %d, want 2", got)
	}
	if _, err := cache.keyByID(context.Background(), "different-unknown-during-cooldown"); err == nil {
		t.Fatal("keyByID(different-unknown-during-cooldown) error = nil")
	}
	if got := currentJWKSRequests(&mu, &jwksRequests); got != 2 {
		t.Fatalf("JWKS requests during unknown-KID cooldown = %d, want 2", got)
	}

	cache.mu.Lock()
	cache.unknownRefreshAfter = time.Time{}
	cache.mu.Unlock()
	mu.Lock()
	jwksStatus = http.StatusServiceUnavailable
	mu.Unlock()
	if _, err := cache.keyByID(context.Background(), "unknown-after-failure"); err == nil {
		t.Fatal("keyByID(unknown-after-failure) error = nil")
	}
	if _, err := cache.keyByID(context.Background(), "different-unknown-after-failure"); err == nil {
		t.Fatal("keyByID(different-unknown-after-failure) error = nil")
	}
	if got := currentJWKSRequests(&mu, &jwksRequests); got != 3 {
		t.Fatalf("JWKS requests during refresh-failure backoff = %d, want 3", got)
	}
	cache.mu.Lock()
	cache.refreshRetryAfter = time.Time{}
	cache.mu.Unlock()
	mu.Lock()
	jwksStatus = http.StatusOK
	mu.Unlock()
	if _, err := cache.keyByID(context.Background(), "unknown-after-failure"); err == nil {
		t.Fatal("second keyByID(unknown-after-failure) error = nil")
	}
	if got := currentJWKSRequests(&mu, &jwksRequests); got != 4 {
		t.Fatalf("JWKS requests after failed refresh retry = %d, want 4", got)
	}
}

func TestConditionalReloadSkipsSupersededGeneration(t *testing.T) {
	key := mustRSAKey(t)
	var jwksRequests atomic.Int32
	provider := newStaticProvider(t, func(string) jwkSet {
		jwksRequests.Add(1)
		return jwkSet{Keys: []jwk{rsaJWK("active", &key.PublicKey)}}
	})
	cache := NewKeyCache(provider.URL+"/discovery", provider.URL, time.Minute, provider.Client())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("initial Refresh() error = %v", err)
	}
	cache.mu.RLock()
	observedGeneration := cache.generation
	cache.mu.RUnlock()
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("second Refresh() error = %v", err)
	}
	if err := cache.reloadIfUnchanged(context.Background(), observedGeneration); err != nil {
		t.Fatalf("reloadIfUnchanged() error = %v", err)
	}
	if got := jwksRequests.Load(); got != 2 {
		t.Fatalf("JWKS requests = %d, want 2 after superseded conditional reload", got)
	}
}

func TestJWKAlgorithmMustMatchTokenAlgorithm(t *testing.T) {
	key := mustRSAKey(t)
	provider := newStaticProvider(t, func(baseURL string) jwkSet {
		key := rsaJWK("active", &key.PublicKey)
		key.Alg = "RS512"
		return jwkSet{Keys: []jwk{key}}
	})
	cache := NewKeyCache(provider.URL+"/discovery", provider.URL, time.Minute, provider.Client())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if _, err := cache.keyByIDForAlgorithm(context.Background(), "active", "RS256"); err == nil {
		t.Fatal("keyByIDForAlgorithm() accepted RS256 for an RS512 JWK")
	}
	if _, err := cache.keyByIDForAlgorithm(context.Background(), "active", "RS512"); err != nil {
		t.Fatalf("keyByIDForAlgorithm() rejected matching RS512: %v", err)
	}
}

func TestRefreshRejectsCrossOriginJWKSURI(t *testing.T) {
	var jwksRequests atomic.Int32
	keyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jwksRequests.Add(1)
		_ = json.NewEncoder(w).Encode(jwkSet{})
	}))
	t.Cleanup(keyServer.Close)

	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(discoveryDocument{
			Issuer: provider.URL, JWKSURI: keyServer.URL + "/jwks",
		})
	}))
	t.Cleanup(provider.Close)

	cache := NewKeyCache(provider.URL, provider.URL, time.Minute, provider.Client())
	if err := cache.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() accepted a cross-origin jwks_uri")
	}
	if got := jwksRequests.Load(); got != 0 {
		t.Fatalf("cross-origin JWKS endpoint received %d requests, want 0", got)
	}
}

func TestRefreshRejectsCrossOriginRedirect(t *testing.T) {
	var redirectedRequests atomic.Int32
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedRequests.Add(1)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	t.Cleanup(redirectTarget.Close)

	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	t.Cleanup(provider.Close)

	cache := NewKeyCache(provider.URL, provider.URL, time.Minute, provider.Client())
	if err := cache.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() followed a cross-origin discovery redirect")
	}
	if got := redirectedRequests.Load(); got != 0 {
		t.Fatalf("cross-origin redirect target received %d requests, want 0", got)
	}
}

func TestLastKnownGoodKeyHasBoundedStaleLifetime(t *testing.T) {
	key := mustRSAKey(t)
	var fail atomic.Bool
	provider := newStaticProvider(t, func(baseURL string) jwkSet {
		if fail.Load() {
			return jwkSet{}
		}
		return jwkSet{Keys: []jwk{rsaJWK("active", &key.PublicKey)}}
	})
	cache := NewKeyCache(provider.URL+"/discovery", provider.URL, time.Minute, provider.Client())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("initial Refresh() error = %v", err)
	}
	cache.mu.Lock()
	cache.fetchedAt = time.Now().Add(-cache.ttl - maxStaleIfError - time.Minute)
	cache.mu.Unlock()
	fail.Store(true)
	if _, err := cache.keyByID(context.Background(), "active"); err == nil {
		t.Fatal("keyByID(active) accepted a key beyond the stale-if-error bound")
	}
	if cache.Ready() {
		t.Fatal("Ready() = true for keys beyond the stale-if-error bound")
	}
}

func TestRefreshFailureCrossingStaleDeadlineRejectsKey(t *testing.T) {
	key := mustRSAKey(t)
	var fail atomic.Bool
	provider := newStaticProvider(t, func(string) jwkSet {
		if fail.Load() {
			time.Sleep(30 * time.Millisecond)
			return jwkSet{}
		}
		return jwkSet{Keys: []jwk{rsaJWK("active", &key.PublicKey)}}
	})
	cache := NewKeyCache(provider.URL+"/discovery", provider.URL, time.Minute, provider.Client())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("initial Refresh() error = %v", err)
	}
	cache.mu.Lock()
	cache.fetchedAt = time.Now().Add(-cache.ttl - maxStaleIfError + 20*time.Millisecond)
	cache.mu.Unlock()
	fail.Store(true)
	if _, err := cache.keyByID(context.Background(), "active"); err == nil {
		t.Fatal("keyByID(active) accepted a key after refresh crossed the stale deadline")
	}
}

func TestReadyUsesStaleGraceOnlyAfterRefreshFailure(t *testing.T) {
	key := mustRSAKey(t)
	var fail atomic.Bool
	provider := newStaticProvider(t, func(string) jwkSet {
		if fail.Load() {
			return jwkSet{}
		}
		return jwkSet{Keys: []jwk{rsaJWK("active", &key.PublicKey)}}
	})
	cache := NewKeyCache(provider.URL+"/discovery", provider.URL, time.Minute, provider.Client())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("initial Refresh() error = %v", err)
	}
	cache.mu.Lock()
	cache.fetchedAt = time.Now().Add(-cache.ttl - time.Second)
	cache.mu.Unlock()
	if cache.Ready() {
		t.Fatal("Ready() = true for expired keys before a failed refresh")
	}
	fail.Store(true)
	if err := cache.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() error = nil during provider failure")
	}
	if !cache.Ready() {
		t.Fatal("Ready() = false during bounded stale-if-error grace")
	}
}

func TestDirectRefreshHonorsFailureBackoff(t *testing.T) {
	key := mustRSAKey(t)
	var fail atomic.Bool
	var jwksRequests atomic.Int32
	provider := newStaticProvider(t, func(string) jwkSet {
		jwksRequests.Add(1)
		if fail.Load() {
			return jwkSet{}
		}
		return jwkSet{Keys: []jwk{rsaJWK("active", &key.PublicKey)}}
	})
	cache := NewKeyCache(provider.URL+"/discovery", provider.URL, time.Minute, provider.Client())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("initial Refresh() error = %v", err)
	}
	fail.Store(true)
	if err := cache.Refresh(context.Background()); err == nil {
		t.Fatal("Refresh() error = nil during provider failure")
	}
	preCanceled, cancelPreCanceled := context.WithCancel(context.Background())
	cancelPreCanceled()
	if err := cache.Refresh(preCanceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled Refresh() during backoff error = %v, want context cancellation", err)
	}
	if err := cache.Refresh(context.Background()); err == nil {
		t.Fatal("second Refresh() error = nil during failure backoff")
	}
	if got := jwksRequests.Load(); got != 2 {
		t.Fatalf("JWKS requests = %d, want 2 with direct refresh backoff", got)
	}
}

func TestUnknownKIDCacheIsMemoryBounded(t *testing.T) {
	cache := NewKeyCache("http://unused.example/discovery", "", time.Minute, nil)
	now := time.Now()
	for i := 0; i < maxUnknownKIDs+10; i++ {
		cache.rememberUnknownKID(fmt.Sprintf("kid-%d", i), now)
	}

	cache.mu.RLock()
	defer cache.mu.RUnlock()
	if got := len(cache.unknownKIDs); got != maxUnknownKIDs {
		t.Fatalf("unknown KID cache size = %d, want %d", got, maxUnknownKIDs)
	}
}

func TestRefreshFailureRetainsLastKnownGoodKey(t *testing.T) {
	key := mustRSAKey(t)
	var fail atomic.Bool
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/discovery":
			_ = json.NewEncoder(w).Encode(discoveryDocument{
				Issuer: provider.URL, JWKSURI: provider.URL + "/jwks",
			})
		case "/jwks":
			if fail.Load() {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{rsaJWK("active", &key.PublicKey)}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)

	cache := NewKeyCache(provider.URL+"/discovery", provider.URL, time.Nanosecond, provider.Client())
	if err := cache.Refresh(context.Background()); err != nil {
		t.Fatalf("initial Refresh() error = %v", err)
	}
	fail.Store(true)
	got, err := cache.keyByID(context.Background(), "active")
	if err != nil {
		t.Fatalf("keyByID(active) error = %v, want last-known-good key", err)
	}
	if got.N.Cmp(key.N) != 0 || got.E != key.E {
		t.Fatal("keyByID(active) did not return the last-known-good key")
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	return key
}

func rsaJWK(kid string, key *rsa.PublicKey) jwk {
	return jwk{
		Kty: "RSA",
		Kid: kid,
		Alg: "RS256",
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
	}
}

func currentJWKSRequests(mu *sync.Mutex, count *int) int {
	mu.Lock()
	defer mu.Unlock()
	return *count
}

func newStaticProvider(t *testing.T, keys func(string) jwkSet) *httptest.Server {
	t.Helper()
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/discovery":
			_ = json.NewEncoder(w).Encode(discoveryDocument{
				Issuer: provider.URL, JWKSURI: provider.URL + "/jwks",
			})
		case "/jwks":
			set := keys(provider.URL)
			if len(set.Keys) == 0 {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(set)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)
	return provider
}
