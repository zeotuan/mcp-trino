package trino

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/tuannvm/mcp-trino/internal/config"
)

type externalAuthTokenManager struct {
	cachePath    string
	httpClient   *http.Client
	openBrowser  func(string) error
	pollInterval time.Duration
	pollTimeout  time.Duration
	store        externalAuthTokenStore
	poller       externalAuthTokenPoller

	mu             sync.Mutex
	token          string
	tokenExpiresAt time.Time
	generation     uint64 // incremented on each InvalidateToken to fence stale writes

	inFlight *tokenAcquisition
}

type tokenAcquisition struct {
	done  chan struct{}
	token string
	err   error
}

func createBearerTokenManager(cfg *config.TrinoConfig) bearerTokenManager {
	if cfg.AuthMode != config.AuthModeExternalAuth {
		return nil
	}

	cachePath := externalTokenCachePath(cfg)
	httpClient := newExternalAuthHTTPClient(&http.Client{Timeout: 30 * time.Second})

	return &externalAuthTokenManager{
		cachePath:    cachePath,
		httpClient:   httpClient,
		openBrowser:  openBrowserDefault,
		pollInterval: externalAuthDefaultPollInterval,
		pollTimeout:  externalAuthDefaultPollTimeout,
		store:        newExternalAuthFileTokenStore(cachePath),
		poller:       newExternalAuthHTTPPoller(httpClient, externalAuthDefaultPollInterval, externalAuthDefaultPollTimeout),
	}
}

func (m *externalAuthTokenManager) CurrentToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.cachedTokenLocked()
}

func (m *externalAuthTokenManager) currentStore() externalAuthTokenStore {
	if m.store != nil {
		return m.store
	}
	return newExternalAuthFileTokenStore(m.cachePath)
}

func (m *externalAuthTokenManager) currentPoller() externalAuthTokenPoller {
	if m.poller != nil {
		return m.poller
	}

	httpClient := m.httpClient
	if httpClient == nil {
		httpClient = newExternalAuthHTTPClient(&http.Client{Timeout: 30 * time.Second})
	}

	pollInterval := m.pollInterval
	if pollInterval == 0 {
		pollInterval = externalAuthDefaultPollInterval
	}

	pollTimeout := m.pollTimeout
	if pollTimeout == 0 {
		pollTimeout = externalAuthDefaultPollTimeout
	}

	return newExternalAuthHTTPPoller(httpClient, pollInterval, pollTimeout)
}

// cachedTokenLocked returns the in-memory or disk-cached token.
// Must be called with m.mu held.
func (m *externalAuthTokenManager) cachedTokenLocked() string {
	if m.token != "" {
		if tokenExpired(m.tokenExpiresAt) {
			m.token = ""
			m.tokenExpiresAt = time.Time{}
		} else {
			return m.token
		}
	}

	if cache := m.loadCache(); cache != nil {
		m.token = cache.AccessToken
		m.tokenExpiresAt = cache.ExpiresAt
	}
	return m.token
}

func (m *externalAuthTokenManager) AcquireToken(ctx context.Context, challenge bearerAuthChallenge, rejectedToken string) (string, error) {
	m.mu.Lock()

	// Return the cached token if it already differs from the one that was rejected.
	// This avoids a redundant browser popup when another goroutine refreshed first.
	if token := m.cachedTokenLocked(); token != "" && token != rejectedToken {
		m.mu.Unlock()
		return token, nil
	}

	if m.inFlight != nil {
		inFlight := m.inFlight
		m.mu.Unlock()
		select {
		case <-inFlight.done:
		case <-ctx.Done():
			return "", ctx.Err()
		}
		return inFlight.token, inFlight.err
	}

	if challenge.TokenURL == "" {
		m.mu.Unlock()
		return "", &externalAuthError{Kind: errMissingExternalAuthTokenURL, Message: errMissingExternalAuthTokenURL.Error()}
	}

	gen := m.generation
	inFlight := &tokenAcquisition{done: make(chan struct{})}
	m.inFlight = inFlight
	m.mu.Unlock()

	token, err := m.acquireFreshToken(ctx, challenge)

	m.mu.Lock()
	// Keep a freshly acquired token unless newer state already replaced it.
	// A racing invalidation only clears prior state; if the manager is still
	// empty here, retaining the fresh token avoids forcing another browser flow.
	if err == nil && (m.generation == gen || m.token == "") {
		expiresAt, _ := tokenExpiry(token)
		m.token = token
		m.tokenExpiresAt = expiresAt
		m.saveCache(&externalTokenCache{
			AccessToken: token,
			ExpiresAt:   expiresAt,
		})
	}
	inFlight.token = token
	inFlight.err = err
	close(inFlight.done)
	if m.inFlight == inFlight {
		m.inFlight = nil
	}
	m.mu.Unlock()

	return token, err
}

func (m *externalAuthTokenManager) InvalidateToken() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.token = ""
	m.tokenExpiresAt = time.Time{}
	m.generation++
	m.currentStore().Clear()
}

func (m *externalAuthTokenManager) waitForToken(ctx context.Context, initialTokenURL string) (string, error) {
	return m.currentPoller().WaitForToken(ctx, initialTokenURL)
}

func (m *externalAuthTokenManager) cleanupTokenURL(parentCtx context.Context, tokenURL string) {
	m.currentPoller().CleanupTokenURL(parentCtx, tokenURL)
}

func (m *externalAuthTokenManager) acquireFreshToken(ctx context.Context, challenge bearerAuthChallenge) (string, error) {
	if challenge.RedirectURL != "" {
		fmt.Fprintln(os.Stderr, "\nOpening browser for Trino authentication...")
		fmt.Fprintln(os.Stderr, challenge.RedirectURL)
		fmt.Fprintln(os.Stderr)
		if err := m.openBrowser(challenge.RedirectURL); err != nil {
			log.Printf("WARNING: Could not open browser: %v", err)
			fmt.Fprintln(os.Stderr, "Could not open browser automatically. Open this URL manually:")
			fmt.Fprintln(os.Stderr, challenge.RedirectURL)
			fmt.Fprintln(os.Stderr)
		}
	} else if challenge.TokenURL != "" {
		fmt.Fprintln(os.Stderr, "\nWaiting for Trino authentication token...")
		fmt.Fprintln(os.Stderr, "Trino did not provide a browser redirect URL in the authentication challenge.")
		fmt.Fprintln(os.Stderr, "If another environment initiated the login flow, complete it there; otherwise this request may time out.")
		fmt.Fprintln(os.Stderr)
	}

	return m.waitForToken(ctx, challenge.TokenURL)
}

func openBrowserDefault(targetURL string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL).Start()
	case "darwin":
		return exec.Command("open", targetURL).Start()
	default:
		return exec.Command("xdg-open", targetURL).Start()
	}
}

func newExternalAuthHTTPClient(base *http.Client) *http.Client {
	if base == nil {
		base = &http.Client{}
	}

	client := *base
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client
}

func (m *externalAuthTokenManager) loadCache() *externalTokenCache {
	return m.currentStore().Load()
}

func (m *externalAuthTokenManager) saveCache(cache *externalTokenCache) {
	m.currentStore().Save(cache)
}
