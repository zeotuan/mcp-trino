package trino

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/tuannvm/mcp-trino/internal/config"
	"github.com/tuannvm/mcp-trino/internal/netutil"
)

const (
	trinoAuthUserAgent         = "mcp-trino-external-auth"
	externalAuthCleanupTimeout = 5 * time.Second
)

var (
	redirectServerPattern = regexp.MustCompile(`x_redirect_server="([^"]+)"`)
	tokenServerPattern    = regexp.MustCompile(`x_token_server="([^"]+)"`)
)

var (
	errMissingExternalAuthTokenURL = errors.New("missing Trino external auth token URL")
	errNoExternalAuthChallenge     = errors.New("no Trino external auth challenge found in WWW-Authenticate header")
	errNoWWWAuthenticateHeader     = errors.New("trino returned no WWW-Authenticate header")
	errExternalAuthInvalidURL      = errors.New("invalid external auth URL")
	errExternalAuthInsecureURL     = errors.New("external auth URL must use https unless host is loopback")
	errExternalAuthUntrustedURL    = errors.New("untrusted external auth URL")
	errExternalAuthPollFailed      = errors.New("trino token polling failed")
	errExternalAuthDecodeFailed    = errors.New("failed to decode Trino token response")
	errExternalAuthPollTimedOut    = errors.New("timed out waiting for Trino access token")
)

type bearerTokenManager interface {
	CurrentToken() string
	// AcquireToken returns a valid token. rejectedToken is the token that was just
	// rejected; if the cache already holds a different token (another goroutine
	// refreshed), it is returned immediately without opening a browser.
	AcquireToken(ctx context.Context, challenge bearerAuthChallenge, rejectedToken string) (string, error)
	InvalidateToken()
}

type bearerAuthChallenge struct {
	RedirectURL string
	TokenURL    string
}

type externalAuthTokenManager struct {
	cachePath    string
	httpClient   *http.Client
	openBrowser  func(string) error
	pollInterval time.Duration
	pollTimeout  time.Duration

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

type externalTokenCache struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

type externalTokenPollResponse struct {
	Token   string `json:"token"`
	Error   string `json:"error"`
	NextURI string `json:"nextUri"`
}

type externalAuthError struct {
	Kind    error
	Message string
	Err     error
}

func (e *externalAuthError) Error() string {
	switch {
	case e == nil:
		return ""
	case e.Err != nil && e.Message != "":
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	case e.Err != nil:
		return e.Err.Error()
	case e.Message != "":
		return e.Message
	case e.Kind != nil:
		return e.Kind.Error()
	default:
		return ""
	}
}

func (e *externalAuthError) Unwrap() error {
	return e.Err
}

func (e *externalAuthError) Is(target error) bool {
	return target == e.Kind || (e.Err != nil && errors.Is(e.Err, target))
}

func createBearerTokenManager(cfg *config.TrinoConfig) bearerTokenManager {
	if cfg.AuthMode != config.AuthModeExternalAuth {
		return nil
	}

	return &externalAuthTokenManager{
		cachePath:    externalTokenCachePath(cfg),
		httpClient:   newExternalAuthHTTPClient(&http.Client{Timeout: 30 * time.Second}),
		openBrowser:  openBrowserDefault,
		pollInterval: 2 * time.Second,
		pollTimeout:  2 * time.Minute,
	}
}

func externalTokenCachePath(cfg *config.TrinoConfig) string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Printf("WARNING: Could not determine home directory; external auth token caching disabled")
		return ""
	}

	hash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%s|external", cfg.Scheme, cfg.Host, cfg.Port, cfg.User)))
	filename := fmt.Sprintf("external-token-cache-%s.json", hex.EncodeToString(hash[:8]))
	return filepath.Join(homeDir, ".config", "trino", filename)
}

func (m *externalAuthTokenManager) CurrentToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.cachedTokenLocked()
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
	// Only persist if no InvalidateToken call raced with our acquisition.
	if err == nil && m.generation == gen {
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
	if m.cachePath != "" {
		if err := os.Remove(m.cachePath); err != nil && !os.IsNotExist(err) {
			log.Printf("WARNING: failed to remove external auth token cache: %v", err)
		}
	}
}

func parseBearerAuthChallenge(headers http.Header, requestURL *url.URL) (bearerAuthChallenge, error) {
	values := headers.Values("WWW-Authenticate")
	if len(values) == 0 {
		return bearerAuthChallenge{}, &externalAuthError{Kind: errNoWWWAuthenticateHeader, Message: errNoWWWAuthenticateHeader.Error()}
	}

	trustedOrigin, err := normalizedOrigin(requestURL)
	if err != nil {
		return bearerAuthChallenge{}, &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: "invalid Trino request URL for external auth challenge validation",
			Err:     err,
		}
	}

	joined := strings.Join(values, ", ")

	redirectMatch := redirectServerPattern.FindStringSubmatch(joined)
	tokenMatch := tokenServerPattern.FindStringSubmatch(joined)
	if len(tokenMatch) < 2 {
		return bearerAuthChallenge{}, &externalAuthError{Kind: errNoExternalAuthChallenge, Message: errNoExternalAuthChallenge.Error()}
	}

	tokenURL, err := validateTrustedAuthURL(tokenMatch[1], trustedOrigin, "x_token_server")
	if err != nil {
		return bearerAuthChallenge{}, err
	}

	challenge := bearerAuthChallenge{
		TokenURL: tokenURL,
	}
	if len(redirectMatch) >= 2 {
		redirectURL, err := validateTrustedAuthURL(redirectMatch[1], trustedOrigin, "x_redirect_server")
		if err != nil {
			return bearerAuthChallenge{}, err
		}
		challenge.RedirectURL = redirectURL
	}
	return challenge, nil
}

func (m *externalAuthTokenManager) waitForToken(ctx context.Context, initialTokenURL string) (string, error) {
	trustedOrigin, err := normalizedOriginFromRawURL(initialTokenURL)
	if err != nil {
		return "", &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: fmt.Sprintf("invalid Trino external auth token URL %q", initialTokenURL),
			Err:     err,
		}
	}

	deadline := time.Now().Add(m.pollTimeout)
	tokenURL := initialTokenURL

	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
		if err != nil {
			return "", &externalAuthError{
				Kind:    errExternalAuthPollFailed,
				Message: "failed to create token polling request",
				Err:     err,
			}
		}
		req.Header.Set("User-Agent", trinoAuthUserAgent)

		resp, err := m.httpClient.Do(req)
		if err != nil {
			return "", &externalAuthError{
				Kind:    errExternalAuthPollFailed,
				Message: "failed to poll Trino token endpoint",
				Err:     err,
			}
		}

		var poll externalTokenPollResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&poll)
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			if decodeErr == nil && poll.Error != "" {
				return "", &externalAuthError{
					Kind:    errExternalAuthPollFailed,
					Message: fmt.Sprintf("trino token polling failed: %s", poll.Error),
				}
			}
			return "", &externalAuthError{
				Kind:    errExternalAuthPollFailed,
				Message: fmt.Sprintf("trino token polling failed with status %d", resp.StatusCode),
			}
		}
		if decodeErr != nil {
			return "", &externalAuthError{
				Kind:    errExternalAuthDecodeFailed,
				Message: errExternalAuthDecodeFailed.Error(),
				Err:     decodeErr,
			}
		}

		if poll.Token != "" {
			m.cleanupTokenURL(ctx, tokenURL)
			return poll.Token, nil
		}
		if poll.Error != "" {
			return "", &externalAuthError{
				Kind:    errExternalAuthPollFailed,
				Message: fmt.Sprintf("trino token polling failed: %s", poll.Error),
			}
		}
		if poll.NextURI != "" {
			nextTokenURL, err := validateTrustedAuthURL(poll.NextURI, trustedOrigin, "nextUri")
			if err != nil {
				return "", err
			}
			tokenURL = nextTokenURL
		}

		select {
		case <-time.After(m.pollInterval):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	return "", &externalAuthError{
		Kind:    errExternalAuthPollTimedOut,
		Message: fmt.Sprintf("timed out waiting for Trino access token after %v", m.pollTimeout),
	}
}

func (m *externalAuthTokenManager) cleanupTokenURL(parentCtx context.Context, tokenURL string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parentCtx), externalAuthCleanupTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, tokenURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", trinoAuthUserAgent)
	resp, err := m.httpClient.Do(req)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}
}

func (m *externalAuthTokenManager) acquireFreshToken(ctx context.Context, challenge bearerAuthChallenge) (string, error) {
	if challenge.RedirectURL != "" {
		fmt.Fprintln(os.Stderr, "\nOpening browser for Trino authentication...")
		fmt.Fprintln(os.Stderr, challenge.RedirectURL)
		fmt.Fprintln(os.Stderr)
		if err := m.openBrowser(challenge.RedirectURL); err != nil {
			log.Printf("WARNING: Could not open browser: %v", err)
		}
	}

	return m.waitForToken(ctx, challenge.TokenURL)
}

func (m *externalAuthTokenManager) loadCache() *externalTokenCache {
	if m.cachePath == "" {
		return nil
	}

	data, err := os.ReadFile(m.cachePath)
	if err != nil {
		return nil
	}

	var cache externalTokenCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil
	}
	if cache.AccessToken == "" {
		return nil
	}
	if cache.ExpiresAt.IsZero() {
		if expiresAt, ok := tokenExpiry(cache.AccessToken); ok {
			cache.ExpiresAt = expiresAt
		}
	}
	if !cache.ExpiresAt.IsZero() && !cache.ExpiresAt.After(time.Now()) {
		return nil
	}
	return &cache
}

func (m *externalAuthTokenManager) saveCache(cache *externalTokenCache) {
	if m.cachePath == "" || cache == nil || cache.AccessToken == "" {
		return
	}

	if cache.ExpiresAt.IsZero() {
		if expiresAt, ok := tokenExpiry(cache.AccessToken); ok {
			cache.ExpiresAt = expiresAt
		}
	}
	if tokenExpired(cache.ExpiresAt) {
		return
	}

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		log.Printf("WARNING: Failed to marshal external auth token cache: %v", err)
		return
	}

	if err := os.MkdirAll(filepath.Dir(m.cachePath), 0700); err != nil {
		log.Printf("WARNING: Failed to create external auth token cache directory: %v", err)
		return
	}
	if err := os.WriteFile(m.cachePath, data, 0600); err != nil {
		log.Printf("WARNING: Failed to write external auth token cache: %v", err)
	}
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

func normalizedOriginFromRawURL(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return normalizedOrigin(parsedURL)
}

func normalizedOrigin(candidateURL *url.URL) (string, error) {
	if candidateURL == nil {
		return "", &externalAuthError{Kind: errExternalAuthInvalidURL, Message: "missing URL"}
	}
	if !candidateURL.IsAbs() {
		return "", &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: fmt.Sprintf("URL %q is not absolute", candidateURL.String()),
		}
	}

	scheme := strings.ToLower(candidateURL.Scheme)
	host := netutil.NormalizeHostname(candidateURL.Hostname())
	if scheme == "" || host == "" {
		return "", &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: fmt.Sprintf("URL %q must include scheme and host", candidateURL.String()),
		}
	}
	switch scheme {
	case "http", "https":
	default:
		return "", &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: fmt.Sprintf("unsupported URL scheme %q", candidateURL.Scheme),
		}
	}

	if !isAllowedExternalAuthSchemeHost(scheme, host) {
		return "", &externalAuthError{
			Kind:    errExternalAuthInsecureURL,
			Message: fmt.Sprintf("external auth URL %q must use https unless host %q is loopback", candidateURL.String(), host),
		}
	}

	port := candidateURL.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, port)), nil
}

func validateTrustedAuthURL(rawURL string, trustedOrigin string, fieldName string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: fmt.Sprintf("invalid %s URL %q", fieldName, rawURL),
			Err:     err,
		}
	}
	if parsedURL.User != nil {
		return "", &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: fmt.Sprintf("invalid %s URL %q: user info is not allowed", fieldName, rawURL),
		}
	}

	candidateOrigin, err := normalizedOrigin(parsedURL)
	if err != nil {
		kind := errExternalAuthInvalidURL
		if errors.Is(err, errExternalAuthInsecureURL) {
			kind = errExternalAuthInsecureURL
		}
		return "", &externalAuthError{
			Kind:    kind,
			Message: fmt.Sprintf("invalid %s URL %q", fieldName, rawURL),
			Err:     err,
		}
	}
	if candidateOrigin != trustedOrigin {
		return "", &externalAuthError{
			Kind:    errExternalAuthUntrustedURL,
			Message: fmt.Sprintf("untrusted %s URL %q: expected origin %s", fieldName, rawURL, trustedOrigin),
		}
	}

	return parsedURL.String(), nil
}

func isAllowedExternalAuthSchemeHost(scheme, host string) bool {
	if scheme == "https" {
		return true
	}
	return scheme == "http" && netutil.IsLoopbackHost(host)
}

func tokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}

	var claims struct {
		Exp *jwtNumericDate `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, false
	}
	if claims.Exp == nil || claims.Exp.Time.IsZero() {
		return time.Time{}, false
	}

	return claims.Exp.Time, true
}

type jwtNumericDate struct {
	time.Time
}

func (d *jwtNumericDate) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	var unixNumber json.Number
	if err := json.Unmarshal(data, &unixNumber); err == nil {
		unixInt, err := unixNumber.Int64()
		if err != nil {
			return fmt.Errorf("invalid jwt exp claim: %w", err)
		}
		d.Time = time.Unix(unixInt, 0).UTC()
		return nil
	}

	return fmt.Errorf("invalid jwt exp claim")
}

func tokenExpired(expiresAt time.Time) bool {
	return !expiresAt.IsZero() && !expiresAt.After(time.Now())
}
