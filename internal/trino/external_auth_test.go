package trino

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tuannvm/mcp-trino/internal/config"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestParseBearerAuthChallenge(t *testing.T) {
	headers := http.Header{}
	headers.Add("WWW-Authenticate", `Bearer x_redirect_server="https://trino.example.com/oauth/init/123", x_token_server="https://trino.example.com/oauth/token/123"`)

	req, err := http.NewRequest(http.MethodGet, "https://trino.example.com/v1/statement", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}

	challenge, err := parseBearerAuthChallenge(headers, req.URL)
	if err != nil {
		t.Fatalf("parseBearerAuthChallenge() error = %v", err)
	}
	if challenge.RedirectURL != "https://trino.example.com/oauth/init/123" {
		t.Errorf("RedirectURL = %q", challenge.RedirectURL)
	}
	if challenge.TokenURL != "https://trino.example.com/oauth/token/123" {
		t.Errorf("TokenURL = %q", challenge.TokenURL)
	}
}

func TestExternalAuthTokenManagerWaitForToken(t *testing.T) {
	var deleteCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"fresh-token"}`))
		case http.MethodDelete:
			deleteCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	manager := &externalAuthTokenManager{
		httpClient:   server.Client(),
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  time.Second,
	}

	token, err := manager.waitForToken(t.Context(), server.URL)
	if err != nil {
		t.Fatalf("waitForToken() error = %v", err)
	}
	if token != "fresh-token" {
		t.Errorf("token = %q", token)
	}
	if !deleteCalled {
		t.Error("expected token cleanup DELETE after successful poll")
	}
}

func TestExternalAuthTokenManagerCache(t *testing.T) {
	cachePath := filepath.Join(t.TempDir(), "external-cache.json")
	manager := &externalAuthTokenManager{cachePath: cachePath}
	manager.saveCache(&externalTokenCache{AccessToken: testJWTWithExp(time.Now().Add(time.Hour))})

	cache := manager.loadCache()
	if cache == nil || cache.AccessToken == "" {
		t.Fatalf("loadCache() = %#v", cache)
	}

	manager.token = cache.AccessToken
	manager.tokenExpiresAt = cache.ExpiresAt
	manager.InvalidateToken()
	if manager.CurrentToken() != "" {
		t.Error("expected invalidated token to be cleared")
	}
	if _, err := os.Stat(cachePath); !os.IsNotExist(err) {
		t.Error("expected cache file to be removed")
	}
}

func TestParseBearerAuthChallenge_TokenOnly(t *testing.T) {
	headers := http.Header{}
	headers.Add("WWW-Authenticate", `Bearer x_token_server="https://trino.example.com/oauth/token/456"`)

	req, err := http.NewRequest(http.MethodGet, "https://trino.example.com/v1/statement", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}

	challenge, err := parseBearerAuthChallenge(headers, req.URL)
	if err != nil {
		t.Fatalf("parseBearerAuthChallenge() error = %v", err)
	}
	if challenge.RedirectURL != "" {
		t.Errorf("RedirectURL = %q, want empty", challenge.RedirectURL)
	}
	if challenge.TokenURL != "https://trino.example.com/oauth/token/456" {
		t.Errorf("TokenURL = %q", challenge.TokenURL)
	}
}

func TestParseBearerAuthChallenge_RejectsCrossOriginURLs(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodGet, "https://trino.example.com/v1/statement", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}

	tests := []struct {
		name        string
		headerValue string
		wantErr     string
		wantKind    error
	}{
		{
			name:        "redirect",
			headerValue: `Bearer x_redirect_server="https://evil.example.com/oauth/init/123", x_token_server="https://trino.example.com/oauth/token/123"`,
			wantErr:     `untrusted x_redirect_server URL`,
			wantKind:    errExternalAuthUntrustedURL,
		},
		{
			name:        "token",
			headerValue: `Bearer x_redirect_server="https://trino.example.com/oauth/init/123", x_token_server="https://evil.example.com/oauth/token/123"`,
			wantErr:     `untrusted x_token_server URL`,
			wantKind:    errExternalAuthUntrustedURL,
		},
		{
			name:        "token scheme downgrade",
			headerValue: `Bearer x_redirect_server="https://trino.example.com/oauth/init/123", x_token_server="http://trino.example.com/oauth/token/123"`,
			wantErr:     `invalid x_token_server URL`,
			wantKind:    errExternalAuthInsecureURL,
		},
		{
			name:        "token port change",
			headerValue: `Bearer x_redirect_server="https://trino.example.com/oauth/init/123", x_token_server="https://trino.example.com:8443/oauth/token/123"`,
			wantErr:     `untrusted x_token_server URL`,
			wantKind:    errExternalAuthUntrustedURL,
		},
		{
			name:        "token userinfo",
			headerValue: `Bearer x_redirect_server="https://trino.example.com/oauth/init/123", x_token_server="https://user@trino.example.com/oauth/token/123"`,
			wantErr:     `invalid x_token_server URL`,
			wantKind:    errExternalAuthInvalidURL,
		},
		{
			name:        "token insecure non-loopback",
			headerValue: `Bearer x_redirect_server="https://trino.example.com/oauth/init/123", x_token_server="http://api.example.com/oauth/token/123"`,
			wantErr:     `invalid x_token_server URL`,
			wantKind:    errExternalAuthInsecureURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Add("WWW-Authenticate", tt.headerValue)

			_, err := parseBearerAuthChallenge(headers, req.URL)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantKind) {
				t.Fatalf("expected typed error %v, got %v", tt.wantKind, err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestHeaderRoundTripperExternalAuthChallenge(t *testing.T) {
	manager := &externalAuthTokenManager{
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  time.Second,
	}
	manager.openBrowser = func(url string) error { return nil }

	pollServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"fresh-bearer-token"}`))
	}))
	defer pollServer.Close()
	manager.httpClient = pollServer.Client()

	requestCount := 0
	transport := &headerRoundTripper{
		config: &config.TrinoConfig{
			AuthMode:    config.AuthModeExternalAuth,
			TrinoSource: "mcp-trino/test",
		},
		tokenManager: manager,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requestCount++
			body, _ := io.ReadAll(req.Body)
			_ = req.Body.Close()

			if requestCount == 1 {
				if got := req.Header.Get("Authorization"); got != "" {
					t.Fatalf("unexpected Authorization on first request: %q", got)
				}
				headers := http.Header{}
				headers.Add("WWW-Authenticate", `Bearer x_redirect_server="`+pollServer.URL+`/oauth/init", x_token_server="`+pollServer.URL+`/token/123"`)
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     headers,
					Body:       io.NopCloser(strings.NewReader("unauthorized")),
				}, nil
			}

			if got := req.Header.Get("Authorization"); got != "Bearer fresh-bearer-token" {
				t.Fatalf("expected bearer token on retry, got %q", got)
			}
			if got := string(body); got != "SELECT 1" {
				t.Fatalf("expected retried request body, got %q", got)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
	}

	req, err := http.NewRequest(http.MethodPost, pollServer.URL+"/v1/statement", io.NopCloser(bytes.NewReader([]byte("SELECT 1"))))
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if requestCount != 2 {
		t.Fatalf("expected 2 requests, got %d", requestCount)
	}
}

func TestBuildDSNExternalModeOmitsPassword(t *testing.T) {
	dsn := buildDSN(&config.TrinoConfig{
		Scheme:      "https",
		Host:        "trino.example.com",
		Port:        443,
		User:        "alice",
		Password:    "secret",
		Catalog:     "memory",
		Schema:      "default",
		SSL:         true,
		SSLInsecure: true,
		AuthMode:    config.AuthModeExternalAuth,
	})

	if strings.Contains(dsn, "secret") {
		t.Fatalf("expected external auth DSN to omit password, got %q", dsn)
	}
	if !strings.Contains(dsn, "alice@trino.example.com:443") {
		t.Fatalf("expected DSN to retain user attribution, got %q", dsn)
	}
}

// ---------------------------------------------------------------------------
// mockTokenManager — test double for bearerTokenManager
// ---------------------------------------------------------------------------

type mockTokenManager struct {
	mu          sync.Mutex
	token       string
	invalidated int
	acquireFunc func(ctx context.Context, challenge bearerAuthChallenge, rejected string) (string, error)
}

func (m *mockTokenManager) CurrentToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token
}

func (m *mockTokenManager) AcquireToken(ctx context.Context, challenge bearerAuthChallenge, rejected string) (string, error) {
	if m.acquireFunc != nil {
		return m.acquireFunc(ctx, challenge, rejected)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token, nil
}

func (m *mockTokenManager) InvalidateToken() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.token = ""
	m.invalidated++
}

// ---------------------------------------------------------------------------
// TestRoundTrip_BasicAuth
// ---------------------------------------------------------------------------

func TestRoundTrip_BasicAuth(t *testing.T) {
	t.Parallel()

	var dispatched int
	transport := &headerRoundTripper{
		config: &config.TrinoConfig{
			AuthMode:    config.AuthModeBasic,
			TrinoSource: "test-source",
		},
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			dispatched++
			if got := req.Header.Get("Authorization"); got != "" {
				t.Errorf("basic auth should not set Authorization header, got %q", got)
			}
			if got := req.Header.Get("X-Trino-Source"); got != "test-source" {
				t.Errorf("X-Trino-Source = %q, want test-source", got)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("ok")),
			}, nil
		}),
	}

	req, err := http.NewRequest(http.MethodGet, "http://trino.example.com/v1/statement", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if dispatched != 1 {
		t.Errorf("expected 1 dispatch, got %d", dispatched)
	}
}

// ---------------------------------------------------------------------------
// TestResolveChallenge_StaleTokenRetry
// ---------------------------------------------------------------------------

// TestResolveChallenge_StaleTokenRetry verifies the stale-token path inside
// resolveChallenge via the full externalAuthRoundTrip flow:
//
//  1. Initial dispatch carries the stale token → 401 with no WWW-Authenticate.
//  2. resolveChallenge invalidates, retries bare → 401 WITH WWW-Authenticate.
//  3. AcquireToken is called with the challenge; returns a fresh token.
//  4. Retry with the fresh token succeeds → 200.
func TestResolveChallenge_StaleTokenRetry(t *testing.T) {
	t.Parallel()

	const tokenServerURL = "https://trino.example.com/token/xyz"

	manager := &mockTokenManager{token: "stale-token"}
	manager.acquireFunc = func(_ context.Context, ch bearerAuthChallenge, rejected string) (string, error) {
		if ch.TokenURL != tokenServerURL {
			t.Errorf("AcquireToken challenge.TokenURL = %q, want %q", ch.TokenURL, tokenServerURL)
		}
		if rejected != "stale-token" {
			t.Errorf("AcquireToken rejectedToken = %q, want stale-token", rejected)
		}
		return "fresh-token", nil
	}

	var requestCount int
	transport := &headerRoundTripper{
		config:       &config.TrinoConfig{AuthMode: config.AuthModeExternalAuth},
		tokenManager: manager,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requestCount++
			auth := req.Header.Get("Authorization")
			switch requestCount {
			case 1: // initial dispatch — stale token
				if auth != "Bearer stale-token" {
					t.Errorf("request 1 Authorization = %q, want Bearer stale-token", auth)
				}
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     http.Header{}, // no WWW-Authenticate
					Body:       io.NopCloser(strings.NewReader("unauthorized")),
				}, nil
			case 2: // bare retry from resolveChallenge
				if auth != "" {
					t.Errorf("request 2 Authorization = %q, want empty", auth)
				}
				hdr := http.Header{}
				hdr.Add("WWW-Authenticate", `Bearer x_token_server="`+tokenServerURL+`"`)
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     hdr,
					Body:       io.NopCloser(strings.NewReader("unauthorized")),
				}, nil
			case 3: // retry with fresh token
				if auth != "Bearer fresh-token" {
					t.Errorf("request 3 Authorization = %q, want Bearer fresh-token", auth)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{},
					Body:       io.NopCloser(strings.NewReader("ok")),
				}, nil
			default:
				t.Errorf("unexpected request %d", requestCount)
				return nil, fmt.Errorf("unexpected request %d", requestCount)
			}
		}),
	}

	req, err := http.NewRequest(http.MethodPost, "https://trino.example.com/v1/statement",
		strings.NewReader("SELECT 1"))
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if requestCount != 3 {
		t.Errorf("expected 3 requests, got %d", requestCount)
	}
	if manager.invalidated == 0 {
		t.Error("expected InvalidateToken to be called during stale-token retry")
	}
}

// ---------------------------------------------------------------------------
// TestExternalAuthRoundTrip_TerminalUnauthorized
// ---------------------------------------------------------------------------

// TestExternalAuthRoundTrip_TerminalUnauthorized verifies that when retries are
// exhausted on a persistent 401, the transport invalidates the token and returns
// the 401 response to the caller.
func TestExternalAuthRoundTrip_TerminalUnauthorized(t *testing.T) {
	t.Parallel()

	const tokenServerURL = "https://trino.example.com/token/xyz"

	manager := &mockTokenManager{token: ""}
	manager.acquireFunc = func(_ context.Context, _ bearerAuthChallenge, _ string) (string, error) {
		return "fresh-token", nil
	}

	var requestCount int
	transport := &headerRoundTripper{
		config:       &config.TrinoConfig{AuthMode: config.AuthModeExternalAuth},
		tokenManager: manager,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requestCount++
			auth := req.Header.Get("Authorization")
			switch requestCount {
			case 1: // no cached token
				if auth != "" {
					t.Errorf("request 1 Authorization = %q, want empty", auth)
				}
				hdr := http.Header{}
				hdr.Add("WWW-Authenticate", `Bearer x_token_server="`+tokenServerURL+`"`)
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     hdr,
					Body:       io.NopCloser(strings.NewReader("unauthorized")),
				}, nil
			case 2: // fresh token — server still rejects (retries exhausted)
				if auth != "Bearer fresh-token" {
					t.Errorf("request 2 Authorization = %q, want Bearer fresh-token", auth)
				}
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     http.Header{},
					Body:       io.NopCloser(strings.NewReader("unauthorized")),
				}, nil
			default:
				t.Errorf("unexpected request %d", requestCount)
				return nil, fmt.Errorf("unexpected request %d", requestCount)
			}
		}),
	}

	req, err := http.NewRequest(http.MethodPost, "https://trino.example.com/v1/statement",
		strings.NewReader("SELECT 1"))
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip() unexpected error = %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
	if requestCount != 2 {
		t.Errorf("expected 2 requests, got %d", requestCount)
	}
	if manager.invalidated == 0 {
		t.Error("expected InvalidateToken to be called after terminal 401")
	}
}

// ---------------------------------------------------------------------------
// AcquireToken tests
// ---------------------------------------------------------------------------

func TestAcquireToken_ReturnsCachedIfAlreadyRefreshed(t *testing.T) {
	t.Parallel()

	cachedToken := testJWTWithExp(time.Now().Add(time.Hour))
	manager := &externalAuthTokenManager{
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  time.Second,
	}
	// Pre-populate the in-memory token (simulates another goroutine already refreshed).
	manager.token = cachedToken
	manager.tokenExpiresAt = time.Now().Add(time.Hour)

	challenge := bearerAuthChallenge{TokenURL: "https://example.com/token"}
	token, err := manager.AcquireToken(t.Context(), challenge, "old-token")
	if err != nil {
		t.Fatalf("AcquireToken() error = %v", err)
	}
	if token != cachedToken {
		t.Errorf("AcquireToken() = %q, want cached token %q", token, cachedToken)
	}
}

func TestAcquireToken_InFlightCoalescing(t *testing.T) {
	t.Parallel()

	unblock := make(chan struct{})
	var browserCalls int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			select {
			case <-unblock:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"coalesced-token"}`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{
		httpClient:   server.Client(),
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  5 * time.Second,
		openBrowser: func(_ string) error {
			browserCalls++
			return nil
		},
	}

	challenge := bearerAuthChallenge{
		RedirectURL: server.URL + "/oauth/init",
		TokenURL:    server.URL,
	}

	var wg sync.WaitGroup
	var token1, token2 string
	var err1, err2 error

	wg.Add(1)
	go func() {
		defer wg.Done()
		token1, err1 = manager.AcquireToken(t.Context(), challenge, "old-token")
	}()

	// Wait for goroutine 1 to set inFlight before starting goroutine 2.
	for i := 0; i < 200; i++ {
		time.Sleep(time.Millisecond)
		manager.mu.Lock()
		set := manager.inFlight != nil
		manager.mu.Unlock()
		if set {
			break
		}
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		token2, err2 = manager.AcquireToken(t.Context(), challenge, "old-token")
	}()

	// Give goroutine 2 time to reach the inFlight select before unblocking.
	time.Sleep(20 * time.Millisecond)
	close(unblock)
	wg.Wait()

	if err1 != nil {
		t.Errorf("goroutine 1 error = %v", err1)
	}
	if err2 != nil {
		t.Errorf("goroutine 2 error = %v", err2)
	}
	if token1 != "coalesced-token" {
		t.Errorf("goroutine 1 token = %q, want coalesced-token", token1)
	}
	if token2 != "coalesced-token" {
		t.Errorf("goroutine 2 token = %q, want coalesced-token", token2)
	}
	if browserCalls != 1 {
		t.Errorf("expected 1 browser call (no duplicate for in-flight), got %d", browserCalls)
	}
}

func TestAcquireToken_GenerationFence(t *testing.T) {
	t.Parallel()

	unblock := make(chan struct{})

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			select {
			case <-unblock:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"raced-token"}`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{
		httpClient:   server.Client(),
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  5 * time.Second,
		openBrowser:  func(_ string) error { return nil },
	}

	challenge := bearerAuthChallenge{TokenURL: server.URL}

	var wg sync.WaitGroup
	var acquiredToken string
	var acquiredErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		acquiredToken, acquiredErr = manager.AcquireToken(t.Context(), challenge, "")
	}()

	// Wait for inFlight to be set.
	for i := 0; i < 200; i++ {
		time.Sleep(time.Millisecond)
		manager.mu.Lock()
		set := manager.inFlight != nil
		manager.mu.Unlock()
		if set {
			break
		}
	}

	// Invalidate while acquisition is in progress — bumps the generation counter.
	manager.InvalidateToken()

	// Let the poll server return the token.
	close(unblock)
	wg.Wait()

	if acquiredErr != nil {
		t.Fatalf("AcquireToken() error = %v", acquiredErr)
	}
	if acquiredToken != "raced-token" {
		t.Errorf("returned token = %q, want raced-token", acquiredToken)
	}

	// Generation fence: the raced token must NOT have been written to m.token.
	manager.mu.Lock()
	stored := manager.token
	manager.mu.Unlock()
	if stored != "" {
		t.Errorf("m.token = %q after generation fence, want empty", stored)
	}
}

func TestAcquireToken_ContextCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Block until the request context is cancelled.
			select {
			case <-r.Context().Done():
				return
			case <-time.After(30 * time.Second):
				w.WriteHeader(http.StatusGatewayTimeout)
			}
		}
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{
		httpClient:   server.Client(),
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  30 * time.Second,
		openBrowser:  func(_ string) error { return nil },
	}

	challenge := bearerAuthChallenge{TokenURL: server.URL}

	ctx1, cancel1 := context.WithCancel(t.Context())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		manager.AcquireToken(ctx1, challenge, "") //nolint:errcheck
	}()

	// Wait for goroutine 1's inFlight to be registered.
	for i := 0; i < 200; i++ {
		time.Sleep(time.Millisecond)
		manager.mu.Lock()
		set := manager.inFlight != nil
		manager.mu.Unlock()
		if set {
			break
		}
	}

	// Second caller with an already-cancelled context — must return ctx.Err() promptly.
	ctx2, cancel2 := context.WithCancel(t.Context())
	cancel2()

	_, err := manager.AcquireToken(ctx2, challenge, "")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}

	cancel1()
	wg.Wait()
}

func TestAcquireToken_ExpiredCachedTokenRefreshes(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(fmt.Sprintf(`{"token":%q}`, testJWTWithExp(time.Now().Add(time.Hour)))))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{
		httpClient:     server.Client(),
		pollInterval:   10 * time.Millisecond,
		pollTimeout:    time.Second,
		token:          testJWTWithExp(time.Now().Add(-time.Minute)),
		tokenExpiresAt: time.Now().Add(-time.Minute),
		openBrowser:    func(string) error { return nil },
	}

	token, err := manager.AcquireToken(t.Context(), bearerAuthChallenge{TokenURL: server.URL}, "")
	if err != nil {
		t.Fatalf("AcquireToken() error = %v", err)
	}
	if token == "" || token == manager.token && tokenExpired(manager.tokenExpiresAt) {
		t.Fatalf("expected refreshed token, got %q", token)
	}
}

// ---------------------------------------------------------------------------
// waitForToken tests
// ---------------------------------------------------------------------------

func TestWaitForToken_NextURI(t *testing.T) {
	t.Parallel()

	var deleteCalledOnNext bool
	var serverURL string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token/initial" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"nextUri":"%s/token/next"}`, serverURL)
		case r.URL.Path == "/token/next" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"final-token"}`))
		case r.URL.Path == "/token/next" && r.Method == http.MethodDelete:
			deleteCalledOnNext = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	serverURL = server.URL

	manager := &externalAuthTokenManager{
		httpClient:   server.Client(),
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  time.Second,
	}

	token, err := manager.waitForToken(t.Context(), serverURL+"/token/initial")
	if err != nil {
		t.Fatalf("waitForToken() error = %v", err)
	}
	if token != "final-token" {
		t.Errorf("token = %q, want final-token", token)
	}
	if !deleteCalledOnNext {
		t.Error("expected DELETE cleanup on /token/next")
	}
}

func TestWaitForToken_RejectsCrossOriginNextURI(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"nextUri":"https://evil.example.com/token/next"}`))
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{
		httpClient:   server.Client(),
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  time.Second,
	}

	_, err := manager.waitForToken(t.Context(), server.URL+"/token/initial")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "untrusted nextUri URL") {
		t.Fatalf("error = %q, want it to mention untrusted nextUri", err.Error())
	}
	if !errors.Is(err, errExternalAuthUntrustedURL) {
		t.Fatalf("expected typed untrusted URL error, got %v", err)
	}
}

func TestWaitForToken_RejectsRedirectResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://evil.example.com/token/next", http.StatusFound)
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{
		httpClient:   newExternalAuthHTTPClient(server.Client()),
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  time.Second,
	}

	_, err := manager.waitForToken(t.Context(), server.URL+"/token/initial")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "status 302") {
		t.Fatalf("error = %q, want it to mention status 302", err.Error())
	}
	if !errors.Is(err, errExternalAuthPollFailed) {
		t.Fatalf("expected typed poll failure error, got %v", err)
	}
}

func TestWaitForToken_PollError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":"auth_denied"}`))
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{
		httpClient:   server.Client(),
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  time.Second,
	}

	_, err := manager.waitForToken(t.Context(), server.URL)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "auth_denied") {
		t.Errorf("error = %q, want it to contain auth_denied", err.Error())
	}
	if !errors.Is(err, errExternalAuthPollFailed) {
		t.Fatalf("expected typed poll failure error, got %v", err)
	}
}

func TestWaitForToken_ContextCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// Return an empty response so waitForToken enters the sleep select.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{
		httpClient:   server.Client(),
		pollInterval: 10 * time.Second, // long — so ctx cancels before the sleep ends
		pollTimeout:  30 * time.Second,
	}

	ctx, cancel := context.WithCancel(t.Context())

	// Cancel the context shortly after the server sends the first empty response.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := manager.waitForToken(ctx, server.URL)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestWaitForToken_Timeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{
		httpClient:   server.Client(),
		pollInterval: time.Millisecond,
		// Negative duration → deadline is already in the past → loop never executes.
		pollTimeout: -1,
	}

	_, err := manager.waitForToken(t.Context(), server.URL)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %q, want it to contain \"timed out\"", err.Error())
	}
	if !errors.Is(err, errExternalAuthPollTimedOut) {
		t.Fatalf("expected typed timeout error, got %v", err)
	}
}

func TestNormalizedOrigin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		rawURL   string
		want     string
		wantErr  string
		wantKind error
	}{
		{
			name:   "https default port",
			rawURL: "https://trino.example.com/v1/statement",
			want:   "https://trino.example.com:443",
		},
		{
			name:   "https explicit default port",
			rawURL: "https://trino.example.com:443/v1/statement",
			want:   "https://trino.example.com:443",
		},
		{
			name:   "hostname trailing dot",
			rawURL: "https://trino.example.com./v1/statement",
			want:   "https://trino.example.com:443",
		},
		{
			name:   "ipv6",
			rawURL: "http://[::1]:8080/v1/statement",
			want:   "http://[::1]:8080",
		},
		{
			name:   "loopback http allowed",
			rawURL: "http://127.0.0.1:8080/v1/statement",
			want:   "http://127.0.0.1:8080",
		},
		{
			name:     "unsupported scheme",
			rawURL:   "ftp://trino.example.com/token",
			wantErr:  `unsupported URL scheme "ftp"`,
			wantKind: errExternalAuthInvalidURL,
		},
		{
			name:     "non loopback http rejected",
			rawURL:   "http://trino.example.com/token",
			wantErr:  `must use https unless host "trino.example.com" is loopback`,
			wantKind: errExternalAuthInsecureURL,
		},
		{
			name:     "relative URL",
			rawURL:   "/v1/statement",
			wantErr:  `is not absolute`,
			wantKind: errExternalAuthInvalidURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parsedURL, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("url.Parse() error = %v", err)
			}

			got, err := normalizedOrigin(parsedURL)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, tt.wantKind) {
					t.Fatalf("expected typed error %v, got %v", tt.wantKind, err)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizedOrigin() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalizedOrigin() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateTrustedAuthURL(t *testing.T) {
	t.Parallel()

	const trustedOrigin = "https://trino.example.com:443"

	tests := []struct {
		name     string
		rawURL   string
		want     string
		wantErr  string
		wantKind error
	}{
		{
			name:   "same origin default port",
			rawURL: "https://trino.example.com/oauth/token/123",
			want:   "https://trino.example.com/oauth/token/123",
		},
		{
			name:   "same origin explicit default port",
			rawURL: "https://trino.example.com:443/oauth/token/123",
			want:   "https://trino.example.com:443/oauth/token/123",
		},
		{
			name:   "same origin trailing dot",
			rawURL: "https://trino.example.com./oauth/token/123",
			want:   "https://trino.example.com./oauth/token/123",
		},
		{
			name:     "port mismatch",
			rawURL:   "https://trino.example.com:8443/oauth/token/123",
			wantErr:  `untrusted x_token_server URL`,
			wantKind: errExternalAuthUntrustedURL,
		},
		{
			name:     "scheme mismatch",
			rawURL:   "http://trino.example.com/oauth/token/123",
			wantErr:  `invalid x_token_server URL`,
			wantKind: errExternalAuthInsecureURL,
		},
		{
			name:     "userinfo rejected",
			rawURL:   "https://user@trino.example.com/oauth/token/123",
			wantErr:  `invalid x_token_server URL`,
			wantKind: errExternalAuthInvalidURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := validateTrustedAuthURL(tt.rawURL, trustedOrigin, "x_token_server")
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, tt.wantKind) {
					t.Fatalf("expected typed error %v, got %v", tt.wantKind, err)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateTrustedAuthURL() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("validateTrustedAuthURL() = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("loopback http allowed", func(t *testing.T) {
		t.Parallel()

		got, err := validateTrustedAuthURL("http://127.0.0.1:8080/oauth/token/123", "http://127.0.0.1:8080", "x_token_server")
		if err != nil {
			t.Fatalf("validateTrustedAuthURL() error = %v", err)
		}
		if got != "http://127.0.0.1:8080/oauth/token/123" {
			t.Fatalf("validateTrustedAuthURL() = %q, want loopback URL", got)
		}
	})
}

// ---------------------------------------------------------------------------
// TestInvalidateToken_LogsCacheRemovalFailure
// ---------------------------------------------------------------------------

func TestInvalidateToken_LogsCacheRemovalFailure(t *testing.T) {
	// Not parallel: redirects the global log output.

	tmpDir := t.TempDir()
	// Use a non-empty directory as cachePath so os.Remove fails with a
	// non-IsNotExist error (directory not empty on all platforms).
	cacheDir := filepath.Join(tmpDir, "cache")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "sentinel"), []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	manager := &externalAuthTokenManager{
		cachePath: cacheDir,
		token:     "some-token",
	}
	manager.InvalidateToken()

	if manager.CurrentToken() != "" {
		t.Error("expected token to be cleared after InvalidateToken")
	}
	if !strings.Contains(logBuf.String(), "WARNING") {
		t.Errorf("expected WARNING in log output, got %q", logBuf.String())
	}
}

// ---------------------------------------------------------------------------
// TestDecorateRequest_Impersonation
// ---------------------------------------------------------------------------

func TestDecorateRequest_Impersonation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		enableImpersonation bool
		ctxUser             string
		wantHeader          string
	}{
		{
			name:                "impersonation enabled with user in context",
			enableImpersonation: true,
			ctxUser:             "alice",
			wantHeader:          "alice",
		},
		{
			name:                "impersonation enabled but no user in context",
			enableImpersonation: true,
			ctxUser:             "",
			wantHeader:          "",
		},
		{
			name:                "impersonation disabled with user in context",
			enableImpersonation: false,
			ctxUser:             "alice",
			wantHeader:          "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			transport := &headerRoundTripper{
				config: &config.TrinoConfig{
					EnableImpersonation: tt.enableImpersonation,
				},
			}

			ctx := t.Context()
			if tt.ctxUser != "" {
				ctx = WithImpersonatedUser(ctx, tt.ctxUser)
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet,
				"http://trino.example.com/v1/statement", nil)
			if err != nil {
				t.Fatalf("http.NewRequestWithContext() error = %v", err)
			}

			decorated := transport.decorateRequest(req, nil, "")
			got := decorated.Header.Get("X-Trino-User")
			if got != tt.wantHeader {
				t.Errorf("X-Trino-User = %q, want %q", got, tt.wantHeader)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestReadRequestBody_NilBody
// ---------------------------------------------------------------------------

func TestReadRequestBody_NilBody(t *testing.T) {
	t.Parallel()

	req, err := http.NewRequest(http.MethodGet, "http://trino.example.com/v1/statement", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}

	body, err := readRequestBody(req)
	if err != nil {
		t.Fatalf("readRequestBody() error = %v", err)
	}
	if body != nil {
		t.Errorf("readRequestBody() = %v, want nil", body)
	}
}

// ---------------------------------------------------------------------------
// TestCachedTokenLocked_DiskLoad
// ---------------------------------------------------------------------------

func TestCachedTokenLocked_DiskLoad(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "token-cache.json")
	manager := &externalAuthTokenManager{cachePath: cachePath}
	token := testJWTWithExp(time.Now().Add(time.Hour))
	manager.saveCache(&externalTokenCache{AccessToken: token})

	// In-memory token is empty; CurrentToken must load from disk.
	got := manager.CurrentToken()
	if got != token {
		t.Errorf("CurrentToken() via disk load = %q, want %q", got, token)
	}
}

// ---------------------------------------------------------------------------
// externalAuthRoundTrip — remaining branch coverage
// ---------------------------------------------------------------------------

// TestExternalAuthRoundTrip_NoChallengeNoToken covers the path where the
// server returns 401 with no WWW-Authenticate header and we have no cached
// token. resolveChallenge should fail immediately and RoundTrip returns (nil, err).
func TestExternalAuthRoundTrip_NoChallengeNoToken(t *testing.T) {
	t.Parallel()

	manager := &mockTokenManager{} // no token
	transport := &headerRoundTripper{
		config:       &config.TrinoConfig{AuthMode: config.AuthModeExternalAuth},
		tokenManager: manager,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     http.Header{}, // no WWW-Authenticate
				Body:       io.NopCloser(strings.NewReader("unauthorized")),
			}, nil
		}),
	}

	req, _ := http.NewRequest(http.MethodGet, "http://trino.example.com/v1/statement", nil)
	resp, err := transport.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errNoWWWAuthenticateHeader) {
		t.Fatalf("expected typed missing header error, got %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil resp alongside error, got %+v", resp)
	}
}

// TestExternalAuthRoundTrip_StaleTokenGetsSuccess covers the path where stale
// token is rejected (401, no challenge), resolveChallenge retries bare, and the
// bare retry returns a non-401 (e.g. 200). externalAuthRoundTrip should return
// that response directly (challenge.TokenURL == "").
func TestExternalAuthRoundTrip_StaleTokenGetsSuccess(t *testing.T) {
	t.Parallel()

	manager := &mockTokenManager{token: "stale-token"}
	var requestCount int
	transport := &headerRoundTripper{
		config:       &config.TrinoConfig{AuthMode: config.AuthModeExternalAuth},
		tokenManager: manager,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requestCount++
			switch requestCount {
			case 1: // stale token sent, rejected without challenge
				return &http.Response{
					StatusCode: http.StatusUnauthorized,
					Header:     http.Header{},
					Body:       io.NopCloser(strings.NewReader("unauthorized")),
				}, nil
			case 2: // bare retry; server now returns 200 (e.g. session already established)
				if auth := req.Header.Get("Authorization"); auth != "" {
					t.Errorf("bare retry should have no Authorization, got %q", auth)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{},
					Body:       io.NopCloser(strings.NewReader("ok")),
				}, nil
			default:
				return nil, fmt.Errorf("unexpected request %d", requestCount)
			}
		}),
	}

	req, _ := http.NewRequest(http.MethodGet, "http://trino.example.com/v1/statement", nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if requestCount != 2 {
		t.Errorf("expected 2 requests, got %d", requestCount)
	}
}

// TestExternalAuthRoundTrip_AcquireTokenError covers the path where AcquireToken
// fails (e.g. browser auth timed out). externalAuthRoundTrip returns (nil, err).
func TestExternalAuthRoundTrip_AcquireTokenError(t *testing.T) {
	t.Parallel()

	acquireErr := fmt.Errorf("browser auth timeout")
	manager := &mockTokenManager{}
	manager.acquireFunc = func(_ context.Context, _ bearerAuthChallenge, _ string) (string, error) {
		return "", acquireErr
	}

	transport := &headerRoundTripper{
		config:       &config.TrinoConfig{AuthMode: config.AuthModeExternalAuth},
		tokenManager: manager,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			hdr := http.Header{}
			hdr.Add("WWW-Authenticate", `Bearer x_token_server="https://trino.example.com/token/1"`)
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     hdr,
				Body:       io.NopCloser(strings.NewReader("unauthorized")),
			}, nil
		}),
	}

	req, _ := http.NewRequest(http.MethodGet, "https://trino.example.com/v1/statement", nil)
	resp, err := transport.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if resp != nil {
		t.Errorf("expected nil resp, got %+v", resp)
	}
	if !errors.Is(err, acquireErr) {
		t.Fatalf("expected wrapped acquire error, got %v", err)
	}
}

func TestExternalAuthRoundTrip_RejectsCrossOriginChallenge(t *testing.T) {
	t.Parallel()

	manager := &mockTokenManager{}
	transport := &headerRoundTripper{
		config:       &config.TrinoConfig{AuthMode: config.AuthModeExternalAuth},
		tokenManager: manager,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			hdr := http.Header{}
			hdr.Add("WWW-Authenticate", `Bearer x_token_server="https://evil.example.com/token/1"`)
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     hdr,
				Body:       io.NopCloser(strings.NewReader("unauthorized")),
			}, nil
		}),
	}

	req, _ := http.NewRequest(http.MethodGet, "https://trino.example.com/v1/statement", nil)
	resp, err := transport.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errExternalAuthUntrustedURL) {
		t.Fatalf("expected typed untrusted URL error, got %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil resp, got %+v", resp)
	}
	if !strings.Contains(err.Error(), "untrusted x_token_server URL") {
		t.Fatalf("error = %q, want it to mention untrusted x_token_server", err.Error())
	}
}

func TestExternalAuthRoundTrip_StaleTokenDoesNotRetryInvalidChallenge(t *testing.T) {
	t.Parallel()

	manager := &mockTokenManager{token: "stale-token"}
	manager.acquireFunc = func(_ context.Context, _ bearerAuthChallenge, _ string) (string, error) {
		t.Fatal("AcquireToken should not be called for an invalid challenge")
		return "", nil
	}

	var requestCount int
	transport := &headerRoundTripper{
		config:       &config.TrinoConfig{AuthMode: config.AuthModeExternalAuth},
		tokenManager: manager,
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requestCount++
			hdr := http.Header{}
			hdr.Add("WWW-Authenticate", `Bearer x_token_server="https://evil.example.com/token/1"`)
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     hdr,
				Body:       io.NopCloser(strings.NewReader("unauthorized")),
			}, nil
		}),
	}

	req, _ := http.NewRequest(http.MethodGet, "https://trino.example.com/v1/statement", nil)
	resp, err := transport.RoundTrip(req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errExternalAuthUntrustedURL) {
		t.Fatalf("expected typed untrusted URL error, got %v", err)
	}
	if resp != nil {
		t.Errorf("expected nil resp, got %+v", resp)
	}
	if requestCount != 1 {
		t.Fatalf("expected invalid challenge to fail without bare retry, got %d requests", requestCount)
	}
	if manager.invalidated != 0 {
		t.Fatalf("expected token to remain untouched on invalid challenge, invalidated=%d", manager.invalidated)
	}
}

// ---------------------------------------------------------------------------
// AcquireToken — empty TokenURL branch
// ---------------------------------------------------------------------------

func TestAcquireToken_EmptyTokenURL(t *testing.T) {
	t.Parallel()

	manager := &externalAuthTokenManager{
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  time.Second,
	}

	// No cached token, no inFlight, empty challenge.TokenURL → error.
	_, err := manager.AcquireToken(t.Context(), bearerAuthChallenge{TokenURL: ""}, "")
	if err == nil {
		t.Fatal("expected error for empty TokenURL, got nil")
	}
	if !errors.Is(err, errMissingExternalAuthTokenURL) {
		t.Fatalf("expected typed missing token URL error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// waitForToken — HTTP 4xx and decode-error branches
// ---------------------------------------------------------------------------

func TestWaitForToken_HTTP400WithError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_token_request"}`))
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{
		httpClient:   server.Client(),
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  time.Second,
	}

	_, err := manager.waitForToken(t.Context(), server.URL)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errExternalAuthPollFailed) {
		t.Fatalf("expected typed poll failure error, got %v", err)
	}
	if !strings.Contains(err.Error(), "invalid_token_request") {
		t.Errorf("error = %q, want it to contain 'invalid_token_request'", err.Error())
	}
}

func TestWaitForToken_HTTP400NoError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`not json`))
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{
		httpClient:   server.Client(),
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  time.Second,
	}

	_, err := manager.waitForToken(t.Context(), server.URL)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, errExternalAuthPollFailed) {
		t.Fatalf("expected typed poll failure error, got %v", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want it to mention status 500", err.Error())
	}
}

func TestWaitForToken_DecodeError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not valid json {{{`))
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{
		httpClient:   server.Client(),
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  time.Second,
	}

	_, err := manager.waitForToken(t.Context(), server.URL)
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
	if !errors.Is(err, errExternalAuthDecodeFailed) {
		t.Fatalf("expected typed decode failure error, got %v", err)
	}
	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("error = %q, want it to mention decode failure", err.Error())
	}
}

// ---------------------------------------------------------------------------
// parseBearerAuthChallenge — header present but no x_token_server
// ---------------------------------------------------------------------------

func TestParseBearerAuthChallenge_NoTokenServer(t *testing.T) {
	t.Parallel()

	headers := http.Header{}
	headers.Add("WWW-Authenticate", `Bearer realm="trino"`) // no x_token_server

	req, err := http.NewRequest(http.MethodGet, "https://trino.example.com/v1/statement", nil)
	if err != nil {
		t.Fatalf("http.NewRequest() error = %v", err)
	}

	_, err = parseBearerAuthChallenge(headers, req.URL)
	if err == nil {
		t.Fatal("expected error for missing x_token_server, got nil")
	}
	if !errors.Is(err, errNoExternalAuthChallenge) {
		t.Fatalf("expected typed missing challenge error, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// acquireFreshToken — browser open fails (logged, poll continues)
// ---------------------------------------------------------------------------

func TestAcquireFreshToken_BrowserError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"polled-token"}`))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{
		httpClient:   server.Client(),
		pollInterval: 10 * time.Millisecond,
		pollTimeout:  time.Second,
		openBrowser:  func(_ string) error { return fmt.Errorf("no browser available") },
	}

	challenge := bearerAuthChallenge{
		RedirectURL: server.URL + "/oauth/init",
		TokenURL:    server.URL,
	}

	// Even though openBrowser fails, the poll should succeed.
	token, err := manager.acquireFreshToken(t.Context(), challenge)
	if err != nil {
		t.Fatalf("acquireFreshToken() error = %v", err)
	}
	if token != "polled-token" {
		t.Errorf("token = %q, want polled-token", token)
	}
}

// ---------------------------------------------------------------------------
// loadCache — corrupt JSON and empty access_token
// ---------------------------------------------------------------------------

func TestLoadCache_CorruptJSON(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(cachePath, []byte(`not json`), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	manager := &externalAuthTokenManager{cachePath: cachePath}
	if manager.loadCache() != nil {
		t.Error("expected nil from loadCache on corrupt JSON")
	}
}

func TestLoadCache_EmptyAccessToken(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(cachePath, []byte(`{"access_token":""}`), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	manager := &externalAuthTokenManager{cachePath: cachePath}
	if manager.loadCache() != nil {
		t.Error("expected nil from loadCache when access_token is empty")
	}
}

func TestLoadCache_ExpiredJWT(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	token := testJWTWithExp(time.Now().Add(-time.Minute))
	if err := os.WriteFile(cachePath, []byte(fmt.Sprintf(`{"access_token":%q}`, token)), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	manager := &externalAuthTokenManager{cachePath: cachePath}
	if manager.loadCache() != nil {
		t.Fatal("expected expired JWT cache to be ignored")
	}
}

func TestLoadCache_UsesJWTExpWhenExpiresAtMissing(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "cache.json")
	token := testJWTWithExp(time.Now().Add(time.Hour))
	if err := os.WriteFile(cachePath, []byte(fmt.Sprintf(`{"access_token":%q}`, token)), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	manager := &externalAuthTokenManager{cachePath: cachePath}
	cache := manager.loadCache()
	if cache == nil {
		t.Fatal("expected non-nil cache")
	}
	if cache.ExpiresAt.IsZero() {
		t.Fatal("expected JWT exp to populate ExpiresAt")
	}
}

func TestCleanupTokenURL_IgnoresCallerCancellation(t *testing.T) {
	t.Parallel()

	deleteCalled := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		select {
		case deleteCalled <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	manager := &externalAuthTokenManager{httpClient: server.Client()}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	manager.cleanupTokenURL(ctx, server.URL)

	select {
	case <-deleteCalled:
	case <-time.After(time.Second):
		t.Fatal("expected DELETE to still be issued after caller context cancellation")
	}
}

func testJWTWithExp(exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp.Unix())))
	return header + "." + payload + "."
}
