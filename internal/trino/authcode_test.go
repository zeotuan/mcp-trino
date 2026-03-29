package trino

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tuannvm/mcp-trino/internal/config"
	"golang.org/x/oauth2"
)

func jsonResponse(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestDeriveAuthorizeURL(t *testing.T) {
	tests := []struct {
		name     string
		tokenURL string
		expected string
	}{
		{
			name:     "Azure AD v2.0",
			tokenURL: "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token",
			expected: "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize",
		},
		{
			name:     "Generic /token suffix",
			tokenURL: "https://auth.example.com/oauth/token",
			expected: "https://auth.example.com/oauth/authorize",
		},
		{
			name:     "No /token suffix",
			tokenURL: "https://auth.example.com/oauth",
			expected: "https://auth.example.com/oauth/authorize",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deriveAuthorizeURL(tt.tokenURL)
			if result != tt.expected {
				t.Errorf("deriveAuthorizeURL(%q) = %q, want %q", tt.tokenURL, result, tt.expected)
			}
		})
	}
}

func TestGenerateState(t *testing.T) {
	state1, err := generateState()
	if err != nil {
		t.Fatalf("generateState() failed: %v", err)
	}
	if state1 == "" {
		t.Error("state is empty")
	}

	state2, _ := generateState()
	if state1 == state2 {
		t.Error("two calls should produce different states")
	}
}

func TestCreateAuthCodeTokenSource(t *testing.T) {
	cfg := &config.TrinoConfig{
		TrinoAuthMode:      config.AuthModeAuthCode,
		TrinoOAuthTokenURL: "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
		TrinoOAuthClientID: "test-client-id",
		TrinoOAuthScopes:   "openid,profile,offline_access",
	}

	ts := createAuthCodeTokenSource(cfg)
	if ts == nil {
		t.Fatal("Expected non-nil token source for auth-code mode")
	}

	ats, ok := ts.(*authCodeTokenSource)
	if !ok {
		t.Fatal("Expected *authCodeTokenSource")
	}
	if ats.conf.ClientID != "test-client-id" {
		t.Errorf("ClientID = %q", ats.conf.ClientID)
	}
	if ats.conf.Endpoint.AuthURL != "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize" {
		t.Errorf("AuthURL = %q", ats.conf.Endpoint.AuthURL)
	}
	if len(ats.conf.Scopes) != 3 {
		t.Errorf("Scopes = %v, want 3 items", ats.conf.Scopes)
	}
	if !strings.Contains(ats.cachePath, "token-cache-") {
		t.Errorf("cachePath should be scoped, got %q", ats.cachePath)
	}
}

func TestCreateAuthCodeTokenSource_WrongMode(t *testing.T) {
	cfg := &config.TrinoConfig{TrinoAuthMode: config.AuthModeBasic}
	if ts := createAuthCodeTokenSource(cfg); ts != nil {
		t.Error("Expected nil for basic mode")
	}
}

func TestAuthCodeTokenSource_CachedValidToken(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "token-cache.json")

	cache := tokenCache{
		AccessToken:  "cached-auth-code-token",
		RefreshToken: "cached-refresh",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	data, _ := json.Marshal(cache)
	_ = os.WriteFile(cachePath, data, 0600)

	ts := &authCodeTokenSource{
		oauthCacheHelper: oauthCacheHelper{
			conf:      &oauth2.Config{},
			cachePath: cachePath,
		},
	}

	token, err := ts.Token()
	if err != nil {
		t.Fatalf("Token() failed: %v", err)
	}
	if token.AccessToken != "cached-auth-code-token" {
		t.Errorf("AccessToken = %q, want 'cached-auth-code-token'", token.AccessToken)
	}
}

func TestAuthCodeTokenSource_RefreshExpiredCache(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "token-cache.json")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") == "refresh_token" {
			jsonResponse(w, map[string]interface{}{
				"access_token":  "refreshed-auth-code-token",
				"refresh_token": "new-refresh",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	cache := tokenCache{
		AccessToken:  "expired-token",
		RefreshToken: "valid-refresh",
		TokenType:    "Bearer",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
	}
	data, _ := json.Marshal(cache)
	_ = os.WriteFile(cachePath, data, 0600)

	ts := &authCodeTokenSource{
		oauthCacheHelper: oauthCacheHelper{
			conf: &oauth2.Config{
				ClientID: "test",
				Scopes:   []string{"openid"},
				Endpoint: oauth2.Endpoint{
					TokenURL:  server.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				},
			},
			cachePath:  cachePath,
			httpClient: server.Client(),
		},
	}

	token, err := ts.Token()
	if err != nil {
		t.Fatalf("Token() failed: %v", err)
	}
	if token.AccessToken != "refreshed-auth-code-token" {
		t.Errorf("AccessToken = %q, want 'refreshed-auth-code-token'", token.AccessToken)
	}
}

func TestAuthCodeRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("refresh_token") != "good-refresh" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "bad refresh",
			})
			return
		}
		jsonResponse(w, map[string]interface{}{
			"access_token":  "new-token",
			"refresh_token": "new-refresh",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer server.Close()

	ts := &authCodeTokenSource{
		oauthCacheHelper: oauthCacheHelper{
			conf: &oauth2.Config{
				ClientID: "test",
				Scopes:   []string{"openid"},
				Endpoint: oauth2.Endpoint{
					TokenURL:  server.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				},
			},
			httpClient: server.Client(),
		},
	}

	// Good refresh
	token, err := ts.refreshTokenShared("good-refresh")
	if err != nil {
		t.Fatalf("refreshToken() failed: %v", err)
	}
	if token.AccessToken != "new-token" {
		t.Errorf("AccessToken = %q", token.AccessToken)
	}

	// Bad refresh — server returns 400 with error JSON
	_, err = ts.refreshTokenShared("bad-refresh")
	if err == nil {
		t.Fatal("Expected error for bad refresh token")
	}
}

func TestAuthCodeFullFlow(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") == "authorization_code" {
			jsonResponse(w, map[string]interface{}{
				"access_token":  "flow-access-token",
				"refresh_token": "flow-refresh-token",
				"token_type":    "Bearer",
				"expires_in":    3600,
			})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer tokenServer.Close()

	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "token-cache.json")

	var capturedURL string
	ts := &authCodeTokenSource{
		oauthCacheHelper: oauthCacheHelper{
			conf: &oauth2.Config{
				ClientID: "test-client",
				Scopes:   []string{"openid"},
				Endpoint: oauth2.Endpoint{
					AuthURL:   "https://auth.example.com/authorize",
					TokenURL:  tokenServer.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				},
			},
			cachePath:  cachePath,
			httpClient: tokenServer.Client(),
		},
		openBrowser: func(u string) error {
			capturedURL = u
			parsed, _ := parseAuthURL(u)
			go func() {
				time.Sleep(50 * time.Millisecond)
				callbackURL := fmt.Sprintf("%s?code=mock-auth-code&state=%s", parsed.redirectURI, parsed.state)
				resp, err := http.Get(callbackURL)
				if err == nil {
					_ = resp.Body.Close()
				}
			}()
			return nil
		},
		serverTimeout: 5 * time.Second,
	}

	token, err := ts.Token()
	if err != nil {
		t.Fatalf("Token() failed: %v", err)
	}
	if token.AccessToken != "flow-access-token" {
		t.Errorf("AccessToken = %q, want 'flow-access-token'", token.AccessToken)
	}
	if capturedURL == "" {
		t.Error("Browser should have been opened")
	}

	// Verify PKCE params were in the auth URL
	if !strings.Contains(capturedURL, "code_challenge=") {
		t.Error("Auth URL should contain code_challenge")
	}
	if !strings.Contains(capturedURL, "code_challenge_method=S256") {
		t.Error("Auth URL should contain code_challenge_method=S256")
	}

	// Verify token was cached
	cachedData, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("Cache not written: %v", err)
	}
	var cached tokenCache
	_ = json.Unmarshal(cachedData, &cached)
	if cached.AccessToken != "flow-access-token" {
		t.Errorf("Cached token = %q", cached.AccessToken)
	}
}

// parseAuthURL is a test helper to extract params from the authorization URL.
type authURLParams struct {
	state       string
	redirectURI string
}

func parseAuthURL(rawURL string) (authURLParams, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return authURLParams{}, err
	}
	return authURLParams{
		state:       parsed.Query().Get("state"),
		redirectURI: parsed.Query().Get("redirect_uri"),
	}, nil
}

func TestAuthCodeCallbackStateMismatch(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, map[string]interface{}{
			"access_token": "should-not-get-here",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenServer.Close()

	ts := &authCodeTokenSource{
		oauthCacheHelper: oauthCacheHelper{
			conf: &oauth2.Config{
				ClientID: "test",
				Scopes:   []string{"openid"},
				Endpoint: oauth2.Endpoint{
					AuthURL:   "https://auth.example.com/authorize",
					TokenURL:  tokenServer.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				},
			},
			httpClient: tokenServer.Client(),
		},
		openBrowser: func(u string) error {
			parsed, _ := parseAuthURL(u)
			go func() {
				time.Sleep(50 * time.Millisecond)
				callbackURL := fmt.Sprintf("%s?code=mock-code&state=WRONG-STATE", parsed.redirectURI)
				resp, err := http.Get(callbackURL)
				if err == nil {
					_ = resp.Body.Close()
				}
			}()
			return nil
		},
		serverTimeout: 2 * time.Second,
	}

	_, err := ts.Token()
	if err == nil {
		t.Fatal("Expected error for state mismatch")
	}
	if !strings.Contains(err.Error(), "state mismatch") && !strings.Contains(err.Error(), "timed out") {
		t.Errorf("Expected state mismatch or timeout error, got: %v", err)
	}
}

func TestBuildDSN_AuthCodeMode(t *testing.T) {
	cfg := &config.TrinoConfig{
		Host:          "trino.example.com",
		Port:          443,
		User:          "user@example.com",
		Password:      "should-be-ignored",
		Catalog:       "delta",
		Schema:        "prod",
		Scheme:        "https",
		SSL:           true,
		TrinoAuthMode: config.AuthModeAuthCode,
	}

	dsn := buildDSN(cfg)

	if strings.Contains(dsn, "should-be-ignored") {
		t.Error("auth-code DSN should not contain password")
	}
	if !strings.Contains(dsn, "trino.example.com") {
		t.Error("DSN should contain host")
	}
}
