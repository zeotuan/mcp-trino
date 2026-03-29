package trino

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestScopedCachePath(t *testing.T) {
	path1 := scopedCachePath("https://login.microsoftonline.com/tenant1/oauth2/v2.0/token", "client-a")
	path2 := scopedCachePath("https://login.microsoftonline.com/tenant2/oauth2/v2.0/token", "client-a")
	path3 := scopedCachePath("https://login.microsoftonline.com/tenant1/oauth2/v2.0/token", "client-b")
	path4 := scopedCachePath("https://login.microsoftonline.com/tenant1/oauth2/v2.0/token", "client-a")

	if path1 == path2 {
		t.Error("Different tenants should produce different cache paths")
	}
	if path1 == path3 {
		t.Error("Different client IDs should produce different cache paths")
	}
	if path1 != path4 {
		t.Error("Same tokenURL+clientID should produce same cache path")
	}
	if !strings.Contains(path1, "token-cache-") {
		t.Errorf("Cache path should contain 'token-cache-' prefix, got %q", path1)
	}
	if !strings.HasSuffix(path1, ".json") {
		t.Errorf("Cache path should end with .json, got %q", path1)
	}
}

func TestParseScopes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{"empty", "", nil},
		{"single", "openid", []string{"openid"}},
		{"multiple", "openid,profile,email", []string{"openid", "profile", "email"}},
		{"with spaces", " openid , profile , email ", []string{"openid", "profile", "email"}},
		{"trailing comma", "openid,profile,", []string{"openid", "profile"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseScopes(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("parseScopes(%q) = %v, want %v", tt.input, result, tt.expected)
				return
			}
			for i, s := range result {
				if s != tt.expected[i] {
					t.Errorf("parseScopes(%q)[%d] = %q, want %q", tt.input, i, s, tt.expected[i])
				}
			}
		})
	}
}

func TestMigrateLegacyCache(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", "")

	legacyPath := defaultCachePath()
	scopedPath := scopedCachePath("https://login.microsoftonline.com/tenant/oauth2/v2.0/token", "client-a")

	legacyData := []byte(`{"access_token":"legacy-token","refresh_token":"legacy-refresh","token_type":"Bearer","expires_at":"2099-01-01T00:00:00Z"}`)
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0700); err != nil {
		t.Fatalf("Failed to create legacy cache dir: %v", err)
	}
	_ = os.WriteFile(legacyPath, legacyData, 0600)

	if _, err := os.Stat(scopedPath); err == nil {
		t.Fatal("Scoped path should not exist yet")
	}

	migrateLegacyCache(scopedPath)
	scopedData, err := os.ReadFile(scopedPath)
	if err != nil {
		t.Fatalf("Failed to read migrated scoped cache: %v", err)
	}
	if string(scopedData) != string(legacyData) {
		t.Error("Scoped cache content doesn't match migrated legacy cache")
	}

	_ = os.WriteFile(scopedPath, []byte(`{"access_token":"scoped-token"}`), 0600)
	migrateLegacyCache(scopedPath)
	after, _ := os.ReadFile(scopedPath)
	if strings.Contains(string(after), "legacy-token") {
		t.Error("migrateLegacyCache should not overwrite existing scoped cache")
	}
}

func TestOAuthError(t *testing.T) {
	err := &oauthError{Code: "authorization_pending", Description: "user hasn't authenticated yet"}
	if err.Error() != "authorization_pending: user hasn't authenticated yet" {
		t.Errorf("Error() = %q", err.Error())
	}

	var wrapped error = err
	var target *oauthError
	if !errors.As(wrapped, &target) {
		t.Error("errors.As should match *oauthError")
	}
	if target.Code != "authorization_pending" {
		t.Errorf("Code = %q", target.Code)
	}
}

func TestTokenCacheLoadSave(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "token-cache.json")

	h := &oauthCacheHelper{cachePath: cachePath}

	if tok := h.loadCacheShared(); tok != nil {
		t.Error("Expected nil from empty cache")
	}

	token := &oauth2.Token{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(1 * time.Hour),
	}
	h.saveCacheShared(token)

	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatalf("Cache file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("Cache file is empty")
	}

	loaded := h.loadCacheShared()
	if loaded == nil {
		t.Fatal("Failed to load cached token")
	}
	if loaded.AccessToken != "test-access-token" {
		t.Errorf("AccessToken = %q, want 'test-access-token'", loaded.AccessToken)
	}
	if loaded.RefreshToken != "test-refresh-token" {
		t.Errorf("RefreshToken = %q, want 'test-refresh-token'", loaded.RefreshToken)
	}
}

func TestTokenCacheExpired(t *testing.T) {
	tmpDir := t.TempDir()
	cachePath := filepath.Join(tmpDir, "token-cache.json")

	h := &oauthCacheHelper{cachePath: cachePath}
	token := &oauth2.Token{
		AccessToken:  "expired-access-token",
		RefreshToken: "valid-refresh-token",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(-1 * time.Hour),
	}
	h.saveCacheShared(token)

	loaded := h.loadCacheShared()
	if loaded == nil {
		t.Fatal("Should load expired token (for refresh)")
	}
	if loaded.Valid() {
		t.Error("Expired token should not be valid")
	}
	if loaded.RefreshToken != "valid-refresh-token" {
		t.Error("Should preserve refresh token")
	}
}

func TestDoTokenRequestShared_OAuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "authorization_pending",
			"error_description": "user hasn't authenticated",
		})
	}))
	defer server.Close()

	h := &oauthCacheHelper{
		tokenURL:   server.URL,
		httpClient: server.Client(),
	}

	_, err := h.doTokenRequestShared(nil)
	if err == nil {
		t.Fatal("Expected error")
	}
	var oauthErr *oauthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("Expected *oauthError, got %T: %v", err, err)
	}
	if oauthErr.Code != "authorization_pending" {
		t.Errorf("Code = %q", oauthErr.Code)
	}
}

func TestRefreshTokenShared_PreservesRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "new-access",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	h := &oauthCacheHelper{
		clientID:   "test",
		tokenURL:   server.URL,
		httpClient: server.Client(),
	}

	token, err := h.refreshTokenShared("original-refresh-token")
	if err != nil {
		t.Fatalf("refreshTokenShared() failed: %v", err)
	}
	if token.RefreshToken != "original-refresh-token" {
		t.Errorf("Should preserve original refresh token, got %q", token.RefreshToken)
	}
}

func TestRefreshTokenShared_MinExpiry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   0,
		})
	}))
	defer server.Close()

	h := &oauthCacheHelper{
		clientID:   "test",
		tokenURL:   server.URL,
		httpClient: server.Client(),
	}

	token, err := h.refreshTokenShared("refresh-token")
	if err != nil {
		t.Fatalf("refreshTokenShared() failed: %v", err)
	}
	if time.Until(token.Expiry) < time.Duration(minTokenExpiry-5)*time.Second {
		t.Errorf("Token expiry too soon: %v (expected at least %ds)", token.Expiry, minTokenExpiry)
	}
}
