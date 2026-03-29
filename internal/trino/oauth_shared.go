package trino

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// tokenCache represents cached OAuth tokens on disk.
type tokenCache struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// oauthCacheHelper provides disk token cache and refresh logic.
type oauthCacheHelper struct {
	conf       *oauth2.Config
	httpClient *http.Client
	cachePath  string
}

// parseScopes splits a comma-separated scope string into trimmed tokens.
func parseScopes(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	scopes := make([]string, 0, len(parts))
	for _, s := range parts {
		if trimmed := strings.TrimSpace(s); trimmed != "" {
			scopes = append(scopes, trimmed)
		}
	}
	return scopes
}

// scopedCachePath returns a token cache path scoped to a specific tokenURL+clientID.
func scopedCachePath(tokenURL, clientID string) string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Printf("WARNING: Could not determine home directory; token caching disabled")
		return ""
	}
	hash := sha256.Sum256([]byte(tokenURL + "|" + clientID))
	filename := fmt.Sprintf("token-cache-%s.json", hex.EncodeToString(hash[:8]))
	return filepath.Join(homeDir, ".config", "trino", filename)
}

// defaultCachePath returns the default unscoped token cache path used for migration.
func defaultCachePath() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(homeDir, ".config", "trino", "token-cache.json")
}

// migrateLegacyCache copies the legacy unscoped token cache to the scoped path if needed.
func migrateLegacyCache(scopedPath string) {
	if scopedPath == "" {
		return
	}
	if _, err := os.Stat(scopedPath); err == nil {
		return
	}
	legacyPath := defaultCachePath()
	if legacyPath == "" {
		return
	}
	if _, err := os.Stat(legacyPath); err != nil {
		return
	}
	data, err := os.ReadFile(legacyPath)
	if err != nil {
		return
	}
	dir := filepath.Dir(scopedPath)
	_ = os.MkdirAll(dir, 0700)
	if err := os.WriteFile(scopedPath, data, 0600); err == nil {
		log.Printf("Migrated legacy token cache to %s", filepath.Base(scopedPath))
	}
}

// refreshTokenShared uses a refresh token to obtain a new access token via the oauth2 library.
func (h *oauthCacheHelper) refreshTokenShared(refreshTok string) (*oauth2.Token, error) {
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, h.httpClient)
	ts := h.conf.TokenSource(ctx, &oauth2.Token{RefreshToken: refreshTok})
	tok, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}
	// Preserve the original refresh token if the server didn't issue a new one.
	if tok.RefreshToken == "" {
		tok.RefreshToken = refreshTok
	}
	return tok, nil
}

// loadCacheShared loads the cached token from disk.
func (h *oauthCacheHelper) loadCacheShared() *oauth2.Token {
	if h.cachePath == "" {
		return nil
	}

	data, err := os.ReadFile(h.cachePath)
	if err != nil {
		return nil
	}

	var cache tokenCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil
	}

	return &oauth2.Token{
		AccessToken:  cache.AccessToken,
		RefreshToken: cache.RefreshToken,
		TokenType:    cache.TokenType,
		Expiry:       cache.ExpiresAt,
	}
}

// saveCacheShared saves the token to disk cache.
func (h *oauthCacheHelper) saveCacheShared(token *oauth2.Token) {
	if h.cachePath == "" || token == nil {
		return
	}

	cache := tokenCache{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		ExpiresAt:    token.Expiry,
	}

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		log.Printf("WARNING: Failed to marshal token cache: %v", err)
		return
	}

	dir := filepath.Dir(h.cachePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Printf("WARNING: Failed to create token cache directory: %v", err)
		return
	}

	if err := os.WriteFile(h.cachePath, data, 0600); err != nil {
		log.Printf("WARNING: Failed to write token cache: %v", err)
		return
	}

	if err := os.Chmod(h.cachePath, 0600); err != nil {
		log.Printf("WARNING: Failed to set token cache permissions: %v", err)
	}
}
