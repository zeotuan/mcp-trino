package trino

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
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

// oauthError is a structured error from the OAuth token endpoint.
type oauthError struct {
	Code        string
	Description string
}

func (e *oauthError) Error() string {
	return e.Code + ": " + e.Description
}

// tokenResponse is the shared JSON structure for token endpoint responses.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// minTokenExpiry is the minimum token lifetime to prevent refresh storms.
const minTokenExpiry = 60 // seconds

// oauthCacheHelper provides shared token cache and refresh logic
// for the interactive auth-code flow and shared refresh-token caching.
type oauthCacheHelper struct {
	clientID   string
	tokenURL   string
	scopes     []string
	cachePath  string
	httpClient *http.Client
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

// doTokenRequestShared sends a POST to the token endpoint and parses the response
func (h *oauthCacheHelper) doTokenRequestShared(data url.Values) (*tokenResponse, error) {
	resp, err := h.httpClient.PostForm(h.tokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("WARNING: Failed to close token response body: %v", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("token endpoint returned non-JSON response (HTTP %d): %s", resp.StatusCode, string(body))
	}

	if tokenResp.Error != "" {
		return nil, &oauthError{Code: tokenResp.Error, Description: tokenResp.ErrorDesc}
	}

	return &tokenResp, nil
}

// refreshTokenShared uses a refresh token to get a new access token
func (h *oauthCacheHelper) refreshTokenShared(refreshTok string) (*oauth2.Token, error) {
	data := url.Values{
		"client_id":     {h.clientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshTok},
		"scope":         {strings.Join(h.scopes, " ")},
	}

	tokenResp, err := h.doTokenRequestShared(data)
	if err != nil {
		return nil, fmt.Errorf("refresh failed: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("refresh failed: server returned empty access token")
	}

	rt := tokenResp.RefreshToken
	if rt == "" {
		rt = refreshTok
	}

	expiresIn := tokenResp.ExpiresIn
	if expiresIn < minTokenExpiry {
		expiresIn = minTokenExpiry
	}

	return &oauth2.Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: rt,
		TokenType:    tokenResp.TokenType,
		Expiry:       time.Now().Add(time.Duration(expiresIn) * time.Second),
	}, nil
}

// loadCacheShared loads the cached token from disk
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

// saveCacheShared saves the token to disk cache
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
