package trino

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tuannvm/mcp-trino/internal/config"
)

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

func unmarshalExternalTokenCache(data []byte, cache *externalTokenCache) error {
	return json.Unmarshal(data, cache)
}

func writeExternalTokenCache(cachePath string, cache *externalTokenCache) {
	if cache == nil || cache.AccessToken == "" {
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

	if err := os.MkdirAll(filepath.Dir(cachePath), 0700); err != nil {
		log.Printf("WARNING: Failed to create external auth token cache directory: %v", err)
		return
	}
	if err := os.WriteFile(cachePath, data, 0600); err != nil {
		log.Printf("WARNING: Failed to write external auth token cache: %v", err)
	}
}

func logExternalAuthCacheRemovalFailure(err error) {
	log.Printf("WARNING: failed to remove external auth token cache: %v", err)
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
