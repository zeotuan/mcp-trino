package trino

import (
	"os"
)

type externalAuthFileTokenStore struct {
	cachePath string
}

func newExternalAuthFileTokenStore(cachePath string) *externalAuthFileTokenStore {
	return &externalAuthFileTokenStore{cachePath: cachePath}
}

func (s *externalAuthFileTokenStore) Load() *externalTokenCache {
	if s.cachePath == "" {
		return nil
	}

	data, err := os.ReadFile(s.cachePath)
	if err != nil {
		return nil
	}

	var cache externalTokenCache
	if err := unmarshalExternalTokenCache(data, &cache); err != nil {
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
	if tokenExpired(cache.ExpiresAt) {
		return nil
	}
	return &cache
}

func (s *externalAuthFileTokenStore) Save(cache *externalTokenCache) {
	if s.cachePath == "" || cache == nil || cache.AccessToken == "" {
		return
	}
	writeExternalTokenCache(s.cachePath, cache)
}

func (s *externalAuthFileTokenStore) Clear() {
	if s.cachePath == "" {
		return
	}
	if err := os.Remove(s.cachePath); err != nil && !os.IsNotExist(err) {
		logExternalAuthCacheRemovalFailure(err)
	}
}
