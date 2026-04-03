package trino

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type externalAuthHTTPPoller struct {
	httpClient   *http.Client
	pollInterval time.Duration
	pollTimeout  time.Duration
}

func newExternalAuthHTTPPoller(httpClient *http.Client, pollInterval, pollTimeout time.Duration) *externalAuthHTTPPoller {
	if pollInterval == 0 {
		pollInterval = externalAuthDefaultPollInterval
	}
	if pollTimeout == 0 {
		pollTimeout = externalAuthDefaultPollTimeout
	}

	return &externalAuthHTTPPoller{
		httpClient:   newExternalAuthHTTPClient(httpClient),
		pollInterval: pollInterval,
		pollTimeout:  pollTimeout,
	}
}

func (p *externalAuthHTTPPoller) WaitForToken(ctx context.Context, initialTokenURL string) (string, error) {
	policy, err := newExternalAuthTrustPolicyFromRawURL(initialTokenURL)
	if err != nil {
		return "", err
	}

	deadline := time.Now().Add(p.pollTimeout)
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

		resp, err := p.httpClient.Do(req)
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
			p.CleanupTokenURL(ctx, tokenURL)
			return poll.Token, nil
		}
		if poll.Error != "" {
			return "", &externalAuthError{
				Kind:    errExternalAuthPollFailed,
				Message: fmt.Sprintf("trino token polling failed: %s", poll.Error),
			}
		}
		if poll.NextURI != "" {
			nextTokenURL, err := policy.Validate(poll.NextURI, "nextUri")
			if err != nil {
				return "", err
			}
			tokenURL = nextTokenURL
		}

		select {
		case <-time.After(p.pollInterval):
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	return "", &externalAuthError{
		Kind:    errExternalAuthPollTimedOut,
		Message: fmt.Sprintf("timed out waiting for Trino access token after %v", p.pollTimeout),
	}
}

func (p *externalAuthHTTPPoller) CleanupTokenURL(parentCtx context.Context, tokenURL string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parentCtx), externalAuthCleanupTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, tokenURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", trinoAuthUserAgent)
	resp, err := p.httpClient.Do(req)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}
}
