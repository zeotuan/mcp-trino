package trino

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/tuannvm/mcp-trino/internal/config"
)

const (
	// maxAuthRetries caps how many token-refresh cycles the external auth flow attempts.
	maxAuthRetries = 1
	// maxChallengeRetries caps how many times resolveChallenge retries to obtain a fresh challenge.
	maxChallengeRetries = 1
)

// headerRoundTripper adds Trino headers and handles external auth challenge/retry.
type headerRoundTripper struct {
	base         http.RoundTripper
	config       *config.TrinoConfig
	tokenManager bearerTokenManager
}

func newHeaderRoundTripper(base http.RoundTripper, cfg *config.TrinoConfig) *headerRoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if cfg == nil {
		cfg = &config.TrinoConfig{}
	}

	return &headerRoundTripper{
		base:         base,
		config:       cfg,
		tokenManager: createBearerTokenManager(cfg),
	}
}

// RoundTrip dispatches to the appropriate auth flow.
func (t *headerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.config.AuthMode == config.AuthModeExternalAuth {
		return t.externalAuthRoundTrip(req)
	}
	return t.dispatchDecorated(req, nil, "")
}

// externalAuthRoundTrip attempts with a cached token; on 401 drives the Trino
// browser challenge flow and retries up to maxAuthRetries times.
func (t *headerRoundTripper) externalAuthRoundTrip(req *http.Request) (*http.Response, error) {
	body, err := readRequestBody(req)
	if err != nil {
		return nil, err
	}

	token := t.tokenManager.CurrentToken()
	for attempt := 0; ; attempt++ {
		sentToken := token
		rejectedToken := ""
		resp, err := t.dispatchDecorated(req, body, token)
		if err == nil && resp.StatusCode == http.StatusUnauthorized && sentToken != "" {
			// The server has explicitly rejected this bearer token. Clear it before
			// any challenge parsing so invalid/malicious challenges cannot leave a
			// known-bad token resident in memory or disk.
			t.tokenManager.InvalidateToken()
			rejectedToken = sentToken
			token = ""
		}
		if err != nil || resp.StatusCode != http.StatusUnauthorized || attempt >= maxAuthRetries {
			return resp, err
		}

		challenge, resp, err := t.resolveChallenge(req, body, sentToken != "", resp)
		if err != nil {
			return nil, err
		}
		if challenge.TokenURL == "" {
			return resp, nil
		}

		_ = resp.Body.Close()
		token, err = t.tokenManager.AcquireToken(req.Context(), challenge, rejectedToken)
		if err != nil {
			return nil, fmt.Errorf("failed to complete Trino external authentication: %w", err)
		}
	}
}

// resolveChallenge parses the Trino bearer challenge from a 401 response.
// If a rejected token was sent and the 401 had no challenge, it retries the
// request bare once so Trino can issue a fresh challenge.
func (t *headerRoundTripper) resolveChallenge(
	req *http.Request,
	body []byte,
	hadRejectedToken bool,
	resp *http.Response,
) (bearerAuthChallenge, *http.Response, error) {
	for attempt := 0; attempt <= maxChallengeRetries; attempt++ {
		challenge, err := parseBearerAuthChallenge(resp.Header, req.URL)
		if err == nil {
			return challenge, resp, nil
		}
		if !hadRejectedToken ||
			attempt == maxChallengeRetries ||
			(!errors.Is(err, errNoWWWAuthenticateHeader) && !errors.Is(err, errNoExternalAuthChallenge)) {
			// Close the body: callers must not receive a non-nil resp alongside
			// a non-nil err (RoundTripper contract).
			_ = resp.Body.Close()
			return bearerAuthChallenge{}, nil, err
		}

		// Stale token rejected without a challenge — retry bare once.
		_ = resp.Body.Close()
		hadRejectedToken = false

		resp, err = t.dispatchDecorated(req, body, "")
		if err != nil || resp.StatusCode != http.StatusUnauthorized {
			return bearerAuthChallenge{}, resp, err
		}
	}

	return bearerAuthChallenge{}, nil, fmt.Errorf("internal: resolveChallenge loop exited unexpectedly")
}

// dispatchDecorated decorates the request and sends it through the base transport.
// Pass nil body to preserve the original; pass buffered bytes on retry paths.
func (t *headerRoundTripper) dispatchDecorated(req *http.Request, body []byte, bearerToken string) (*http.Response, error) {
	return t.base.RoundTrip(t.decorateRequest(req, body, bearerToken))
}

// decorateRequest clones req, optionally overrides the body, and injects Trino headers.
func (t *headerRoundTripper) decorateRequest(req *http.Request, body []byte, token string) *http.Request {
	cloned := req.Clone(req.Context())

	if body != nil {
		cloned.Body = io.NopCloser(bytes.NewReader(body))
		cloned.ContentLength = int64(len(body))
	}

	if token != "" {
		cloned.Header.Set("Authorization", "Bearer "+token)
	}

	if t.config.TrinoSource != "" {
		cloned.Header.Set("X-Trino-Source", t.config.TrinoSource)
	}

	if t.config.EnableImpersonation {
		if user, ok := req.Context().Value(impersonatedUserKey).(string); ok && user != "" {
			cloned.Header.Set("X-Trino-User", user)
		}
	}

	return cloned
}

func readRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body for retry: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	return body, nil
}
