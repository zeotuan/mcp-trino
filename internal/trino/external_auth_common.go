package trino

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	trinoAuthUserAgent              = "mcp-trino-external-auth"
	externalAuthCleanupTimeout      = 5 * time.Second
	externalAuthDefaultPollInterval = 2 * time.Second
	externalAuthDefaultPollTimeout  = 2 * time.Minute
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

type externalAuthTokenStore interface {
	Load() *externalTokenCache
	Save(*externalTokenCache)
	Clear()
}

type externalAuthTokenPoller interface {
	WaitForToken(ctx context.Context, initialTokenURL string) (string, error)
	CleanupTokenURL(parentCtx context.Context, tokenURL string)
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
