package trino

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/tuannvm/mcp-trino/internal/netutil"
)

var (
	redirectServerPattern = regexp.MustCompile(`x_redirect_server="([^"]+)"`)
	tokenServerPattern    = regexp.MustCompile(`x_token_server="([^"]+)"`)
)

type externalAuthTrustPolicy struct {
	trustedOrigin string
}

func newExternalAuthTrustPolicyFromRequest(requestURL *url.URL) (externalAuthTrustPolicy, error) {
	trustedOrigin, err := normalizedOrigin(requestURL)
	if err != nil {
		return externalAuthTrustPolicy{}, &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: "invalid Trino request URL for external auth challenge validation",
			Err:     err,
		}
	}
	return externalAuthTrustPolicy{trustedOrigin: trustedOrigin}, nil
}

func newExternalAuthTrustPolicyFromRawURL(rawURL string) (externalAuthTrustPolicy, error) {
	trustedOrigin, err := normalizedOriginFromRawURL(rawURL)
	if err != nil {
		return externalAuthTrustPolicy{}, &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: fmt.Sprintf("invalid Trino external auth token URL %q", rawURL),
			Err:     err,
		}
	}
	return externalAuthTrustPolicy{trustedOrigin: trustedOrigin}, nil
}

func (p externalAuthTrustPolicy) Validate(rawURL string, fieldName string) (string, error) {
	return validateTrustedAuthURL(rawURL, p.trustedOrigin, fieldName)
}

func parseBearerAuthChallenge(headers http.Header, requestURL *url.URL) (bearerAuthChallenge, error) {
	values := headers.Values("WWW-Authenticate")
	if len(values) == 0 {
		return bearerAuthChallenge{}, &externalAuthError{Kind: errNoWWWAuthenticateHeader, Message: errNoWWWAuthenticateHeader.Error()}
	}

	policy, err := newExternalAuthTrustPolicyFromRequest(requestURL)
	if err != nil {
		return bearerAuthChallenge{}, err
	}

	joined := strings.Join(values, ", ")

	redirectMatch := redirectServerPattern.FindStringSubmatch(joined)
	tokenMatch := tokenServerPattern.FindStringSubmatch(joined)
	if len(tokenMatch) < 2 {
		return bearerAuthChallenge{}, &externalAuthError{Kind: errNoExternalAuthChallenge, Message: errNoExternalAuthChallenge.Error()}
	}

	tokenURL, err := policy.Validate(tokenMatch[1], "x_token_server")
	if err != nil {
		return bearerAuthChallenge{}, err
	}

	challenge := bearerAuthChallenge{
		TokenURL: tokenURL,
	}
	if len(redirectMatch) >= 2 {
		redirectURL, err := policy.Validate(redirectMatch[1], "x_redirect_server")
		if err != nil {
			return bearerAuthChallenge{}, err
		}
		challenge.RedirectURL = redirectURL
	}
	return challenge, nil
}

func normalizedOriginFromRawURL(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return normalizedOrigin(parsedURL)
}

func normalizedOrigin(candidateURL *url.URL) (string, error) {
	if candidateURL == nil {
		return "", &externalAuthError{Kind: errExternalAuthInvalidURL, Message: "missing URL"}
	}
	if !candidateURL.IsAbs() {
		return "", &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: fmt.Sprintf("URL %q is not absolute", candidateURL.String()),
		}
	}

	scheme := strings.ToLower(candidateURL.Scheme)
	host := netutil.NormalizeHostname(candidateURL.Hostname())
	if scheme == "" || host == "" {
		return "", &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: fmt.Sprintf("URL %q must include scheme and host", candidateURL.String()),
		}
	}
	switch scheme {
	case "http", "https":
	default:
		return "", &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: fmt.Sprintf("unsupported URL scheme %q", candidateURL.Scheme),
		}
	}

	if !isAllowedExternalAuthSchemeHost(scheme, host) {
		return "", &externalAuthError{
			Kind:    errExternalAuthInsecureURL,
			Message: fmt.Sprintf("external auth URL %q must use https unless host %q is loopback", candidateURL.String(), host),
		}
	}

	port := candidateURL.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}

	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, port)), nil
}

func validateTrustedAuthURL(rawURL string, trustedOrigin string, fieldName string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: fmt.Sprintf("invalid %s URL %q", fieldName, rawURL),
			Err:     err,
		}
	}
	if parsedURL.User != nil {
		return "", &externalAuthError{
			Kind:    errExternalAuthInvalidURL,
			Message: fmt.Sprintf("invalid %s URL %q: user info is not allowed", fieldName, rawURL),
		}
	}

	candidateOrigin, err := normalizedOrigin(parsedURL)
	if err != nil {
		kind := errExternalAuthInvalidURL
		if errors.Is(err, errExternalAuthInsecureURL) {
			kind = errExternalAuthInsecureURL
		}
		return "", &externalAuthError{
			Kind:    kind,
			Message: fmt.Sprintf("invalid %s URL %q", fieldName, rawURL),
			Err:     err,
		}
	}
	if candidateOrigin != trustedOrigin {
		return "", &externalAuthError{
			Kind:    errExternalAuthUntrustedURL,
			Message: fmt.Sprintf("untrusted %s URL %q: expected origin %s", fieldName, rawURL, trustedOrigin),
		}
	}

	return parsedURL.String(), nil
}

func isAllowedExternalAuthSchemeHost(scheme, host string) bool {
	if scheme == "https" {
		return true
	}
	return scheme == "http" && netutil.IsLoopbackHost(host)
}
