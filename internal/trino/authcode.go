package trino

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/tuannvm/mcp-trino/internal/config"
	"golang.org/x/oauth2"
)

// authCodeTokenSource implements oauth2TokenSource using Authorization Code + PKCE flow.
type authCodeTokenSource struct {
	oauthCacheHelper

	mu    sync.Mutex
	token *oauth2.Token

	// For testing: override browser open and callback server
	openBrowser   func(url string) error
	callbackPort  int // 0 = auto-assign
	serverTimeout time.Duration
}

// createAuthCodeTokenSource creates an auth code + PKCE token source from config.
func createAuthCodeTokenSource(cfg *config.TrinoConfig) oauth2TokenSource {
	if cfg.TrinoAuthMode != config.AuthModeAuthCode {
		return nil
	}

	scopes := parseScopes(cfg.TrinoOAuthScopes)
	authorizeURL := deriveAuthorizeURL(cfg.TrinoOAuthTokenURL)
	cachePath := scopedCachePath(cfg.TrinoOAuthTokenURL, cfg.TrinoOAuthClientID)

	migrateLegacyCache(cachePath)

	conf := &oauth2.Config{
		ClientID: cfg.TrinoOAuthClientID,
		Scopes:   scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   authorizeURL,
			TokenURL:  cfg.TrinoOAuthTokenURL,
			AuthStyle: oauth2.AuthStyleInParams, // public client, no secret
		},
	}

	return &authCodeTokenSource{
		oauthCacheHelper: oauthCacheHelper{
			conf:       conf,
			cachePath:  cachePath,
			httpClient: &http.Client{Timeout: 30 * time.Second},
		},
		openBrowser:   openBrowserDefault,
		serverTimeout: 120 * time.Second,
	}
}

// deriveAuthorizeURL derives the authorization endpoint from the token URL.
func deriveAuthorizeURL(tokenURL string) string {
	if idx := len(tokenURL) - len("/token"); idx > 0 && tokenURL[idx:] == "/token" {
		return tokenURL[:idx] + "/authorize"
	}
	return tokenURL + "/authorize"
}

// Token implements oauth2TokenSource.
func (a *authCodeTokenSource) Token() (*oauth2Token, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.token != nil && a.token.Valid() {
		return &oauth2Token{AccessToken: a.token.AccessToken}, nil
	}

	if cached := a.loadCacheShared(); cached != nil {
		if cached.Valid() {
			a.token = cached
			return &oauth2Token{AccessToken: cached.AccessToken}, nil
		}
		if cached.RefreshToken != "" {
			refreshed, err := a.refreshTokenShared(cached.RefreshToken)
			if err == nil {
				a.token = refreshed
				a.saveCacheShared(refreshed)
				return &oauth2Token{AccessToken: refreshed.AccessToken}, nil
			}
			log.Printf("Token refresh failed, re-authenticating: %v", err)
		}
	}

	token, err := a.doAuthCodeFlow()
	if err != nil {
		return nil, fmt.Errorf("authorization code authentication failed: %w", err)
	}
	a.token = token
	a.saveCacheShared(token)
	return &oauth2Token{AccessToken: token.AccessToken}, nil
}

// generateState creates a random state parameter for CSRF protection.
func generateState() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// doAuthCodeFlow performs the full Authorization Code + PKCE flow.
func (a *authCodeTokenSource) doAuthCodeFlow() (*oauth2.Token, error) {
	verifier := oauth2.GenerateVerifier()

	state, err := generateState()
	if err != nil {
		return nil, err
	}

	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", a.callbackPort))
	if err != nil {
		return nil, fmt.Errorf("failed to start callback server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://localhost:%d/callback", port)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			errChan <- fmt.Errorf("state mismatch: possible CSRF attack")
			http.Error(w, "State mismatch", http.StatusBadRequest)
			return
		}

		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			desc := r.URL.Query().Get("error_description")
			errChan <- fmt.Errorf("authorization error: %s: %s", errMsg, desc)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, "<html><body><h2>Authentication failed</h2><p>%s: %s</p><p>You can close this tab.</p></body></html>",
				html.EscapeString(errMsg), html.EscapeString(desc))
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			errChan <- fmt.Errorf("no authorization code in callback")
			http.Error(w, "No code", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprintf(w, "<html><body><h2>Authentication successful!</h2><p>You can close this tab and return to the terminal.</p></body></html>")
		codeChan <- code
	})

	srv := &http.Server{Handler: mux}
	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("callback server error: %w", err)
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("WARNING: Failed to shut down auth callback server: %v", err)
		}
	}()

	// shallow copy so RedirectURL is set per-call without mutating the shared conf
	conf := *a.conf
	conf.RedirectURL = redirectURI
	authURL := conf.AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.AccessTypeOffline,
	)

	_, _ = fmt.Fprintf(os.Stderr, "\nOpening browser for authentication...\n")
	_, _ = fmt.Fprintf(os.Stderr, "If the browser doesn't open, visit:\n%s\n\n", authURL)

	if err := a.openBrowser(authURL); err != nil {
		log.Printf("WARNING: Could not open browser: %v", err)
	}

	select {
	case code := <-codeChan:
		_, _ = fmt.Fprintf(os.Stderr, "Authorization code received, exchanging for token...\n")
		ctx := context.WithValue(context.Background(), oauth2.HTTPClient, a.httpClient)
		tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			return nil, fmt.Errorf("token exchange failed: %w", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "Authentication successful!\n\n")
		return tok, nil
	case err := <-errChan:
		return nil, err
	case <-time.After(a.serverTimeout):
		return nil, fmt.Errorf("authentication timed out after %v", a.serverTimeout)
	}
}

// openBrowserDefault opens the URL in the user's default browser.
func openBrowserDefault(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
