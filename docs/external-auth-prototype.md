# External Authentication Branch Notes

This document summarizes what is currently implemented on this branch for Trino external authentication, what security properties the branch enforces, and what should still be revisited when turning it into a production-grade implementation.

## What the feature does

This branch implements a **Trino external browser authentication flow** for `TRINO_AUTH_MODE=external`.

At a high level:

1. mcp-trino sends a normal request to Trino.
2. If Trino responds with `401` and a `WWW-Authenticate` bearer challenge, mcp-trino extracts:
   - `x_redirect_server`: browser URL to open for user login
   - `x_token_server`: polling URL used to wait for the access token
3. mcp-trino opens the browser URL for the user.
4. mcp-trino polls the token URL until Trino returns a bearer token.
5. The bearer token is cached and reused on later requests.
6. If Trino rejects the token later, mcp-trino invalidates the cache and can restart the flow.

## Main implementation areas

### 1. Transport and retry integration

Implemented in:

- `internal/trino/client.go`
- `internal/trino/auth_transport.go`

Key behaviors:

- `newHeaderRoundTripper()` wires auth behavior into the Trino HTTP client
- `externalAuthRoundTrip()` drives the `401` -> challenge -> token acquisition -> retry loop
- `resolveChallenge()` handles the stale-token bare-retry rule without masking invalid or untrusted challenges
- rejected bearer tokens are invalidated immediately once Trino returns `401`

### 2. External-auth coordinator

Implemented in:

- `internal/trino/external_auth.go`
- `internal/trino/external_auth_common.go`

Key behaviors:

- `externalAuthTokenManager` coordinates:
  - current token state
  - in-flight acquisition coalescing
  - generation fencing
  - browser launch
  - store/poller delegation
- `externalAuthTokenStore` and `externalAuthTokenPoller` define the side-effect seams used by the manager

### 3. Challenge parsing and trust policy

Implemented in:

- `internal/trino/external_auth_challenge.go`
- `internal/netutil/host.go`

Key behaviors:

- parses Trino bearer challenges
- normalizes and validates request origin, challenge URLs, and `nextUri`
- enforces HTTPS or loopback-only HTTP
- rejects userinfo and cross-origin endpoint injection

### 4. Polling and cleanup

Implemented in:

- `internal/trino/external_auth_poller.go`

Key behaviors:

- polls the Trino token endpoint without following redirects
- validates each `nextUri` hop against the original token origin
- performs best-effort cleanup with a timeout-bounded cancellation-detached `DELETE`

### 5. Local token cache

The prototype caches the Trino access token on disk under the user config directory using a per-connection cache file.

Cache properties:

- keyed by `scheme + host + port + user + auth mode`
- file mode `0600`
- directory mode `0700`
- stores:
  - `access_token`
  - `expires_at` when known

### 6. File-backed token store and cache helpers

Implemented in:

- `internal/trino/external_auth_store.go`
- `internal/trino/external_auth_cache.go`

Behavior:

- file-backed default store for cached bearer tokens
- JWT `exp` parsing and `expires_at` persistence
- cache writes refuse already-expired tokens
- cache reads fail closed on malformed, empty, or expired state

### 7. Config-level auth mode support

Implemented in:

- `internal/config/config.go`
- `internal/config/authmode_external.go`
- `internal/config/authmode_test.go`

Behavior:

- `TRINO_AUTH_MODE=external` enables the browser challenge flow
- `https` is required for non-loopback hosts
- `http` is allowed only for:
  - `localhost`
  - `127.0.0.1`
  - `::1`
- `MCP_TRANSPORT=http` is rejected; external browser auth is restricted to local interactive use
- unsupported schemes such as `ftp` are rejected

## Security hardening implemented on this branch

### 1. Same-origin challenge validation

This was the core trust-boundary fix.

Before this branch, `parseAuthHeader` trusted `x_redirect_server` and `x_token_server` from `WWW-Authenticate` without validating that those URLs belonged to the Trino coordinator that issued the challenge.

Now:

- the original Trino request URL is treated as the trust anchor
- `x_redirect_server` must match that origin
- `x_token_server` must match that origin
- polling `nextUri` values must stay on the original token origin

Origin comparison normalizes:

- scheme
- hostname case
- trailing-dot hostnames
- default ports
- IPv6 host formatting

Userinfo in URLs is explicitly rejected.

### 2. HTTPS enforcement with loopback-only HTTP exception

The runtime URL validator now allows only:

- `https` for normal hosts
- `http` only for loopback hosts

The same rule is enforced at config time, so the feature cannot be enabled with an unsafe scheme/host combination and then rely on runtime validation alone.

### 3. Redirect bypass protection

Token polling uses an HTTP client with redirect-following disabled.

This closes an important bypass: even if the initial token URL is trusted, an automatic `302`/`307` redirect could otherwise move polling to a different origin before origin validation logic had a chance to run.

### 4. Safer stale-token retry behavior

The transport still supports the useful stale-token case:

- request sends cached token
- Trino rejects it with `401` but no usable auth challenge
- mcp-trino retries once without the token

But it now retries **only** when the problem is a missing challenge. It does **not** retry when the challenge exists but is invalid, insecure, or cross-origin. That avoids silently masking trust-boundary failures.

At the same time, the implementation now clears a token as soon as Trino rejects it with `401`, even if challenge validation fails afterward. That prevents a known-bad cached token from being replayed indefinitely behind an invalid or malicious challenge.

### 5. JWT `exp`-based cache expiry

Earlier behavior effectively treated cached external-auth tokens as timeless unless explicitly invalidated by a later `401`.

This branch added:

- JWT payload parsing for the `exp` claim
- `expires_at` persistence in the token cache
- rejection of expired cache entries
- refusal to save already-expired tokens

If a token is not a JWT or has no parseable `exp`, the prototype falls back to server-side rejection as the expiration signal.

### 6. Typed external-auth errors

The branch introduced typed sentinel errors for key failure classes such as:

- missing challenge
- missing `WWW-Authenticate`
- invalid URL
- insecure URL
- untrusted URL
- poll failure
- decode failure
- poll timeout

This improved two things:

- retry logic can make decisions based on error kind instead of string matching
- tests can assert security-relevant behavior precisely

### 7. Cleanup behavior after successful polling

After a token is received, the client issues a best-effort `DELETE` to the token URL to clean up the server-side one-time polling resource.

The final implementation uses:

- `context.WithoutCancel(parentCtx)`
- plus a fixed 5-second timeout

That preserves the caller context values while preventing request cancellation from skipping cleanup in the success path.

## Concurrency and correctness behavior

The prototype includes a few useful correctness features that are worth keeping:

- **in-flight coalescing**: concurrent callers wait on a single token acquisition instead of opening multiple browser flows
- **generation fence**: if a token is invalidated during acquisition, the stale result is not written back into cache
- **explicit invalidation on rejected token**: a `401` against a cached token clears that token immediately

## Tests added or strengthened

The branch added or updated focused tests for:

- same-origin acceptance
- cross-origin rejection
- insecure URL rejection
- userinfo rejection
- trailing-dot hostname normalization
- IPv4/IPv6 loopback handling
- redirect-response rejection
- stale-token retry rules
- JWT `exp` cache behavior
- cleanup behavior
- typed error matching
- config-level loopback HTTP rules
- constructor/default wiring for the split auth subsystem
- file-store behavior for expired token persistence

## What this prototype is good for

This branch is a strong **security-conscious prototype** for local or controlled environments where Trino already exposes the external browser challenge flow.

It demonstrates:

- the client-side control flow
- a reasonable caching model
- the correct trust boundary for challenge URLs
- defense-in-depth around redirects, URL parsing, and token reuse

## What should be redesigned for production

If this is rebuilt from the ground up for production, these are the main areas to revisit.

### 1. Replace ad-hoc challenge parsing with a formal contract

Current prototype behavior parses `WWW-Authenticate` with regexes. That is acceptable for a prototype but brittle as a long-term contract.

Production direction:

- define a stricter parser for the bearer challenge format
- clearly document supported fields and escaping assumptions
- consider an internal representation that is easier to audit than raw string parsing

### 2. Keep the token lifecycle subsystem explicit

This branch already started that split with separate manager, poller, store, cache, and trust-policy components. That direction is worth preserving.

Production direction:

- define explicit token states
- support refresh/re-auth decisions more intentionally
- add metrics and audit logging around token acquisition and invalidation
- decide whether non-JWT opaque tokens need explicit TTL metadata from Trino

### 3. Strengthen observability

The prototype surfaces errors clearly, but production should add:

- structured logs for auth state transitions
- counters for challenge failures, cross-origin rejections, poll timeouts, and invalidations
- optional redacted tracing for browser auth sessions

### 4. Revisit browser-launch UX and deployment boundaries

This flow is naturally best suited for:

- local development
- single-user CLI environments

It is less natural for:

- shared servers
- headless service deployments
- remote MCP HTTP environments

Production direction:

- clearly separate local interactive auth from remote/server auth
- consider whether external browser auth should be disabled entirely for some deployment modes

### 5. Define a formal security policy

This branch implements a concrete security model, but production should make it explicit in docs and code comments:

- trust anchor is the original Trino request origin
- redirects are never implicitly trusted
- only loopback may use cleartext HTTP
- challenge URLs may not contain userinfo
- token cache must fail closed on malformed state

### 6. Expand verification beyond unit tests

The current tests are strong for package-level behavior. A production rewrite should also include:

- integration tests against a real Trino external-auth setup
- failure injection for malformed challenges and polling responses
- end-to-end tests for cancellation, retry, and cache reuse

## Recommended productionization principles

If rebuilding this feature from scratch, keep these invariants:

1. **Never trust challenge-provided endpoints without origin validation.**
2. **Never allow automatic redirects in the token polling path.**
3. **Allow cleartext HTTP only for literal loopback hosts.**
4. **Treat cache expiry as security-sensitive state, not convenience metadata.**
5. **Use typed errors for retry decisions and security policy enforcement.**
6. **Keep local interactive auth distinct from remote multi-tenant auth.**

## Files touched by this branch

- `internal/trino/client.go`
- `internal/trino/auth_transport.go`
- `internal/trino/external_auth.go`
- `internal/trino/external_auth_common.go`
- `internal/trino/external_auth_challenge.go`
- `internal/trino/external_auth_cache.go`
- `internal/trino/external_auth_store.go`
- `internal/trino/external_auth_poller.go`
- `internal/config/config.go`
- `internal/config/authmode_external.go`
- `internal/config/authmode_test.go`
- `internal/netutil/host.go`
- `internal/trino/external_auth_test.go`
- `README.md`

## Bottom line

This branch does more than patch a bug. It now contains both a hardened prototype and the beginning of a cleaner production-oriented split for a **secure Trino external browser-auth client**:

- origin-pinned
- redirect-safe
- loopback-aware
- expiry-aware
- concurrency-safe
- componentized
- test-covered

That makes it a strong base for a future production-grade implementation, with the core security model already enforced and the internal boundaries now much easier to harden further.
