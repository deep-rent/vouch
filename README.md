# Vouch

[![Coverage](https://img.shields.io/badge/Coverage-89.0%25-brightgreen)](https://deep-rent.github.io/vouch)
[![Report](https://goreportcard.com/badge/github.com/deep-rent/vouch)](https://goreportcard.com/report/github.com/deep-rent/vouch)
![Test](https://github.com/deep-rent/vouch/actions/workflows/test.yml/badge.svg)
![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)
![Release](https://img.shields.io/github/v/release/deep-rent/vouch?label=Release)

Vouch is a lightweight proxy for Apache CouchDB designed to offload token-based authentication. It is intended to be deployed as a sidecar container alongside your CouchDB instance.

## Features

*   **Token-based Authentication:** Secure your CouchDB instance with token-based authentication.
*   **JWKS Support:** Fetch signature verification keys from a remote JWKS endpoint and cache them locally.
*   **Modern Algorithms:** Supports Ed448 and Ed25519 signature algorithms.
*   **Proxy Authentication:** Forwards the authenticated username and roles to CouchDB via proxy authentication headers.
*   **Configurable Claims:** Extract the username from the "sub" claim and roles from a configurable claim in the JWT.

## Deployment

Vouch is designed to be deployed as a sidecar to your CouchDB container. This means it runs in the same pod (in Kubernetes terms) or container group as your CouchDB instance, intercepting incoming requests to handle authentication before they reach CouchDB.

## Authentication Flow

1.  An incoming request with a bearer token reaches Vouch.
2.  Vouch verifies the token's signature using the configured JWKS endpoint or local keys.
3.  Upon successful verification, Vouch extracts the username from the "sub" claim of the token.
4.  If a roles claim is configured, Vouch extracts the roles from the specified claim.
5.  Vouch forwards the request to CouchDB, including the extracted username and roles in the `X-Auth-CouchDB-UserName` and `X-Auth-CouchDB-Roles` proxy authentication headers.
6.  CouchDB uses these headers to authorize the request.

## Configuration

Vouch is configured using environment variables. The following table lists the available variables and their default values:

| Environment Variable | Description | Default |
| --- | --- | --- |
| `VOUCH_LOG_LEVEL` | Log level (e.g., debug, info, warn, error). | `info` |
| `VOUCH_LOG_FORMAT` | Log format (e.g., text, json). | `json` |
| `VOUCH_UPDATER_ENABLED` | Enable checking for new releases. | `false` |
| `VOUCH_UPDATER_BASE_URL` | Base URL for the updater. | |
| `VOUCH_HOST` | Host to bind the server to. | `0.0.0.0` |
| `VOUCH_PORT` | Port to bind the server to. | `8080` |
| `VOUCH_READ_HEADER_TIMEOUT` | Read header timeout. | `5s` |
| `VOUCH_READ_TIMEOUT` | Read timeout. | `30s` |
| `VOUCH_WRITE_TIMEOUT` | Write timeout. | `0s` |
| `VOUCH_IDLE_TIMEOUT` | Idle timeout. | `120s` |
| `VOUCH_MAX_HEADER_BYTES` | Maximum header bytes. | `0` |
| `VOUCH_USER_NAME_HEADER` | Header to forward the username. | `X-Auth-CouchDB-UserName` |
| `VOUCH_ROLES_HEADER` | Header to forward the roles. | `X-Auth-CouchDB-Roles` |
| `VOUCH_TARGET` | Target URL for the proxy. | `http://localhost:5984` |
| `VOUCH_FLUSH_INTERVAL` | Flush interval for streaming responses. | `-1` |
| `VOUCH_MIN_BUFFER_SIZE` | Minimum buffer size for streaming responses. | `32768` |
| `VOUCH_MAX_BUFFER_SIZE` | Maximum buffer size for streaming responses. | `262144` |
| `VOUCH_MAX_IDLE_CONNS` | Maximum number of idle connections to the target. | `512` |
| `VOUCH_IDLE_CONN_TIMEOUT` | Idle connection timeout for connections to the target. | `90s` |
| `VOUCH_TOKEN_ISSUERS` | Comma-separated list of allowed token issuers. | |
| `VOUCH_TOKEN_AUDIENCES`| Comma-separated list of allowed token audiences. | |
| `VOUCH_TOKEN_LEEWAY` | Leeway for token expiration. | `30s` |
| `VOUCH_TOKEN_MAX_AGE` | Maximum age of a token. | `0s` |
| `VOUCH_TOKEN_AUTH_SCHEME` | Authentication scheme for tokens. | `Bearer` |
| `VOUCH_TOKEN_ROLES_CLAIM` | Claim to extract roles from. | `_couchdb.roles` |
| `VOUCH_KEYS_URL` | URL to fetch the JWKS from. | **required** |
| `VOUCH_KEYS_TIMEOUT` | Timeout for fetching keys. | `10s` |
| `VOUCH_KEYS_MIN_REFRESH_INTERVAL` | Minimum refresh interval for keys. | `1m` |
| `VOUCH_KEYS_MAX_REFRESH_INTERVAL` | Maximum refresh interval for keys. | `10080m` |
| `VOUCH_KEYS_ATTEMPT_LIMIT` | Attempt limit for fetching keys. | `0` |
| `VOUCH_KEYS_BACKOFF_MIN_DELAY` | Minimum backoff delay for fetching keys. | `1s` |
| `VOUCH_KEYS_BACKOFF_MAX_DELAY` | Maximum backoff delay for fetching keys. | `120s` |
| `VOUCH_KEYS_BACKOFF_GROWTH_FACTOR` | Backoff growth factor for fetching keys. | `1.75` |
| `VOUCH_KEYS_BACKOFF_JITTER_AMOUNT` | Backoff jitter amount for fetching keys. | `0.66` |
