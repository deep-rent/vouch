# Vouch

Vouch is a sidecar proxy for Apache CouchDB that offloads JWT-based authentication and authorization.

## Overview

While CouchDB supports JWT authentication, it requires a static set of verification keys to be configured upfront. Vouch acts as a reverse proxy that can fetch keys from a remote JWKS endpoint (e.g., from Keycloak or another OIDC provider), validate incoming requests, and then securely forward proxy authentication headers to CouchDB.

## Features

-   **Dynamic JWKS Fetching**: Automatically fetches and caches public keys from a JWKS endpoint.
-   **JWT Validation**: Validates JWTs from the `Authorization` header.
-   **Proxy Authentication**: Forwards user and role information to CouchDB via `X-Auth-CouchDB-UserName` and `X-Auth-CouchDB-Roles` headers.
-   **Configurable**: All settings are managed via environment variables.
-   **Structured Logging**: Provides structured logs for better observability.

## Configuration

Vouch is configured using environment variables:

| Variable                   | Description                                                 | Default                        |
| -------------------------- | ----------------------------------------------------------- | ------------------------------ |
| `VOUCH_JWKS_URL`           | The URL of the remote JWKS endpoint.                        | **(required)**                 |
| `VOUCH_COUCHDB_URL`        | The URL of the CouchDB instance to proxy to.                | **(required)**                 |
| `VOUCH_PORT`               | The port for the Vouch proxy to listen on.                  | `8080`                         |
| `VOUCH_ROLES_CLAIM`        | The name of the JWT claim containing the user's roles.      | `roles`                        |
| `VOUCH_LOG_LEVEL`          | The log level (`debug`, `info`, `warn`, `error`).           | `info`                         |
| `VOUCH_JWKS_FETCH_TIMEOUT` | The timeout for fetching the JWKS from the remote endpoint. | `10s`                          |

### CouchDB Configuration

You need to configure CouchDB to use a proxy for authentication. In your `local.ini` or `default.ini` file, add the following:

```ini
[chttpd]
authentication_handlers = {chttpd_auth, proxy_authentication_handler}, {chttpd_auth, default_authentication_handler}

[proxy]
proxy_use_credentials = true
```

### Security Note

For a production setup, it is highly recommended to secure the communication between Vouch and CouchDB. One way to do this is by using a shared secret token. CouchDB can be configured to require a specific header (e.g., `X-Auth-CouchDB-Token`) from the proxy.

This can be configured in CouchDB's `local.ini`:
```ini
[proxy]
proxy_use_credentials = true
authentication_secret = your-very-secret-token
```
Vouch does not currently support sending this token, but it can be added to the `forward.Proxy` handler.

## Running the Application

To run the application, first ensure that the dependencies are downloaded:
```sh
go mod tidy
```

Then, you can run the application:
```sh
export VOUCH_JWKS_URL="http://your-keycloak/realms/test/protocol/openid-connect/certs"
export VOUCH_COUCHDB_URL="http://localhost:5984"
go run ./cmd/vouch
```

The proxy will then be available at `http://localhost:8080`.

## Building

To build the application binary:
```sh
go build -o vouch ./cmd/vouch
```

## Packages Used

This project is built using the following packages from the `deep-rent/nexus` project:

-   `github.com/deep-rent/nexus/app`: For application bootstrapping.
-   `github.com/deep-rent/nexus/env`: For environment variable configuration.
-   `github.com/deep-rent/nexus/log`: For structured logging.
-   `github.com/deep-rent/nexus/jose/jwk`: For fetching and caching JWKS.
-   `github.com/deep-rent/nexus/jose/jwt`: For JWT validation.
-   `github.com/deep-rent/nexus/header`: For extracting credentials from headers.

The tests are written using `github.com/stretchr/testify`.
