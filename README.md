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
