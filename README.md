<h1 align="center">
  traefik-plugin-couchdb
</h1>

<p align="center">
  A Traefik middleware that authenticates requests with JWTs and authorizes access to CouchDB databases, forwarding credentials via CouchDB Proxy Authentication headers.
</p>

<p align="center">
  <img src="./.github/assets/logo.svg" width="64" height="64" alt="deep.rent GmbH"/>
</p>

## Features

- JWKS-backed JWT verification
  - JWKS can be a URL (http/https with background refresh) or inline JSON/object
  - Remote JWKS loaded via github.com/MicahParks/keyfunc/v3 (NewDefaultCtx)
- Optional issuer and audience validation
- Algorithm allowlist: RS256/384/512, ES256/384/512, PS256/384/512
- CORS preflight passthrough (OPTIONS forwarded without auth)
- Path-based authorization
  - Admins (adm=true) can access any database; role _admin is set
  - Non-admins are limited to: user_<uid>, team_<uid>, and team_<tid> (if present)
- CouchDB Proxy Authentication
  - Sets X-Auth-CouchDB-UserName and X-Auth-CouchDB-Roles
  - Optionally signs X-Auth-CouchDB-Expires and X-Auth-CouchDB-Token using HMAC-SHA1(secret, "username,roles,expires")
- Strips Authorization before forwarding to CouchDB
- URL-decodes the first path segment (database name)

## Requirements

- Traefik v2.10+ with plugins enabled
- CouchDB 3.x configured for Proxy Authentication
- An IdP that issues JWTs with a kid header and publishes a JWKS

## Installation

Enable the plugin in Traefik’s static configuration:

```yaml
experimental:
  plugins:
    traefik-plugin-couchdb:
      moduleName: github.com/deep-rent/traefik-plugin-couchdb
      version: v0.1.0
```

## Configuration (dynamic)

Attach the middleware to a router:

```yaml
http:
  routers:
    couchdb:
      rule: Host(`couch.example.com`)
      service: couchdb
      middlewares: [couchdb-jwt]

  services:
    couchdb:
      loadBalancer:
        servers:
          - url: http://couchdb:5984

  middlewares:
    couchdb-jwt:
      plugin:
        traefik-plugin-couchdb:
          # JWKS can be a URL (auto-refresh), a raw JSON string, or an inline object
          jwks: https://idp.example.com/.well-known/jwks.json
          issuer: https://idp.example.com/
          audience: ["couchdb"]
          proxySecret: "super-secret"
          lifetime: 300
          leeway: 60
```

### Configuration reference

| Key         | Type               | Required | Default | Description                                                                                                                                                                                                 | Example |
|------------|--------------------|----------|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------|
| jwks       | string or object   | yes      | —       | JWKS source. If a string URL is given, keys will be fetched from there. If a string is JSON or value is an inline object/array, it’s parsed locally as a JWKS.            | URL: <https://idp.example.com/.well-known/jwks.json>; Object: { keys: [ … ] } |
| issuer     | string             | no       | ""      | If set, the JWT `iss` claim must match this value.                                                                                                                                                  | "<https://idp.example.com/>" |
| audience  | array of strings   | no       | []      | If set, the JWT `aud` claim must contain at least one of these.                                                                                                                        | ["couchdb"] |
| proxySecret| string             | no       | ""      | When set, signs CouchDB proxy headers (recommended).                                                                                                           | "super-secret" |
| lifetime   | int (seconds)      | no       | 600     | Expiration offset for `X-Auth-CouchDB-Expires` when `proxySecret` is set.                                                                                                                                       | 300 |
| leeway     | int (seconds)      | no       | 60       | Allowed clock skew for validating the temporal validity of tokens.                                                                                                                                             | 0 |

Notes:

- Inline object JWKS is convenient in YAML/TOML (no string escaping).
- Remote JWKS enables background refresh and unknown-kid refresh via keyfunc defaults.

### JWKS examples

- URL:

  ```yaml
  jwks: https://idp.example.com/.well-known/jwks.json
  ```

- Inline object:

  ```yaml
  jwks:
    keys:
      - kty: RSA
        kid: kid1
        use: sig
        alg: RS256
        n: "<base64url modulus>"
        e: AQAB
  ```

- Inline JSON string:

  ```yaml
  jwks: >
    {"keys":[{"kty":"RSA","kid":"kid1","use":"sig","alg":"RS256","n":"...","e":"AQAB"}]}
  ```

## Expected JWT claims

- Private:
  - uid (string, required): user ID used as CouchDB username and for path authorization
  - tid (string, optional): team ID; adds team_<tid> to allowed databases
  - adm (bool, optional): grants admin access and sets role _admin
- Standard:
  - exp (required), iat, nbf (validated with leeway)
  - iss (validated when configured)
  - aud (validated when configured)
  - Header must include kid that resolves via JWKS

## Behavior

- CORS preflight (OPTIONS) requests bypass authentication
- On success:
  - Adds `X-Auth-CouchDB-UserName` and `X-Auth-CouchDB-Roles` headers
  - If `proxySecret` is set, also adds `X-Auth-CouchDB-Expires` and `X-Auth-CouchDB-Token` headers
  - Strips the `Authorization` header before forwarding
- On failure:
  - 401 Unauthorized with `WWW-Authenticate` for missing/invalid token
  - 403 Forbidden when authenticated but not authorized for the target database
