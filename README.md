<h1 align="center">
  traefik-plugin-couchdb
</h1>

<p align="center">
  Traefik middleware that offloads token-based authentication and authorization for Apache CouchDB.
</p>

<p align="center">
<a href="https://github.com/deep-rent/traefik-plugin-couchdb/actions/workflows/test.yml"><img src="https://github.com/deep-rent/traefik-plugin-couchdb/actions/workflows/test.yml/badge.svg"/></a>
<a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg"/></a>
<a href="https://github.com/deep-rent/traefik-plugin-couchdb/releases/latest"><img src="https://img.shields.io/github/v/release/deep-rent/traefik-plugin-couchdb?label=Release"/></a>
</p>

<p align="center">
  <a href="https://couchdb.apache.org">
    <img src="./.github/assets/icon.png" width="64" height="64" alt="Apache CouchDB"/>
  </a>
</p>

## Contents

- [Overview](#overview)
- [How it Works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [Legal Notice](#legal-notice)
- [Maintenance](#maintenance)
- [Development](#development)

## Overview

This middleware plugin validates incoming JSON Web Tokens (JWTs) against a JSON Web Key Set (JWKS), evaluates ordered authorization rules, and forwards CouchDB “trusted proxy” headers to your CouchDB node or cluster. When a proxy secret is configured, it also signs the forwarded identity, securing the connection between Traefik and CouchDB.

In practice, this lets you:
- **Centralize Access Control:** Keep CouchDB anonymous and let Traefik enforce authentication and authorization at the edge.
- **Create Dynamic Policies:** Implement per-user databases and role-based access without touching CouchDB design documents.
- **Simplify Your Stack:** Remove bearer tokens before traffic reaches CouchDB.

<a name="how-it-works"></a>

## How it Works

The middleware processes requests in three stages. If authentication or authorization fails, the processing stops immediately, and an appropriate HTTP status code is returned (401 or 403).

1. **Authentication:** The plugin extracts the bearer token from the Authorization header and verifies its signature and claims against the configured JWKS.
2. **Authorization:** It builds an evaluation context containing the token claims and request details, then evaluates your rule expressions in order. The first rule that matches determines whether to allow or deny the request.
3. **Forwarding:** On success, it strips the Authorization header and adds the X-Auth-CouchDB-* headers before proxying the request to CouchDB. OPTIONS requests are passed through without modifications to support CORS pre-flight checks.

<a name="prerequisites"></a>

## Prerequisites

Before getting started, ensure that your setup meets the minimum requirements:

- **Traefik v3.2 or later** with plugin support enabled.
- **Apache CouchDB v3.3.1 or later** configured for proxy authentication.
- An **Identity Provider** that issues JWTs and exposes a JWKS endpoint.

In the CouchDB `local.ini` (or equivalent configuration) you must enable the proxy authentication handler for the integration to work:

```ini
[chttpd_auth]
authentication_handlers = {chttpd_auth, cookie_authentication_handler}, {chttpd_auth, proxy_authentication_handler}
require_valid_user = true
```

Please refer to the [CouchDB documentation](https://docs.couchdb.org/en/stable/api/server/authn.html#proxy-authentication) for more information.

<a name="quick-start"></a>

## Quick Start

This guide will walk you through setting up the plugin using a complete, runnable example with **Docker Compose**. You'll enable the plugin, configure it with a JWKS and authorization rules, and attach it to your CouchDB router.

**Step 1: Configure Traefik**

First, you'll need a static Traefik configuration file (`traefik.yml`). This file tells Traefik how to load the plugin and where to find your dynamic configuration.

```yaml
# traefik.yml

log:
  level: INFO

api:
  insecure: true

entryPoints:
  websecure:
    address: ':443'

providers:
  docker:
    exposedByDefault: false
  file:
    filename: /etc/traefik/dynamic.yml

experimental:
  plugins:
    github-com-deep-rent-traefik-plugin-couchdb:
      modulename: github.com/deep-rent/traefik-plugin-couchdb
      version: v0.2.0
```

**Step 2: Define the Middleware**

Next, create a dynamic configuration file (`dynamic.yml`). This is where you'll define the plugin middleware, add your authorization rules, and set up the Traefik router and service for CouchDB.

```yaml
# dynamic.yml

http:
  middlewares:
    couchdb-auth:
      plugin:
        github.com/deep-rent/traefik-plugin-couchdb:
          jwks: https://auth.example.com/.well-known/jwks.json
          secret: NyH2b4ltJ1l3wRnuQXgH7Fnrl7PKzYQH
          issuer: https://auth.example.com/
          audience: ['couchdb-api']
          strict: true
          leeway: 60
          algorithms: [ES256, ES384, ES512]
          rules:
            - when: 'C["sub"] == "bob"'
              mode: deny
            - when: 'true'
              mode: allow
          headers:
            user: X-Auth-CouchDB-UserName
            role: X-Auth-CouchDB-Roles
            token: X-Auth-CouchDB-Token

  routers:
    couchdb:
      rule: 'Host(`couch.example.com`)'
      entryPoints: ['websecure']
      service: 'couchdb'
      middlewares: ['couchdb-auth']
      tls:
        certResolver: letsencrypt

  services:
    couchdb:
      loadBalancer:
        servers:
          - url: 'http://couchdb:5984'
```

**Step 3: Run with Docker Compose**

To launch the full example, create a `docker-compose.yml` file. This file will orchestrate Traefik, CouchDB, and an optional mock JWKS server for local testing. Place the configuration files from the previous steps in the same directory. Observe that the `local.ini` and `jwks.json` files will be mounted as well, although they are optional.

```yaml
# docker-compose.yml

version: '3.9'

services:
  traefik:
    image: traefik:v3
    restart: unless-stopped
    ports:
      - '80:80'
      - '443:443'
    volumes:
      - ./traefik.yml:/etc/traefik/traefik.yml:ro
      - ./dynamic.yml:/etc/traefik/dynamic.yml:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - traefik-acme:/acme
    networks:
      - traefik

  couchdb:
    image: couchdb:3
    restart: unless-stopped
    environment:
      COUCHDB_USER: admin
      COUCHDB_PASSWORD: password
    volumes:
      - ./local.ini:/opt/couchdb/etc/local.d:ro
      - couchdb-data:/opt/couchdb/data
    networks:
      - traefik

  jwks:
    image: nginx:alpine
    restart: unless-stopped
    volumes:
      - ./jwks.json:/usr/share/nginx/html/.well-known/jwks.json:ro
    ports:
      - "8080:80"
    networks:
      - traefik

volumes:
  traefik-acme:
  couchdb-data:

networks:
  traefik:
    driver: bridge
```

<a name="configuration"></a>

## Configuration

### Summary

| Option                                 | Required | Description                             |
|----------------------------------------|----------|-----------------------------------------|
| [ `jwks` ]( #option-jwks )             | yes      | JWKS used for signature verification    |
| [ `rules` ]( #option-rules )           | yes      | Authorization rules                     |
| [ `secret` ]( #option-secret )         | no       | CouchDB proxy signing secret            |
| [ `issuer` ]( #option-issuer )         | no       | Token issuer to match                   |
| [ `audience` ]( #option-audience )     | no       | Acceptable token audiences              |
| [ `leeway` ]( #option-leeway )         | no       | Clock skew tolerance for token lifespan |
| [ `strict` ]( #option-strict )         | no       | Prohibit non-expiring tokens            |
| [ `algorithms` ]( #option-algorithms ) | no       | Allowed signature algorithms            |
| [ `headers` ]( #option-headers )       | no       | Custom CouchDB proxy header names       |

### Details

<a name="option-jwks"></a>

#### `jwks`

**Required.** Specifies either a single JWKS endpoint, a list of such endpoints, or an inline JWKS object. If one or more URLs are specified, the plugin fetches keys from these endpoints and refreshes them continuously. A static JWKS can be defined as shown below. Also note the nesting of the `keys` array beneath `jwks` when providing a static JWKS.

```yaml
jwks:
  keys:
    - kty: EC
      use: sig
      kid: Is1uskkAi3KCrz14riT82BwtWqMYPPCCshvmb4A8hvE
      alg: ES256
      crv: P-256
      x: yxKwnD25UKgQiRi1md_mYUZzw0AjCgF88RCTvX6lihQ
      y: 2XAQO8F8266bk2jCrefbiy-eFCTJLLofQpZKn0PSHpE
    - kty: RSA
      use: sig
      kid: Bg1SKFhYebULc1qrJoL0lPqGoEtn8AqoUsxfTFPkJb0
      alg: RS256
      n: s3GCmurZR4HUil2EwrrP75efzlGSyXKt_VrTiOXDyOLI_LIxdIv58ro_VXfhNdZc4N0rYU9YFgfEgjxvSXmZXt0DB_yPCKotDIXnmfbjsrU3e1rFpkam25CZCdZ-oPU72DCnEaY-Q4zl1X6_0O_3eYJOx9QFHIr8OrjrYBvWfyBNdO77qe3ZD5guJNwHQKznnsg0yq_Qr9z6KTI_hBqk_azzOn1NJuulMc2aPXNe9_WkUURN7eA_6rYi_vUrG2UctinS7RF38ks6zU1OOXs3PLOVrXzNG5G-b5KbcrRk8nz_Ms2WGer8JV4WwppjLOM5vTfirirH1YrgsWF_BpTpzQ
      e: AQAB
```

<a name="option-rules"></a>

#### `rules`

**Required.** Defines the authorization rules that determine valid interactions with the CouchDB API. Every rule consists of a boolean `when` expression and a `mode`. If the `when` condition is met, then access is either allowed or denied, depending on the rule’s mode. Rules are applied in order, and the first match decides. If no rule matches, access is denied. The rule list must be non-empty, or else an error will be raised during startup.

Rules in `allow` mode must specify a `user` expression that evaluates to a string, which is the username forwarded to CouchDB via a proxy header. Optionally, the rule can also specify `role`. This expression may return:
- a single role name as a string,
- a comma-separated list of role names as a string, or
- an array of role names.

These roles are forwarded in a proxy header.

```yaml
rules:
  - when: 'C["adm"] == true'
    mode: allow
    user: 'C["sub"]'
    role: '"_admin"'
  - when: 'Method in ["PUT", "DELETE"] && HasPrefix(DB, "logs_")'
    mode: deny
  - when: 'DB == "user_" + C["sub"]'
    mode: allow
    user: 'C["sub"]'
    role: '["reader", "writer"]'
```

Expressions adhere to the [Expr](https://expr-lang.org/docs/language-definition) syntax. The expression environment provides the following variables and utility functions:

- `Claims` (alias `C`): the mapping of claim values by name (e.g., `C["sub"]`).
- `Method`: the HTTP request method (`GET`, `POST`, ...).
- `Path`: the HTTP request path (for example, `/db/_all_docs`).
- `DB`: the database name (first segment of `Path`).
- `HasPrefix(s, prefix)`: indicates whether `s` starts with `prefix`.
- `HasSuffix(s, suffix)`: indicates whether `s` ends with `suffix`.

<a name="option-secret"></a>

#### `secret`

**Optional.** The shared secret used to sign proxy tokens sent to CouchDB. Enabling this in CouchDB is highly recommended for production.

It must match the secret in your CouchDB configuration:

```ini
[chttpd_auth]
proxy_use_secret = true
secret = your-proxy-secret
```

<a name="option-issuer"></a>

#### `issuer`

**Optional.** The expected value of the `iss` (issuer) claim in the JWT. If omitted, any value is accepted.

<a name="option-audience"></a>

#### `audience`

**Optional.** An array of acceptable values for the `aud` (audience) claim. If provided, at least one value must match. If omitted, any value is accepted.

<a name="option-leeway"></a>

#### `leeway`

**Optional.** The allowed time drift (in seconds) to account for clock skew between the token issuer and Traefik when validating the `nbf` (not before) and `exp` (expires at) claims.

<a name="option-strict"></a>

#### `strict`

**Optional.** If enabled, all tokens must contain an `exp` claim. Non-expiring tokens will be rejected. Disabled by default.

<a name="option-algorithms"></a>

#### `algorithms`

**Optional.** Narrows down the supported JSON Web Algorithms (JWAs) for verifying token signatures. By default, it includes `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, and `PS512`.

<a name="option-headers"></a>

#### `headers`

**Optional.** Customizes the names of the CouchDB proxy headers to inject. Only change these if you have customized the corresponding `x_auth_*` settings in your CouchDB config.

Default values:

```yaml
user: X-Auth-CouchDB-UserName
role: X-Auth-CouchDB-Roles
token: X-Auth-CouchDB-Token
```

<a name="usage"></a>

## Usage

Below are some common policy examples for the `rules` configuration.

**Use Cases:**

* [Admin Full Access](#use-case-admin-full-access)
* [Per-User Private Databases](#use-case-per-user-private-databases)
* [Role-based Access](#use-case-role-based-access)
* [Append-Only Databases](#use-case-append-only-databases)

<a name="use-case-admin-full-access"></a>

### Admin Full Access

Grant a user with an `"adm": true` claim the `_admin` role in CouchDB.

```yaml
rules:
  - when: 'C["adm"] == true'
    mode: allow
    user: 'C["sub"]'
    role: '"_admin"' # CouchDB's special admin role
```

<a name="use-case-per-user-private-databases"></a>

### Per-User Private Databases

Grant users read/write access only to a database named after their unique user identifier (given by the `sub` claim).

```yaml
rules:
  - when: 'DB == "user_" + C["sub"]'
    mode: allow
    user: 'C["sub"]'
    rike: '["reader", "writer"]' # These roles must exist in the database's _security document
```

<a name="use-case-role-based-access"></a>

### Role-based Access

Map JWT roles to CouchDB roles for a shared database.

```yaml
rules:
  # Admins can do anything in the "shared" database
  - when: 'DB == "shared" && "admin" in C["rol"]'
    mode: allow
    user: 'C["sub"]'
    role: '["editor", "reader"]'

  # Editors can write to the "shared" database
  - when: 'DB == "shared" && "editor" in C["rol"]'
    mode: allow
    user: 'C["sub"]'
    role: '"editor"'

  # Everyone else gets read-only access to "shared"
  - when: 'DB == "shared"'
    mode: allow
    user: 'C["sub"]'
    role: '"reader"'
```

<a name="use-case-append-only-databases"></a>

### Append-Only Databases

Prevent updates and deletions to certain databases, making them append-only. This is ideal for audit logs or historical records where existing data must not be changed.

```yaml
rules:
  # Documents in databases prefixed with "logs_" cannot be altered
  # New documents are still allowed
  - when: 'Method in ["PUT", "DELETE"] && HasPrefix(DB, "logs_")'
    mode: deny
  - when: 'true'
    mode: allow
    user: 'C["sub"]'
```

<a name="security-considerations"></a>

## Security Considerations

- Always use HTTPS for JWKS endpoints.
- Prefer TLS (or mTLS) between Traefik and CouchDB. Make it mandatory when traffic crosses hosts or untrusted networks.
- Keep the proxy secret strong and rotate it periodically.
- Restrict Traefik access to CouchDB; CouchDB should not be publicly reachable.
- Limit accepted algorithms, issuer, and audience to the necessary minimum.

<a name="legal-notice"></a>

## Legal Notice

Licensed under the Apache License, Version 2.0. See the `LICENSE` file for further details.

Apache, Apache CouchDB and the CouchDB logo are trademarks of The Apache Software Foundation. This project is not endorsed by or affiliated with The Apache Software Foundation.

<a name="maintenance"></a>

## Maintenance

If you discover a security vulnerability, please report it privately to [support@deep.rent](mailto:support@deep.rent) instead of opening a public GitHub issue. Public issue reports can disclose vulnerabilities and increase the risk of exploitation before a fix is available.

<a name="development"></a>

## Development

This plugin has been developed by deep.rent GmbH and was originally created for company-internal use. It is currently feature-frozen and will not receive major new features. Security fixes may be provided as needed.

<p align="center">
  <a href="https://www.deep.rent">
    <img src="./.github/assets/logo.svg" width="64" height="64" alt="deep.rent GmbH"/>
  </a>
</p>
