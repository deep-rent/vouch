---
applyTo: "**/*.go"
---

# Project Overview

This Go-based **reverse proxy** offloads access control from **Apache CouchDB**. It is designed
to be deployed as a **sidecar container** alongside CouchDB instances. The proxy server
authenticates incoming requests based on **JSON Web Tokens** (JWTs), and determines the
authorization scope using **rule expressions** in `expr` syntax. Each rule is evaluated against
the token claims and request parameters. The first matching rule decides. Upon a rule match, the
request is enriched with additional authentication headers (`X-Auth-CouchDB-*`) and forwarded to
the upstream server. Configuration is read from a YAML file on startup, and JSON Web Keys (JWKs)
for signature verification are periodically fetched from a JWKS endpoint.

## Code Quality

- Focus on clean, readable, and maintainable code
- Reduce cyclomatic complexity, enhance testability, and apply common design patterns
- Prefer short variable names in small scopes and longer, descriptive names in larger scopes
- Avoid deep nesting and long functions; break them into smaller, reusable components
- Follow Go idioms and best practices
- Use the `log/slog` package to produce structured logs

## Performance

- Analyze the code to identify potential performance bottlenecks, memory leaks, and concurrency issues
- Look for opportunities to optimize algorithms and data structures
- Ensure efficient use of goroutines and channels

## Tests

- Make use of the `assert` and `require` packages from `github.com/stretchr/testify`
- Cover both typical use cases and edge cases
- Write table-driven tests where applicable and parallelize when possible

## Documentation

- Generate comprehensive documentation comments
- Adhere to the official style guidelines: https://go.dev/doc/comment
- Give usage examples where appropriate
- Enforce the print width of 80 characters also for comments

## Libraries

- `github.com/expr-lang/expr` for dynamic expressions
- `github.com/lestrrat-go/jwx/v3` for JOSE operations
- `gopkg.in/yaml.v3` for YAML parsing
- `github.com/spf13/pflag` for command-line arguments
