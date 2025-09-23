package boot

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"time"

	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/gateway"
	"github.com/deep-rent/vouch/internal/middleware"
	"github.com/deep-rent/vouch/internal/proxy"
	"github.com/deep-rent/vouch/internal/rule"
	"github.com/deep-rent/vouch/internal/signer"
)

func NewGateway(ctx *Context, cfg config.Config) gateway.Gateway {
	host := cfg.Host
	port := cfg.Port
	readTimeout := time.Duration(cfg.ReadTimeout) * time.Second
	readHeaderTimeout := time.Duration(cfg.ReadHeaderTimeout) * time.Second
	idleTimeout := time.Duration(cfg.IdleTimeout) * time.Second
	maxHeaderBytes := cfg.MaxHeaderBytes

	proxy := NewProxy(ctx.WithField("proxy"), cfg.Proxy)
	guard := NewGuard(ctx.WithField("proxy"), cfg.Proxy)

	return gateway.New(
		gateway.WithHost(host),
		gateway.WithPort(port),
		gateway.WithReadTimeout(readTimeout),
		gateway.WithReadHeaderTimeout(readHeaderTimeout),
		gateway.WithIdleTimeout(idleTimeout),
		gateway.WithMaxHeaderBytes(maxHeaderBytes),
		gateway.WithLogger(ctx.Logger()),
		gateway.WithHandler(proxy),
		gateway.WithMiddleware(
			middleware.Catch(ctx.Logger()),
			middleware.Preflight(proxy),
			middleware.Health(proxy),
			middleware.Auth(guard),
		),
	)
}

func NewProxy(ctx *Context, cfg config.Proxy) http.Handler {
	scheme := cfg.Scheme
	host := cfg.Host
	port := cfg.Port
	path := cfg.Path
	minBufferSize := cfg.MinBufferSize
	maxBufferSize := cfg.MaxBufferSize
	flushInterval := time.Duration(cfg.FlushInterval) * time.Millisecond

	return proxy.New(
		proxy.WithScheme(scheme),
		proxy.WithHost(host),
		proxy.WithPort(port),
		proxy.WithPath(path),
		proxy.WithLogger(ctx.Logger()),
		proxy.WithMinBufferSize(minBufferSize),
		proxy.WithMaxBufferSize(maxBufferSize),
		proxy.WithFlushInterval(flushInterval),
		proxy.WithLogger(ctx.Logger()),
	)
}

func NewGuard(ctx *Context, cfg config.Proxy) auth.Guard {
	return auth.NewGuard(
		NewBouncer(ctx, cfg),
		NewStamper(ctx, cfg),
	)
}

func NewBouncer(ctx *Context, cfg config.Proxy) auth.Bouncer {
	return rule.NewBouncer(
		nil,
		nil,
	)
}

func NewStamper(ctx *Context, cfg config.Proxy) auth.Stamper {
	return auth.NewStamper(
		auth.WithUserHeader(cfg.Headers.User),
		auth.WithRolesHeader(cfg.Headers.Roles),
		auth.WithTokenHeader(cfg.Headers.Token),
		auth.WithSigner(NewSigner(ctx, cfg)),
	)
}

func NewSigner(ctx *Context, cfg config.Proxy) signer.Signer {
	key := cfg.Secret
	if key == "" {
		ctx.WithField("secret").
			Warn("No signing secret configured; proxy authentication is disabled")
		return nil
	}
	if len(key) < signer.MinimumKeyLength {
		ctx.WithField("secret").
			Warn("Signing secret should be at least %d characters long",
				signer.MinimumKeyLength)
	}
	alg := signer.ResolveAlgorithm(cfg.Algorithm)
	if alg == nil {
		ctx.WithField("algorithm").
			Error("Unknown signing algorithm", "name", cfg.Algorithm)
	}
	return signer.New(key, signer.WithAlgorithm(alg))
}

func NewTLSConfig(ctx *Context, cfg config.TLS) *tls.Config {
	out := &tls.Config{
		ServerName: cfg.ServerName,
	}
	if cfg.Insecure {
		ctx.WithField("insecure").
			Warn("Skipping TLS verification")
		out.InsecureSkipVerify = true
	}
	if name := cfg.MinVersion; name != "" {
		if id, ok := TLSVersion(ctx.WithField("minVersion"), name); ok {
			out.MinVersion = id
		}
	}
	if name := cfg.MaxVersion; name != "" {
		if id, ok := TLSVersion(ctx.WithField("maxVersion"), name); ok {
			out.MaxVersion = id
		}
	}
	if names := cfg.Ciphers; len(names) > 0 {
		out.CipherSuites = TLSCipherSuites(ctx.WithField("ciphers"), names)
	}
	if cert, key := cfg.Certificate, cfg.Key; cert != "" || key != "" {
		out.Certificates = TLSCertificates(ctx, cert, key)
	}
	if path := cfg.CA; path != "" {
		out.RootCAs = TLSRootCAs(ctx.WithField("ca"), path)
	}
	return out
}

func TLSVersion(ctx *Context, name string) (uint16, bool) {
	var id uint16
	secure := false
	switch name {
	case "TLS1.0":
		id = tls.VersionTLS10
	case "TLS1.1":
		id = tls.VersionTLS11
	case "TLS1.2":
		id = tls.VersionTLS12
		secure = true
	case "TLS1.3":
		id = tls.VersionTLS13
		secure = true
	default:
		ctx.Error("Unknown TLS version", "name", name)
		return 0, false
	}
	if !secure {
		ctx.Warn("Insecure TLS version", "name", name)
	}
	return id, true
}

func TLSCipherSuites(ctx *Context, names []string) []uint16 {
	suites := make([]uint16, 0, len(names))
	for i, name := range names {
		if id, ok := TLSCipherSuite(ctx.WithIndex(i), name); ok {
			suites = append(suites, id)
		}
	}
	return suites
}

func TLSCipherSuite(ctx *Context, name string) (uint16, bool) {
	for _, s := range tls.CipherSuites() {
		if s.Name == name {
			return s.ID, true
		}
	}
	for _, s := range tls.InsecureCipherSuites() {
		if s.Name == name {
			ctx.Warn("Insecure cipher suite", "name", name)
			return s.ID, true
		}
	}
	ctx.Error("Unknown cipher suite", "name", name)
	return 0, false
}

func TLSCertificates(ctx *Context, cert, key string) []tls.Certificate {
	if cert == "" {
		ctx.WithField("cert").
			Error("Missing certificate for private key")
		return nil
	}
	if key == "" {
		ctx.WithField("key").
			Error("Missing private key for certificate")
		return nil
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		ctx.Error("Couldn't load key pair", "error", err)
		return nil
	}
	return []tls.Certificate{pair}
}

func TLSRootCAs(ctx *Context, path string) *x509.CertPool {
	cp := x509.NewCertPool()
	ca, err := os.ReadFile(path)
	if err != nil {
		ctx.Error("Failed to read certificate file", "error", err)
		return nil
	}
	if ok := cp.AppendCertsFromPEM(ca); !ok {
		ctx.Error("Failed to parse PEM certificate")
		return nil
	}
	return cp
}
