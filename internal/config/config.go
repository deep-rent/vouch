package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-json"
	"github.com/goccy/go-yaml"
)

// Config holds the configuration options for the HTTP server handling inbound
// requests.
type Config struct {
	// Host is the hostname or IP address the server listens on.
	Host string `yaml:"host" json:"host"`

	// Port is the TCP port number the server listens on.
	Port int `yaml:"port" json:"port"`

	// ReadTimeout is the maximum duration in seconds for reading the entire
	// request, including the body.
	ReadTimeout int64 `yaml:"timeout" json:"timeout"`

	// ReadHeaderTimeout is the amount of time in seconds allowed to read
	// only the request headers.
	ReadHeaderTimeout int64 `yaml:"headerTimeout" json:"headerTimeout"`

	// IdleTimeout is the maximum lifetime of an idle keep-alive connection in
	// seconds.
	IdleTimeout int64 `yaml:"keepAliveTimeout" json:"keepAliveTimeout"`

	// MaxHeaderBytes controls the maximum number of bytes the server will read
	// from the request header.
	MaxHeaderBytes int `yaml:"maxHeaderSize" json:"maxHeaderSize"`

	// TLS customizes the server's TLS configuration.
	TLS TLS `yaml:"tls" json:"tls"`

	// Proxy configures the reverse proxy in front of CouchDB.
	Proxy Proxy `yaml:"proxy" json:"proxy"`
}

// Proxy holds the configuration options for the reverse proxy handling outbound
// requests to CouchDB.
type Proxy struct {
	// Scheme is the URL scheme used to connect to CouchDB.
	Scheme string `yaml:"scheme" json:"scheme"`

	// Host is the hostname or IP address of the CouchDB server to proxy to.
	Host string `yaml:"host" json:"host"`

	// Port is the TCP port number of the CouchDB server to proxy to.
	Port int `yaml:"port" json:"port"`

	// Path is the base path on the CouchDB server to proxy to.
	Path string `yaml:"path" json:"path"`

	// FlushInterval is the interval in milliseconds at which to flush
	// response data to the client.
	FlushInterval int64 `yaml:"flushInterval" json:"flushInterval"`

	// MinBufferSize is the minimum size of the buffer used for reading
	// request bodies.
	MinBufferSize int `yaml:"minBufferSize" json:"minBufferSize"`

	// MaxBufferSize is the maximum size of the buffer used for reading
	// request bodies.
	MaxBufferSize int `yaml:"maxBufferSize" json:"maxBufferSize"`

	// Headers customizes the names of the HTTP headers used for proxy
	// authentication against CouchDB.
	Headers Headers `yaml:"header" json:"header"`

	// Secret is the secret key used to sign proxy authentication tokens.
	Secret string `yaml:"secret" json:"secret"`

	// Algorithm is the signing algorithm used for proxy authentication tokens.
	Algorithm string `yaml:"algorithm" json:"algorithm"`

	// Rules is an ordered list of access control rules applied to requests.
	Rules []Rule `yaml:"rules" json:"rules"`

	// Token configures the validation of incoming JWTs.
	Token Token `yaml:"token" json:"token"`
}

// Headers contains the names of the HTTP headers used for proxy authentication.
type Headers struct {
	// User is the header used to convey the authenticated User name.
	User string `yaml:"user" json:"user"`

	// Roles is the header used to convey the authenticated user Roles.
	Roles string `yaml:"roles" json:"roles"`

	// Token is the header used to convey the proxy Token.
	Token string `yaml:"token" json:"token"`
}

// Unique reports whether the configured header names are distinct.
func (h Headers) Unique() bool {
	return h.User != h.Roles && h.User != h.Token && h.Roles != h.Token
}

// Rule represents a single access control rule.
type Rule struct {
	// Deny specifies whether to allow or deny matching requests.
	Deny bool `yaml:"deny" json:"deny"`

	// When is a boolean expression that determines when the rule applies.
	When string `yaml:"when" json:"when"`

	// User is an expression that returns the name of the authenticated user
	// in CouchDB.
	User string `yaml:"user" json:"user"`

	// Roles is an expression that returns the roles of the authenticated user
	// in CouchDB.
	Roles string `yaml:"roles" json:"roles"`
}

// Token holds the configuration options for validating incoming JWTs.
type Token struct {
	// Header is the name of the HTTP header from which to read tokens.
	Header string `yaml:"header" json:"header"`

	// Scheme is the authentication scheme used in the configured header.
	Scheme string `yaml:"scheme" json:"scheme"`

	// Audience is the expected audience of the tokens.
	Audience string `yaml:"audience" json:"audience"`

	// Issuer is the expected issuer of the tokens.
	Issuer string `yaml:"issuer" json:"issuer"`

	// Leeway is the amount of time in seconds to allow for clock skew when
	// checking the token's temporal validity.
	Leeway int64 `yaml:"leeway" json:"leeway"`

	// KeySet configures the JWKS endpoint from which to fetch public keys used
	// to verify token signatures.
	KeySet KeySet `yaml:"keySet" json:"keySet"`
}

// KeySet holds the configuration options for the JWKS cache.
type KeySet struct {
	// URL is the HTTP(S )endpoint from which to fetch the remote JWKS.
	URL string `yaml:"url" json:"url"`

	// MinInterval is the minimum duration to wait between successful
	// JWKS fetch attempts.
	MinInterval string `yaml:"minInterval" json:"minInterval"`

	// MaxInterval is the maximum duration to wait between successful
	// JWKS fetch attempts.
	MaxInterval string `yaml:"maxInterval" json:"maxInterval"`

	// Backoff configures the exponential backoff strategy applied when
	// retrying failed JWKS fetch attempts.
	Backoff Backoff `yaml:"backoff" json:"backoff"`

	// TLS configures the TLS settings used when fetching the JWKS.
	TLS TLS `yaml:"tls" json:"tls"`
}

// Backoff holds the configuration options for exponential backoff retries.
type Backoff struct {
	// MinDelay is the initial delay duration in milliseconds.
	MinDelay int64 `yaml:"minDelay" json:"minDelay"`

	// MaxDelay is the maximum delay duration in milliseconds.
	MaxDelay int64 `yaml:"maxDelay" json:"maxDelay"`

	// Factor is the multiplier applied to the delay after each retry.
	Factor float64 `yaml:"factor" json:"factor"`

	// Jitter is the percentage of randomization applied to the delay.
	Jitter float64 `yaml:"jitter" json:"jitter"`
}

// TLS holds the configuration options for TLS connections.
type TLS struct {
	// ServerName is used to verify the hostname on the returned
	// certificates and for Server Name Indication (SNI).
	// If empty, the server's address is used.
	ServerName string `yaml:"serverName" json:"serverName"`

	// MinVersion contains the minimum TLS version that is acceptable.
	// Supported values: "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3".
	// If empty, Go's default minimum is used.
	MinVersion string `yaml:"minVersion" json:"minVersion"`

	// MaxVersion contains the maximum TLS version that is acceptable.
	// Supported values: "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3".
	// If empty, no maximum is enforced.
	MaxVersion string `yaml:"maxVersion" json:"maxVersion"`

	// CipherSuites is a list of supported cipher suites. If empty, a default
	// list from the crypto/tls package will be used.
	// Example values: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	// "TLS_AES_128_GCM_SHA256".
	CipherSuites []string `yaml:"ciphers" json:"ciphers"`

	// CertFile is the path to the client's certificate file for mTLS.
	CertFile string `yaml:"cert" json:"cert"`

	// KeyFile is the path to the client's private key file for mTLS.
	KeyFile string `yaml:"key" json:"key"`

	// CAFile is the path to the Root Certificate Authority (CA) file
	// used to verify the server's certificate.
	CAFile string `yaml:"ca" json:"ca"`

	// InsecureSkipVerify controls whether a client verifies the server's
	// certificate chain and host name. If true, TLS is susceptible to
	// man-in-the-middle attacks. This should be used only for testing.
	// Defaults to false.
	InsecureSkipVerify bool `yaml:"insecure" json:"insecure"`
}

// Decoder decodes raw configuration data into the provided Go value.
type Decoder func(data []byte, v any) error

// infer detects the Decoder to use based on the file extension.
// Returns nil if no suitable Decoder is found.
func infer(path string) Decoder {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return json.Unmarshal
	case ".yaml", ".yml":
		return yaml.Unmarshal
	default:
		return nil
	}
}

// Default returns a Config struct initialized with defaults.
func Default() Config {
	return Config{}
}

// Load reads the configuration file from the given path, decodes it,
// and returns a populated Config struct by value.
// If dec is nil, it attempts to infer the decoder from the file extension.
func Load(path string, dec Decoder) (Config, error) {
	if dec == nil {
		if dec = infer(path); dec == nil {
			return Config{}, errors.New("unsupported format")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading failed: %w", err)
	}
	cfg := Default()
	if err := dec(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing failed: %w", err)
	}
	return cfg, nil
}
