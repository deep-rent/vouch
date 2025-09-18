package config

type Config struct {
	Gateway `yaml:",inline"`
}

// Gateway configures a gateway.Gateway instance.
type Gateway struct {
	Host              string    `yaml:"host"`
	Port              int       `yaml:"port"`
	Transport         Transport `yaml:",inline"`
	ReadTimeout       int       `yaml:"readTimeout"`
	ReadHeaderTimeout int       `yaml:"readHeaderTimeout"`
	IdleTimeout       int       `yaml:"idleTimeout"`
	MaxHeaderBytes    int       `yaml:"maxHeaderBytes"`
	Proxy             Proxy     `yaml:"proxy"`
}

// Transport configures a http.Transport instance.
type Transport struct{}

// Proxy configures a proxy.Proxy instance.
type Proxy struct {
	Scheme        string  `yaml:"scheme"`
	Host          string  `yaml:"host"`
	Port          int     `yaml:"port"`
	Path          string  `yaml:"path"`
	FlushInterval int     `yaml:"flushInterval"`
	MinBufferSize int     `yaml:"minBufferSize"`
	MaxBufferSize int     `yaml:"maxBufferSize"`
	Bouncer       Bouncer `yaml:",inline"`
	Stamper       Stamper `yaml:",inline"`
}

// Bouncer configures an auth.Bouncer instance.
type Bouncer struct {
	Token Parser `yaml:"token"`
	Rules []Rule `yaml:"rules"`
}

// Rule configures a rule.Rule instance.
type Rule struct {
	Mode  string `yaml:"mode"`
	When  string `yaml:"when"`
	User  string `yaml:"user"`
	Roles string `yaml:"roles"`
}

type Header struct {
	User  string `yaml:"user"`
	Roles string `yaml:"roles"`
	Token string `yaml:"token"`
}

// Stamper configures an auth.Stamper instance.
type Stamper struct {
	Header Header `yaml:"header"`
	Signer Signer `yaml:",inline"`
}

// Signer configures a signer.Signer instance.
type Signer struct {
	Secret    string `yaml:"secret"`
	Algorithm string `yaml:"algorithm"`
}

// Parser configures a token.Parser instance.
type Parser struct {
	Header   string `yaml:"header"`
	Scheme   string `yaml:"scheme"`
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	Leeway   int    `yaml:"leeway"`
	KeySet   KeySet `yaml:"keys"`
}

// KeySet configures a token.KeySet instance (backed by cache.Cache).
type KeySet struct {
	URL         string  `yaml:"url"`
	MinInterval string  `yaml:"minInterval"`
	MaxInterval string  `yaml:"maxInterval"`
	Timeout     int     `yaml:"timeout"`
	Backoff     Backoff `yaml:"backoff"`
}

// Backoff configures a retry.Backoff instance.
type Backoff struct {
	MinDelay int     `yaml:"minDelay"`
	MaxDelay int     `yaml:"maxDelay"`
	Factor   float64 `yaml:"factor"`
	Jitter   float64 `yaml:"jitter"`
}

func Default() Config {
	// All fields zero-valued is what we want here. The defaulting logic is
	// outsourced to the respective packages
	return Config{}
}
