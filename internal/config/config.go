package config

import "github.com/deep-rent/nexus/env"

type Config struct {
	JWKS       string   `env:",required"`
	UserAgent  string   `env:",default=Vouch"`
	RoleClaim  string   `env:",default:_couchdb.roles"`
	Audiences  []string `env:",split"`
	Issuers    []string `env:",split"`
	Leeway     int      `env:",default=0"`
	MaxAge     int      `env:",default=0"`
	UserHeader string   `env:",default:X-Auth-CouchDB-UserName"`
	RoleHeader string   `env:",default:X-Auth-CouchDB-Roles"`
}

func Load() (*Config, error) {
	var cfg *Config
	if err := env.Unmarshal(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
