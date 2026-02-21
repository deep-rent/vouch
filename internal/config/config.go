package config

import (
	"time"

	"github.com/deep-rent/nexus/env"
)

type Config struct {
	Level  string `env:",default:info"`
	Format string `env:",default:json"`

	Host              string        `env:",default:0.0.0.0"`
	Port              string        `env:",default:8080"`
	ReadHeaderTimeout time.Duration `env:",unit:s,default:5"`
	ReadTimeout       time.Duration `env:",unit:s,default:5"`
	WriteTimeout      time.Duration `env:",unit:s,default:5"`
	IdleTimeout       time.Duration `env:",unit:s,default:5"`
	MaxHeaderBytes    int           `env:",default:0"`
	UserNameHeader    string        `env:",default:X-Auth-CouchDB-UserName"`
	RolesHeader       string        `env:",default:X-Auth-CouchDB-Roles"`

	Issuers    []string      `env:",split"`
	Audiences  []string      `env:",split"`
	Leeway     time.Duration `env:",unit:s,default:30"`
	MaxAge     time.Duration `env:",unit:s,default:0"`
	AuthScheme string        `env:",default:Bearer"`
	RolesClaim string        `env:",default:_couchdb.roles"`

	JWKS                string        `env:",required"`
	UserAgent           string        `env:",default:Vouch"`
	Timeout             time.Duration `env:",unit:s,default:10"`
	MinRefreshInterval  time.Duration `env:",unit:s,default:60"`
	MaxRefreshInterval  time.Duration `env:",unit:s,default:28800"`
	BackoffMinDelay     time.Duration `env:",unit:s,default:1"`
	BackoffMaxDelay     time.Duration `env:",unit:s,default:120"`
	BackoffGrowthFactor float64       `env:",default:1.75"`
	BackoffJitterAmount float64       `env:",default:0.66"`
}

func Load() (*Config, error) {
	var cfg Config
	if err := env.Unmarshal(&cfg, env.WithPrefix("VOUCH_")); err != nil {
		return nil, err
	}
	return &cfg, nil
}
