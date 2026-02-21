package config

import (
	"net/url"
	"time"

	"github.com/deep-rent/nexus/env"
)

type Config struct {
	LogLevel                  string        `env:",default:info"`
	LogFormat                 string        `env:",default:json"`
	Target                    *url.URL      `env:",default:http://localhost:5984"`
	Host                      string        `env:",default:0.0.0.0"`
	Port                      string        `env:",default:5984"`
	ReadHeaderTimeout         time.Duration `env:",unit:s,default:5"`
	ReadTimeout               time.Duration `env:",unit:s,default:30"`
	WriteTimeout              time.Duration `env:",unit:s,default:0"`
	IdleTimeout               time.Duration `env:",unit:s,default:120"`
	MaxHeaderBytes            int           `env:",default:0"`
	UserNameHeader            string        `env:",default:X-Auth-CouchDB-UserName"`
	RolesHeader               string        `env:",default:X-Auth-CouchDB-Roles"`
	FlushInterval             time.Duration `env:",unit:s,default:-1"`
	MinBufferSize             int           `env:",default:32768"`
	MaxBufferSize             int           `env:",default:262144"`
	MaxIdleConns              int           `env:",default:1000"`
	IdleConnTimeout           time.Duration `env:",unit:s,default:90"`
	TokenIssuers              []string      `env:",split"`
	TokenAudiences            []string      `env:",split"`
	TokenLeeway               time.Duration `env:",unit:s,default:30"`
	TokenMaxAge               time.Duration `env:",unit:s,default:0"`
	TokenAuthScheme           string        `env:",default:Bearer"`
	TokenRolesClaim           string        `env:",default:_couchdb.roles"`
	KeySetURL                 string        `env:",required"`
	KeySetUserAgent           string        `env:",default:Vouch"`
	KeySetTimeout             time.Duration `env:",unit:s,default:10"`
	KeySetMinRefreshInterval  time.Duration `env:",unit:s,default:60"`
	KeySetMaxRefreshInterval  time.Duration `env:",unit:s,default:28800"`
	KeySetBackoffMinDelay     time.Duration `env:",unit:s,default:1"`
	KeySetBackoffMaxDelay     time.Duration `env:",unit:s,default:120"`
	KeySetBackoffGrowthFactor float64       `env:",default:1.75"`
	KeySetBackoffJitterAmount float64       `env:",default:0.66"`
}

func Load() (*Config, error) {
	var cfg Config
	if err := env.Unmarshal(&cfg, env.WithPrefix("VOUCH_")); err != nil {
		return nil, err
	}
	return &cfg, nil
}
