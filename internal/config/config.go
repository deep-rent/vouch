package config

import (
	"net/url"
	"time"

	"github.com/deep-rent/nexus/env"
)

type Config struct {
	LogLevel                string        `env:",default:info"`
	LogFormat               string        `env:",default:json"`
	Host                    string        `env:",default:0.0.0.0"`
	Port                    string        `env:",default:5984"`
	ReadHeaderTimeout       time.Duration `env:",unit:s,default:5"`
	ReadTimeout             time.Duration `env:",unit:s,default:30"`
	WriteTimeout            time.Duration `env:",unit:s,default:0"`
	IdleTimeout             time.Duration `env:",unit:s,default:120"`
	MaxHeaderBytes          int           `env:",default:0"`
	UserNameHeader          string        `env:",default:X-Auth-CouchDB-UserName"`
	RolesHeader             string        `env:",default:X-Auth-CouchDB-Roles"`
	Target                  *url.URL      `env:",default:http://localhost:5984"`
	FlushInterval           time.Duration `env:",unit:ms,default:-1"`
	MinBufferSize           int           `env:",default:32768"`
	MaxBufferSize           int           `env:",default:262144"`
	MaxIdleConns            int           `env:",default:1000"`
	IdleConnTimeout         time.Duration `env:",unit:s,default:90"`
	TokenIssuers            []string      `env:",split"`
	TokenAudiences          []string      `env:",split"`
	TokenLeeway             time.Duration `env:",unit:s,default:30"`
	TokenMaxAge             time.Duration `env:",unit:s,default:0"`
	TokenAuthScheme         string        `env:",default:Bearer"`
	TokenRolesClaim         string        `env:",default:_couchdb.roles"`
	KeysURL                 string        `env:",required"`
	KeysUserAgent           string        `env:",default:Vouch"`
	KeysTimeout             time.Duration `env:",unit:s,default:10"`
	KeysMinRefreshInterval  time.Duration `env:",unit:m,default:60"`
	KeysMaxRefreshInterval  time.Duration `env:",unit:m,default:28800"`
	KeysBackoffMinDelay     time.Duration `env:",unit:s,default:1"`
	KeysBackoffMaxDelay     time.Duration `env:",unit:s,default:120"`
	KeysBackoffGrowthFactor float64       `env:",default:1.75"`
	KeysBackoffJitterAmount float64       `env:",default:0.66"`
}

func Load() (*Config, error) {
	var cfg Config
	if err := env.Unmarshal(&cfg, env.WithPrefix("VOUCH_")); err != nil {
		return nil, err
	}
	return &cfg, nil
}
