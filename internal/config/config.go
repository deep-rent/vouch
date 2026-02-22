// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"net/url"
	"time"

	"github.com/deep-rent/nexus/env"
)

// Prefix is the environment variable prefix used by the application.
const Prefix = "VOUCH_"

// Config holds the application configuration. It is populated from environment
// variables prefixed with [Prefix]. The struct tags define the default values
// and parsing rules for each field.
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
	MaxIdleConns            int           `env:",default:512"`
	IdleConnTimeout         time.Duration `env:",unit:s,default:90"`
	TokenIssuers            []string      `env:""`
	TokenAudiences          []string      `env:""`
	TokenLeeway             time.Duration `env:",unit:s,default:30"`
	TokenMaxAge             time.Duration `env:",unit:s,default:0"`
	TokenAuthScheme         string        `env:",default:Bearer"`
	TokenRolesClaim         string        `env:",default:_couchdb.roles"`
	KeysURL                 string        `env:",required"`
	KeysUserAgent           string        `env:",default:Vouch"`
	KeysTimeout             time.Duration `env:",unit:s,default:10"`
	KeysMinRefreshInterval  time.Duration `env:",unit:m,default:60"`
	KeysMaxRefreshInterval  time.Duration `env:",unit:m,default:28800"`
	KeysAttemptLimit        int           `env:",default:0"`
	KeysBackoffMinDelay     time.Duration `env:",unit:s,default:1"`
	KeysBackoffMaxDelay     time.Duration `env:",unit:s,default:120"`
	KeysBackoffGrowthFactor float64       `env:",default:1.75"`
	KeysBackoffJitterAmount float64       `env:",default:0.66"`
}

// Load reads the configuration from environment variables, applying the
// [Prefix] to all lookups. It returns an error if required variables are
// missing or if parsing fails.
func Load() (*Config, error) {
	var cfg Config
	if err := env.Unmarshal(&cfg, env.WithPrefix(Prefix)); err != nil {
		return nil, err
	}
	return &cfg, nil
}
