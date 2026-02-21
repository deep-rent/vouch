package config

import (
	"log/slog"
	"net/url"
	"time"
)

type Config struct {
	LogLevel           string
	LogFormat          string
	Host               string
	Port               string
	Target             *url.URL
	JWKS               string
	Issuers            []string
	Audiences          []string
	Leeway             time.Duration
	MaxAge             time.Duration
	UserAgent          string
	Timeout            time.Duration
	MinRefreshInterval time.Duration
	MaxRefreshInterval time.Duration
	AuthScheme         string
	RolesClaim         string
	UserHeader         string
	RolesHeader        string
	Logger             *slog.Logger
}
