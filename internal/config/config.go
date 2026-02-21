package config

type Config struct {
	LogLevel  string `env:",default=info"`
	LogFormat string `env:",default=json"`
}
