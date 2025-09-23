package token

import (
	"time"

	"github.com/deep-rent/vouch/internal/cache"
	"github.com/deep-rent/vouch/internal/di"
	"github.com/deep-rent/vouch/internal/logger"
)

var (
	KeySetSlot = di.NewSlot[KeySet]()
	ParserSlot = di.NewSlot[Parser]()
)

func ProvideKeySet(in *di.Injector) (KeySet, error) {
	log := di.Opt(in, logger.Slot)

	return NewKeySet(
		in.Context(),
		"",
		cache.WithTimeout(time.Second),
		cache.WithMinInterval(time.Second),
		cache.WithMaxInterval(time.Minute),
		cache.WithTLSConfig(nil),
		cache.WithHeader("User-Agent", "Vouch"),
		cache.WithBackoff(nil),
		cache.WithLogger(log),
	), nil
}

func ProvideParser(in *di.Injector) (Parser, error) {
	set := di.Opt(in, KeySetSlot)

	return NewParser(
		WithScheme(""),
		WithHeader(""),
		WithAudience(""),
		WithIssuer(""),
		WithLeeway(time.Minute),
		WithKeySet(set),
	), nil
}

func BindKeySet(in *di.Injector) {
	di.Bind(in, KeySetSlot, ProvideKeySet, di.Singleton())
}

func BindParser(in *di.Injector) {
	di.Bind(in, ParserSlot, ProvideParser, di.Singleton())
}
