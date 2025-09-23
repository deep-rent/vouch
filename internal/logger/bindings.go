package logger

import (
	"log/slog"
	"os"

	"github.com/deep-rent/vouch/internal/di"
)

var Slot = di.NewSlot[*slog.Logger]()

func ProvideLogger(in *di.Injector) (*slog.Logger, error) {
	return New(os.Getenv("VOUCH_LOG")), nil
}

func BindLogger(in *di.Injector) {
	di.Bind(in, Slot, ProvideLogger, di.Singleton())
}
