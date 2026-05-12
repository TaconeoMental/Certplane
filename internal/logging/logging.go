package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/TaconeoMental/certplane/config"
)

func New(cfg config.LoggingConfig) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	var w io.Writer = os.Stdout
	if cfg.Destination == "stderr" {
		w = os.Stderr
	}

	opts := &slog.HandlerOptions{Level: level}
	if cfg.Format == "text" {
		return slog.New(slog.NewTextHandler(w, opts))
	}
	return slog.New(slog.NewJSONHandler(w, opts))
}

func SetDefault(logger *slog.Logger) {
	if logger != nil {
		slog.SetDefault(logger)
	}
}
