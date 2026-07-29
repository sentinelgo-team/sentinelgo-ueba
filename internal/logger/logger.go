package logger

import (
	"fmt"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/sentinelgo/sentinelgo-ueba/internal/config"
)

var global *zap.SugaredLogger

func init() {
	l, _ := zap.NewNop().Sugar(), error(nil)
	global = l
}

func Init(cfg config.LoggingConfig) error {
	level, err := parseLevel(cfg.Level)
	if err != nil {
		return err
	}

	encoderCfg := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	var cores []zapcore.Core

	if cfg.Output == "console" || cfg.Output == "both" || cfg.Output == "" {
		consoleEncoder := zapcore.NewConsoleEncoder(encoderCfg)
		cores = append(cores, zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), level))
	}

	if cfg.Output == "file" || cfg.Output == "both" {
		if cfg.FilePath == "" {
			cfg.FilePath = "logs/sentinelgo.log"
		}
		if err := os.MkdirAll(filepath.Dir(cfg.FilePath), 0750); err != nil {
			return fmt.Errorf("create log directory: %w", err)
		}
		file, err := os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}

		fileEncoderCfg := encoderCfg
		fileEncoderCfg.EncodeLevel = zapcore.CapitalLevelEncoder
		fileEncoder := zapcore.NewJSONEncoder(fileEncoderCfg)
		cores = append(cores, zapcore.NewCore(fileEncoder, zapcore.AddSync(file), level))
	}

	if len(cores) == 0 {
		return fmt.Errorf("no valid logging output configured (got %q)", cfg.Output)
	}

	core := zapcore.NewTee(cores...)
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))
	global = logger.Sugar()
	return nil
}

func parseLevel(s string) (zapcore.Level, error) {
	switch s {
	case "debug":
		return zapcore.DebugLevel, nil
	case "info", "":
		return zapcore.InfoLevel, nil
	case "warn":
		return zapcore.WarnLevel, nil
	case "error":
		return zapcore.ErrorLevel, nil
	default:
		return zapcore.InfoLevel, fmt.Errorf("unknown log level: %q", s)
	}
}

func Info(msg string, keysAndValues ...interface{})  { global.Infow(msg, keysAndValues...) }
func Debug(msg string, keysAndValues ...interface{}) { global.Debugw(msg, keysAndValues...) }
func Warn(msg string, keysAndValues ...interface{})  { global.Warnw(msg, keysAndValues...) }
func Error(msg string, keysAndValues ...interface{}) { global.Errorw(msg, keysAndValues...) }
func Fatal(msg string, keysAndValues ...interface{}) { global.Fatalw(msg, keysAndValues...) }

func Sync() {
	if global != nil {
		_ = global.Sync()
	}
}
