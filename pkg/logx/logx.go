package logx

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
)

type Logger struct {
	level int
	base  *log.Logger
	mu    sync.Mutex
}

const (
	levelDebug = iota
	levelInfo
	levelWarn
	levelError
)

func New(level string) *Logger {
	return &Logger{
		level: parseLevel(level),
		base:  log.New(os.Stderr, "", log.LstdFlags),
	}
}

func (l *Logger) SetOutput(w io.Writer) {
	if l == nil {
		return
	}
	if w == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.base.SetOutput(w)
}

func (l *Logger) Debugf(format string, args ...any) {
	l.printf(levelDebug, "DEBUG", format, args...)
}

func (l *Logger) Infof(format string, args ...any) {
	l.printf(levelInfo, "INFO", format, args...)
}

func (l *Logger) Warnf(format string, args ...any) {
	l.printf(levelWarn, "WARN", format, args...)
}

func (l *Logger) Errorf(format string, args ...any) {
	l.printf(levelError, "ERROR", format, args...)
}

func (l *Logger) printf(level int, prefix, format string, args ...any) {
	if level < l.level {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.base.Printf("[%s] %s", prefix, fmt.Sprintf(format, args...))
}

func parseLevel(level string) int {
	switch strings.ToLower(level) {
	case "debug":
		return levelDebug
	case "warn":
		return levelWarn
	case "error":
		return levelError
	default:
		return levelInfo
	}
}
