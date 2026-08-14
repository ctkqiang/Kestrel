package utilities

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// LogLevel 日志级别枚举。
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l LogLevel) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Logger 结构化日志器，支持级别过滤和 verbose 模式。
type Logger struct {
	mu      sync.Mutex
	out     io.Writer
	level   LogLevel
	verbose bool
	fields  map[string]string
	prefix  string
}

// NewLogger 创建日志器，level 为最低输出级别。
func NewLogger(level LogLevel) *Logger {
	return &Logger{
		out:     os.Stderr,
		level:   level,
		verbose: false,
		fields:  make(map[string]string),
	}
}

// WithVerbose 开启 verbose 模式，输出 DEBUG 级别日志。
func (l *Logger) WithVerbose() *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.verbose = true
	l.level = LevelDebug
	return l
}

// WithPrefix 设置日志前缀。
func (l *Logger) WithPrefix(prefix string) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prefix = prefix
	return l
}

// WithOutput 设置输出目标。
func (l *Logger) WithOutput(w io.Writer) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out = w
	return l
}

// WithField 添加持久化字段，后续每条日志都会携带。
func (l *Logger) WithField(key, value string) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fields[key] = value
	return l
}

// log 写入一条日志。
func (l *Logger) log(level LogLevel, msg string, fields []Field) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	ts := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	var line string
	if l.prefix != "" {
		line = fmt.Sprintf("[%s] %s %s: %s", ts, level, l.prefix, msg)
	} else {
		line = fmt.Sprintf("[%s] %s: %s", ts, level, msg)
	}

	// 合并持久化字段和临时字段
	all := make([]Field, 0, len(l.fields)+len(fields))
	for k, v := range l.fields {
		all = append(all, Field{Key: k, Value: v})
	}
	all = append(all, fields...)

	if len(all) > 0 {
		pairs := make([]string, 0, len(all))
		for _, f := range all {
			pairs = append(pairs, fmt.Sprintf("%s=%s", f.Key, f.Value))
		}
		line += " | " + strings.Join(pairs, " ")
	}

	fmt.Fprintln(l.out, line)
}

// Field 临时日志字段。
type Field struct {
	Key   string
	Value string
}

// F 创建临时字段。
func F(key, value string) Field {
	return Field{Key: key, Value: value}
}

// Fi 创建整型临时字段。
func Fi(key string, value int) Field {
	return Field{Key: key, Value: fmt.Sprintf("%d", value)}
}

// Fs 创建字符串切片临时字段。
func Fs(key string, values []string) Field {
	return Field{Key: key, Value: fmt.Sprintf("[%s]", strings.Join(values, " "))}
}

// Debug 输出 DEBUG 级别日志。
func (l *Logger) Debug(msg string, fields ...Field) {
	l.log(LevelDebug, msg, fields)
}

// Debugf 输出 DEBUG 级别格式化日志。
func (l *Logger) Debugf(format string, args ...any) {
	l.log(LevelDebug, fmt.Sprintf(format, args...), nil)
}

// Info 输出 INFO 级别日志。
func (l *Logger) Info(msg string, fields ...Field) {
	l.log(LevelInfo, msg, fields)
}

// Infof 输出 INFO 级别格式化日志。
func (l *Logger) Infof(format string, args ...any) {
	l.log(LevelInfo, fmt.Sprintf(format, args...), nil)
}

// Warn 输出 WARN 级别日志。
func (l *Logger) Warn(msg string, fields ...Field) {
	l.log(LevelWarn, msg, fields)
}

// Warnf 输出 WARN 级别格式化日志。
func (l *Logger) Warnf(format string, args ...any) {
	l.log(LevelWarn, fmt.Sprintf(format, args...), nil)
}

// Error 输出 ERROR 级别日志。
func (l *Logger) Error(msg string, fields ...Field) {
	l.log(LevelError, msg, fields)
}

// Errorf 输出 ERROR 级别格式化日志。
func (l *Logger) Errorf(format string, args ...any) {
	l.log(LevelError, fmt.Sprintf(format, args...), nil)
}

// IsVerbose 返回是否开启了 verbose 模式。
func (l *Logger) IsVerbose() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.verbose
}

// IsLevelEnabled 检查指定级别是否会被输出。
func (l *Logger) IsLevelEnabled(level LogLevel) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return level >= l.level
}

// FromGoLog 将标准 log.Logger 输出桥接到 Logger。
// 适用于无法直接替换 log.Println 的第三方库。
func FromGoLog(writer io.Writer) *Logger {
	return &Logger{
		out:     writer,
		level:   LevelInfo,
		verbose: false,
		fields:  make(map[string]string),
	}
}
