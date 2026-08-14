package config

import (
	"flag"
	"fmt"
	"os"

	"kestrel/internal/utilities"
)

// Version 通过 ldflags 注入的版本号。
var Version = "dev"

// Config 汇总应用所有配置来源（flag + 环境变量）。
type Config struct {
	// ClusterID 集群标识符，注入到所有归一化事件中。
	ClusterID string

	// Verbose 是否开启 DEBUG 级别日志。
	Verbose bool

	// LogFormat 日志输出格式（text / json）。
	LogFormat string
}

// Parse 解析 flag 和环境变量，返回最终配置。
// 优先级：flag > 环境变量 > 默认值。
func Parse() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.ClusterID, "cluster-id", envOr("KESTREL_CLUSTER_ID", ""), "集群标识符（环境变量 KESTREL_CLUSTER_ID）")
	flag.BoolVar(&cfg.Verbose, "v", false, "verbose 模式，输出 DEBUG 级别日志")
	flag.StringVar(&cfg.LogFormat, "log-format", "text", "日志格式（text / json）")

	flag.Parse()

	if cfg.ClusterID == "" {
		return nil, fmt.Errorf("集群标识符未设置：请使用 -cluster-id 参数或 KESTREL_CLUSTER_ID 环境变量")
	}

	if cfg.LogFormat != "text" && cfg.LogFormat != "json" {
		return nil, fmt.Errorf("不支持的日志格式: %s（可选值: text, json）", cfg.LogFormat)
	}

	return cfg, nil
}

// LogLevel 根据配置返回对应的日志级别。
func (c *Config) LogLevel() utilities.LogLevel {
	if c.Verbose {
		return utilities.LevelDebug
	}
	return utilities.LevelInfo
}

// envOr 读取环境变量，未设置时返回 fallback。
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
