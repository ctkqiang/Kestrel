package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"kestrel/internal/config"
	"kestrel/internal/service"
	"kestrel/internal/utilities"
)

const (
	exitOK  = 0
	exitErr = 1
)

// Stats 记录管道处理过程中的累计统计。
type Stats struct {
	Processed int // 成功归一化输出的事件数
	Skipped   int // 因无法识别或解析失败被跳过的行数
}

func main() {
	cfg, err := config.Parse()
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置错误: %v\n", err)
		os.Exit(exitErr)
	}

	logger := utilities.NewLogger(cfg.LogLevel()).
		WithPrefix("kestrel").
		WithField("cluster", cfg.ClusterID).
		WithField("version", config.Version)

	logger.Info("启动 Kestrel sidecar",
		utilities.F("cluster_id", cfg.ClusterID),
		utilities.F("verbose", fmt.Sprintf("%v", cfg.Verbose)),
	)

	os.Exit(run(os.Stdin, os.Stdout, cfg, logger))
}

// run 是程序主逻辑，接受输入/输出/配置/日志器，返回退出码。
// 从 reader 逐行读取 JSONL 遥测数据，归一化后写入 writer。
// 支持通过 SIGINT/SIGTERM 信号优雅关停。
func run(reader io.Reader, writer io.Writer, cfg *config.Config, logger *utilities.Logger) int {
	// 监听终止信号，实现优雅关停。
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	s := service.New(cfg.ClusterID, logger)
	if s == nil {
		logger.Error("无法初始化 sidecar")
		return exitErr
	}

	scanner := bufio.NewScanner(reader)
	// 审计日志单行可达 256KB，放宽 buffer 上限。
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	encoder := json.NewEncoder(writer)
	stats := Stats{}

scanLoop:
	for scanner.Scan() {
		// 检查是否收到终止信号。
		select {
		case <-ctx.Done():
			logger.Info("收到终止信号，停止读取新输入")
			break scanLoop
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		source, err := detectSource(line)
		if err != nil {
			logger.Warn("跳过无法识别的行", utilities.F("error", err.Error()))
			stats.Skipped++
			continue
		}

		logger.Debug("开始处理遥测行", utilities.F("source", string(source)))

		events, err := s.Process([]byte(line), source)
		if err != nil {
			logger.Warn("处理失败",
				utilities.F("source", string(source)),
				utilities.F("error", err.Error()),
			)
			stats.Skipped++
			continue
		}

		for _, ev := range events {
			if err := encoder.Encode(ev); err != nil {
				logger.Error("输出事件失败", utilities.F("error", err.Error()))
				continue
			}
			stats.Processed++
			logger.Debug("事件已归一化输出",
				utilities.F("event_id", ev.ID),
				utilities.F("action", string(ev.Action.Type)),
				utilities.F("identity", string(ev.Actor.IdentityType)),
			)
		}
	}

	// 如果是信号中断导致的退出，不算错误。
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		// 信号导致的 scanner 停止不报错。
		if ctx.Err() != nil {
			logger.Info("管道因信号中断而停止")
		} else {
			logger.Error("读取输入失败", utilities.F("error", err.Error()))
			return exitErr
		}
	}

	logger.Info("处理完成",
		utilities.Fi("processed", stats.Processed),
		utilities.Fi("skipped", stats.Skipped),
	)

	return exitOK
}

// detectSource 根据原始 JSON 内容推断遥测来源。
// K8s 审计日志包含 "auditID" 字段，Docker 事件包含 "Type" + "Action" 字段。
func detectSource(raw string) (service.TelemetrySource, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &probe); err != nil {
		return "", fmt.Errorf("JSON 解析失败: %w", err)
	}

	if _, ok := probe["auditID"]; ok {
		return service.SourceK8sAudit, nil
	}

	if _, ok := probe["Type"]; ok {
		if _, ok := probe["Action"]; ok {
			return service.SourceDocker, nil
		}
	}

	return "", errors.New("无法识别的遥测格式")
}
