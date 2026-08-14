package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"kestrel/internal/service"
	"kestrel/internal/utilities"
)

const (
	exitOK  = 0
	exitErr = 1
)

func main() {
	verbose := flag.Bool("v", false, "verbose 模式，输出 DEBUG 级别日志")
	flag.Parse()

	level := utilities.LevelInfo
	if *verbose {
		level = utilities.LevelDebug
	}

	logger := utilities.NewLogger(level).
		WithPrefix("kestrel").
		WithField("cluster", os.Getenv("KESTREL_CLUSTER_ID"))

	os.Exit(run(os.Stdin, os.Stdout, logger))
}

// run 是程序主逻辑，接受输入/输出/日志器，返回退出码。
// 从 reader 逐行读取 JSONL 遥测数据，归一化后写入 writer。
func run(reader io.Reader, writer io.Writer, logger *utilities.Logger) int {
	scanner := bufio.NewScanner(reader)
	// 审计日志单行可达 256KB，放宽 buffer 上限。
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	clusterID := os.Getenv("KESTREL_CLUSTER_ID")
	s := service.New(clusterID, logger)
	if s == nil {
		logger.Error("无法初始化 sidecar")
		return exitErr
	}

	logger.Info("sidecar 已启动", utilities.F("cluster_id", clusterID))

	encoder := json.NewEncoder(writer)

	var processed int
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		source, err := detectSource(line)
		if err != nil {
			logger.Warn("跳过无法识别的行", utilities.F("error", err.Error()))
			continue
		}

		logger.Debug("开始处理遥测行", utilities.F("source", string(source)))

		events, err := s.Process([]byte(line), source)
		if err != nil {
			logger.Warn("处理失败", utilities.F("source", string(source)), utilities.F("error", err.Error()))
			continue
		}

		for _, ev := range events {
			if err := encoder.Encode(ev); err != nil {
				logger.Error("输出事件失败", utilities.F("error", err.Error()))
				continue
			}
			processed++
			logger.Debug("事件已归一化输出",
				utilities.F("event_id", ev.ID),
				utilities.F("action", string(ev.Action.Type)),
				utilities.F("identity", string(ev.Actor.IdentityType)),
			)
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Error("读取输入失败", utilities.F("error", err.Error()))
		return exitErr
	}

	logger.Info("处理完成", utilities.Fi("events", processed))
	return exitOK
}

// detectSource 根据原始 JSON 内容推断遥测来源。
// K8s 审计日志包含 "auditID" + "apiVersion"，Docker 事件包含 "Type" + "Action"。
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
