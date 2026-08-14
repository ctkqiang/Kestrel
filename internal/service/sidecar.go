package service

import (
	"encoding/json"
	"fmt"

	"kestrel/internal/model"
	"kestrel/internal/utilities"
)

// TelemetrySource 标识原始遥测数据的来源类型。
type TelemetrySource string

const (
	SourceK8sAudit TelemetrySource = "k8s_audit"
	SourceDocker   TelemetrySource = "docker"
)

// Sidecar 将容器运行时的原始遥测数据归一化为 model.Event 结构体。
// 它是纯处理器 —— 不生成信号、活动或检测结果。
// 调用方负责获取原始遥测数据（HTTP webhook、日志轮询等），
// 并将归一化后的事件转发给检测引擎。
type Sidecar struct {
	clusterID string
	logger    *utilities.Logger
}

// New 创建绑定到指定集群标识符的 Sidecar 实例。
// clusterID 会被应用到所有缺少集群上下文的归一化事件中。
// logger 用于记录归一化过程中的关键决策点。
func New(clusterID string, logger *utilities.Logger) *Sidecar {
	if logger == nil {
		logger = utilities.NewLogger(utilities.LevelInfo).WithPrefix("sidecar")
	}
	return &Sidecar{
		clusterID: clusterID,
		logger:    logger.WithPrefix("sidecar"),
	}
}

// Process 解析原始遥测 JSON，返回归一化后的事件列表。
// source 参数决定使用哪个归一化器。
// K8s 审计输入可以是单个事件对象，也可以是 JSON 数组（批量摄入）。
// Docker 输入预期为单个事件对象。
func (s *Sidecar) Process(raw []byte, source TelemetrySource) ([]model.Event, error) {
	s.logger.Debug("开始归一化",
		utilities.F("source", string(source)),
		utilities.Fi("bytes", len(raw)),
	)

	switch source {
	case SourceK8sAudit:
		events, err := normalizeK8sAudit(raw, s.clusterID, s.logger)
		if err != nil {
			s.logger.Warn("K8s 审计解析失败",
				utilities.F("error", err.Error()),
				utilities.Fi("bytes", len(raw)),
			)
			return nil, err
		}
		s.logger.Debug("K8s 审计解析完成",
			utilities.Fi("events", len(events)),
		)
		return events, nil

	case SourceDocker:
		events, err := normalizeDocker(raw, s.clusterID, s.logger)
		if err != nil {
			s.logger.Warn("Docker 事件解析失败",
				utilities.F("error", err.Error()),
				utilities.Fi("bytes", len(raw)),
			)
			return nil, err
		}
		s.logger.Debug("Docker 事件解析完成",
			utilities.Fi("events", len(events)),
		)
		return events, nil

	default:
		s.logger.Error("未知的遥测来源", utilities.F("source", string(source)))
		return nil, fmt.Errorf("未知的遥测来源: %s", source)
	}
}

// ProcessJSON 是 Process 的便捷封装，接受 json.RawMessage 作为输入。
// 行为与 Process 完全一致。
func (s *Sidecar) ProcessJSON(raw json.RawMessage, source TelemetrySource) ([]model.Event, error) {
	return s.Process([]byte(raw), source)
}
