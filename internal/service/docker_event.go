package service

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"kestrel/internal/model"
	"kestrel/internal/utilities"
)

// dockerEvent 匹配 Docker daemon 事件模式。
// Docker 事件由 Docker API /events 流产生。
type dockerEvent struct {
	Type     string `json:"Type"`
	Action   string `json:"Action"`
	Actor    struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
	Scope    string `json:"scope"`
	Time     int64  `json:"time"`
	TimeNano int64  `json:"timeNano"`
}

// normalizeDocker 将原始 Docker daemon 事件 JSON 解析为 model.Event。
// Docker 事件缺少用户身份和源 IP —— 这些字段被设置为保守默认值
// （anonymous / unknown），以便检测器以适当的警觉度评估这些事件。
func normalizeDocker(raw []byte, clusterID string, logger *utilities.Logger) ([]model.Event, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("Docker 事件载荷为空")
	}

	var de dockerEvent
	if err := json.Unmarshal(raw, &de); err != nil {
		return nil, fmt.Errorf("Docker 事件反序列化失败: %w", err)
	}

	logger.Debug("Docker 事件解析",
		utilities.F("type", de.Type),
		utilities.F("action", de.Action),
		utilities.F("container_id", de.Actor.ID),
		utilities.F("scope", de.Scope),
	)

	event := dockerEventToModelEvent(de, clusterID, logger)
	return []model.Event{event}, nil
}

// dockerEventToModelEvent 将 Docker daemon 事件映射为 model.Event。
func dockerEventToModelEvent(de dockerEvent, clusterID string, logger *utilities.Logger) model.Event {
	actionType, interactive := mapDockerAction(de.Action)

	logger.Debug("Docker action 映射",
		utilities.F("docker_action", de.Action),
		utilities.F("mapped_type", string(actionType)),
		utilities.F("interactive", fmt.Sprintf("%v", interactive)),
	)

	// Docker 事件使用 Unix 时间戳。
	var ts time.Time
	if de.TimeNano > 0 {
		ts = time.Unix(0, de.TimeNano)
	} else if de.Time > 0 {
		ts = time.Unix(de.Time, 0)
	}

	containerName := ""
	image := ""
	if de.Actor.Attributes != nil {
		containerName = de.Actor.Attributes["name"]
		image = de.Actor.Attributes["image"]
	}

	metadata := map[string]string{
		"source_type":   string(SourceDocker),
		"docker_action": de.Action,
		"docker_type":   de.Type,
		"docker_scope":  de.Scope,
	}
	if image != "" {
		metadata["image"] = image
	}

	// Docker 不携带用户身份，保守默认为 anonymous。
	// 检测器应以更高警觉评估这些事件。
	logger.Debug("Docker 事件身份缺失，默认 anonymous",
		utilities.F("container_id", de.Actor.ID),
		utilities.F("container_name", containerName),
	)

	return model.Event{
		ID:        generateEventID(),
		Timestamp: ts,
		Actor: model.Actor{
			UserID:       "unknown",
			Username:     "unknown",
			IdentityType: model.IdentityAnonymous,
		},
		Action: model.Action{
			Type:        actionType,
			Interactive: interactive,
		},
		Target: model.Target{
			ClusterID:     clusterID,
			ContainerID:   de.Actor.ID,
			ContainerName: containerName,
		},
		Source: model.Source{
			Service: "docker-daemon",
		},
		Metadata: metadata,
	}
}

// mapDockerAction 将 Docker 事件的 Action 转换为 model.ActionType。
// T1059.013 相关的动作：
//   - exec_create / exec_start → ContainerExec
//   - attach                   → ContainerExec（交互式）
func mapDockerAction(action string) (model.ActionType, bool) {
	switch action {
	case "exec_create", "exec_start":
		return model.ContainerExec, false
	case "exec_die":
		return model.ContainerExec, false
	case "attach":
		return model.ContainerExec, true
	default:
		return model.ProcessStart, false
	}
}

// generateEventID 为缺少原生 ID 的事件生成短随机 hex ID。
// Docker daemon 事件不携带事件标识符。
func generateEventID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "evt-" + hex.EncodeToString(b)
}
