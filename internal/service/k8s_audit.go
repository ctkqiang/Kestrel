package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"kestrel/internal/model"
	"kestrel/internal/utilities"
)

// k8sAuditEvent 匹配 Kubernetes audit.v1 事件模式。
// 仅捕获与 T1059.013（容器 exec/attach）相关的字段。
type k8sAuditEvent struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Level      string `json:"level"`
	AuditID    string `json:"auditID"`
	Stage      string `json:"stage"`

	RequestURI string `json:"requestURI"`
	Verb       string `json:"verb"`

	User struct {
		Username string   `json:"username"`
		UID      string   `json:"uid"`
		Groups   []string `json:"groups"`
		Extra    map[string]json.RawMessage `json:"extra"`
	} `json:"user"`

	SourceIPs []string `json:"sourceIPs"`
	UserAgent string   `json:"userAgent"`

	ObjectRef struct {
		Resource    string `json:"resource"`
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
		Subresource string `json:"subresource"`
	} `json:"objectRef"`

	ResponseStatus struct {
		Code    int    `json:"code"`
		Reason  string `json:"reason"`
	} `json:"responseStatus"`

	RequestReceivedTimestamp time.Time `json:"requestReceivedTimestamp"`
	StageTimestamp           time.Time `json:"stageTimestamp"`

	Annotations map[string]string `json:"annotations"`
}

// normalizeK8sAudit 将原始 K8s 审计 JSON 解析为 model.Event 列表。
// 支持单个事件对象和 JSON 数组（批量摄入）两种格式。
func normalizeK8sAudit(raw []byte, clusterID string, logger *utilities.Logger) ([]model.Event, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("K8s 审计载荷为空")
	}

	// 优先尝试数组格式（批量），否则回退到单个对象。
	if trimmed[0] == '[' {
		var events []k8sAuditEvent
		if err := json.Unmarshal(raw, &events); err != nil {
			return nil, fmt.Errorf("K8s 审计数组反序列化失败: %w", err)
		}
		logger.Debug("批量 K8s 审计摄入", utilities.Fi("count", len(events)))
		out := make([]model.Event, 0, len(events))
		for _, e := range events {
			out = append(out, k8sAuditToEvent(e, clusterID, logger))
		}
		return out, nil
	}

	var event k8sAuditEvent
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, fmt.Errorf("K8s 审计反序列化失败: %w", err)
	}
	return []model.Event{k8sAuditToEvent(event, clusterID, logger)}, nil
}

// k8sAuditToEvent 将单个 K8s 审计事件映射为 model.Event。
func k8sAuditToEvent(a k8sAuditEvent, clusterID string, logger *utilities.Logger) model.Event {
	identityType, serviceAccount := classifyK8sIdentity(a.User.Username, a.User.Groups)

	logger.Debug("审计事件解析",
		utilities.F("audit_id", a.AuditID),
		utilities.F("user", a.User.Username),
		utilities.F("identity_type", string(identityType)),
		utilities.F("subresource", a.ObjectRef.Subresource),
		utilities.F("namespace", a.ObjectRef.Namespace),
		utilities.F("pod", a.ObjectRef.Name),
	)

	actionType, command, interactive := parseK8sAction(a.Verb, a.ObjectRef.Subresource, a.RequestURI)

	if command != "" {
		logger.Debug("命令提取",
			utilities.F("audit_id", a.AuditID),
			utilities.F("command", command),
		)
	}

	sourceIP := ""
	if len(a.SourceIPs) > 0 {
		sourceIP = a.SourceIPs[0]
	}

	ts := a.StageTimestamp
	if ts.IsZero() {
		ts = a.RequestReceivedTimestamp
	}

	metadata := map[string]string{
		"source_type":    string(SourceK8sAudit),
		"audit_id":       a.AuditID,
		"audit_level":    a.Level,
		"audit_stage":    a.Stage,
		"verb":           a.Verb,
		"request_uri":    a.RequestURI,
		"response_code":  fmt.Sprintf("%d", a.ResponseStatus.Code),
	}

	if a.ResponseStatus.Code == 401 || a.ResponseStatus.Code == 403 {
		metadata["denied"] = "true"
		logger.Warn("exec 请求被拒绝",
			utilities.F("audit_id", a.AuditID),
			utilities.F("user", a.User.Username),
			utilities.F("code", fmt.Sprintf("%d", a.ResponseStatus.Code)),
			utilities.F("reason", a.ResponseStatus.Reason),
			utilities.F("namespace", a.ObjectRef.Namespace),
			utilities.F("pod", a.ObjectRef.Name),
		)
	}

	if a.ObjectRef.Subresource != "" {
		metadata["subresource"] = a.ObjectRef.Subresource
	}

	for k, v := range a.Annotations {
		metadata["annotation_"+k] = v
	}

	// 从 namespace 推断环境（如果能识别的话）。
	if env := inferEnvironment(a.ObjectRef.Namespace); env != "" {
		metadata["environment"] = env
	}

	ev := model.Event{
		ID:        a.AuditID,
		Timestamp: ts,
		Actor: model.Actor{
			UserID:         a.User.UID,
			Username:       a.User.Username,
			SourceIP:       sourceIP,
			UserAgent:      a.UserAgent,
			ServiceAccount: serviceAccount,
			IdentityType:    identityType,
		},
		Action: model.Action{
			Type:        actionType,
			Command:     command,
			Interactive: interactive,
		},
		Target: model.Target{
			ClusterID: clusterID,
			Namespace: a.ObjectRef.Namespace,
			PodName:   a.ObjectRef.Name,
		},
		Source: model.Source{
			IP:      sourceIP,
			Service: a.UserAgent,
		},
		Metadata: metadata,
	}

	return ev
}

// classifyK8sIdentity 根据 K8s 用户名和用户组判定身份类型。
// 如果是服务账号，同时提取服务账号名称。
func classifyK8sIdentity(username string, groups []string) (model.IdentityType, string) {
	switch {
	case username == "system:anonymous":
		return model.IdentityAnonymous, ""
	case strings.HasPrefix(username, "system:serviceaccount:"):
		// 格式：system:serviceaccount:{namespace}:{name}
		parts := strings.SplitN(username, ":", 4)
		if len(parts) == 4 {
			return model.IdentityServiceAccount, parts[2] + "/" + parts[3]
		}
		return model.IdentityServiceAccount, username
	case strings.HasPrefix(username, "system:node:"):
		return model.IdentityNode, ""
	}

	for _, g := range groups {
		if g == "system:unauthenticated" {
			return model.IdentityAnonymous, ""
		}
	}

	return model.IdentityUser, ""
}

// parseK8sAction 将 K8s 审计的 verb + subresource 映射为 ActionType，
// 并从请求 URI 的查询参数中提取命令。
func parseK8sAction(verb, subresource, requestURI string) (model.ActionType, string, bool) {
	var actionType model.ActionType
	interactive := false

	switch subresource {
	case "exec":
		actionType = model.ContainerExec
		interactive = true
	case "attach":
		actionType = model.ContainerExec
		interactive = true
	case "portforward":
		actionType = model.NetworkConnect
	default:
		// 不是 T1059.013 相关的子资源。
		// 仍然以 process_start 记录，保证完整性。
		actionType = model.ProcessStart
	}

	command := extractCommandFromURI(requestURI)

	return actionType, command, interactive
}

// extractCommandFromURI 解析 K8s 审计 requestURI 的查询参数，
// 将重复的 "command" 参数拼接为单个字符串。
// 示例：/api/v1/namespaces/default/pods/foo/exec?command=/bin/sh&command=-c&command=whoami
// → "/bin/sh -c whoami"
func extractCommandFromURI(requestURI string) string {
	u, err := url.Parse(requestURI)
	if err != nil {
		return ""
	}

	commands := u.Query()["command"]
	if len(commands) == 0 {
		return ""
	}

	return strings.Join(commands, " ")
}

// inferEnvironment 尝试将 namespace 分类为 production 或 staging。
// 这是一个启发式推断 —— 检测层可以用更精确的数据覆盖此结果。
func inferEnvironment(namespace string) string {
	switch namespace {
	case "production", "prod", "default":
		return "production"
	case "staging", "stage":
		return "staging"
	default:
		return ""
	}
}
