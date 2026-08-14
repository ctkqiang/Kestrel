package model

import "time"

// Event 是归一化后的安全事件，是整个检测管线的通用数据单元。
// 由 Sidecar 从原始遥测（K8s 审计 / Docker 事件）归一化生成。
type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`

	Actor  Actor  `json:"actor"`
	Action Action `json:"action"`
	Target Target `json:"target"`

	Source  Source   `json:"source"`
	Process *Process `json:"process,omitempty"`
	Network *Network `json:"network,omitempty"`

	Metadata map[string]string `json:"metadata,omitempty"`
}
