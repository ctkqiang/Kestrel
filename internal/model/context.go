package model

// Context 提供事件发生时的环境上下文，用于检测器评估行为是否可疑。
type Context struct {
	UserAuthorized      bool `json:"user_authorized"`
	SourceAuthorized    bool `json:"source_authorized"`
	ContainerAuthorized bool `json:"container_authorized"`

	KnownUserAgent bool `json:"known_user_agent"`
	KnownWorkload  bool `json:"known_workload"`

	Production bool `json:"production"`
}
