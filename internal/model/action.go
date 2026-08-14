package model

// ActionType 标识事件中容器执行的动作类型。
type ActionType string

const (
	ContainerExec  ActionType = "container_exec"
	ShellSpawn     ActionType = "shell_spawn"
	ProcessStart   ActionType = "process_start"
	NetworkConnect ActionType = "network_connect"
	FileWrite      ActionType = "file_write"
)

func (t ActionType) String() string { return string(t) }

// Action 描述事件中执行的具体动作及其参数。
type Action struct {
	Type        ActionType `json:"type"`
	Command     string     `json:"command"`
	Interactive bool       `json:"interactive"`
}
