package model

type ActionType string

const (
	ContainerExec  ActionType = "container_exec"
	ShellSpawn     ActionType = "shell_spawn"
	ProcessStart   ActionType = "process_start"
	NetworkConnect ActionType = "network_connect"
	FileWrite      ActionType = "file_write"
)

func (t ActionType) String() string { return string(t) }

type Action struct {
	Type        ActionType `json:"type"`
	Command     string     `json:"command"`
	Interactive bool       `json:"interactive"`
}
