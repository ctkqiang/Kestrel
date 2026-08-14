package model

// Process 捕获与事件关联的进程级元数据。
type Process struct {
	PID         int    `json:"pid"`
	Name        string `json:"name"`
	CommandLine string `json:"command_line"`
	ParentPID   int    `json:"parent_pid"`
	ParentName  string `json:"parent_name"`
}
