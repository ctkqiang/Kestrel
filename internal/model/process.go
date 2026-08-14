package model

// Process captures process-level metadata associated with an event.
type Process struct {
	PID         int    `json:"pid"`
	Name        string `json:"name"`
	CommandLine string `json:"command_line"`
	ParentPID   int    `json:"parent_pid"`
	ParentName  string `json:"parent_name"`
}
