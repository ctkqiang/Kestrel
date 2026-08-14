package model

// Network 捕获与事件关联的网络层元数据。
type Network struct {
	Protocol        string `json:"protocol"`
	SourceIP        string `json:"source_ip"`
	SourcePort      int    `json:"source_port"`
	DestinationIP   string `json:"destination_ip"`
	DestinationPort int    `json:"destination_port"`
	Direction       string `json:"direction"`
}
