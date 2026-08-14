package model

// Network captures network-level metadata associated with an event.
type Network struct {
	Protocol        string `json:"protocol"`
	SourceIP        string `json:"source_ip"`
	SourcePort      int    `json:"source_port"`
	DestinationIP   string `json:"destination_ip"`
	DestinationPort int    `json:"destination_port"`
	Direction       string `json:"direction"`
}
