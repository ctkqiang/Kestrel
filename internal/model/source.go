package model

// Source 描述事件的来源信息。
type Source struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
}
