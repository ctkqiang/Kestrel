package model

// Source describes the origin of an event.
type Source struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
}
