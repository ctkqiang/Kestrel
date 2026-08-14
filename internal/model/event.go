package model

import "time"

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
