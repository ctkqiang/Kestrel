package model

import "time"

type Activity struct {
	ID string `json:"id"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	Events []Event `json:"events"`

	Actors  map[string]Actor  `json:"actors"`
	Targets map[string]Target `json:"targets"`

	Signals []Signal `json:"signals"`

	Score float64 `json:"score"`
}
