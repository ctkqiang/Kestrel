package model

import "time"

// Activity 是一组关联事件的集合，代表同一行为者的连续行为序列。
// 由 Correlator 通过 CorrelationKey 将相关 Event 归类生成。
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
