package model

import "time"

type SignalType string

const (
	SignalAnomaly             SignalType = "anomaly"
	SignalThreatIntel         SignalType = "threat_intel"
	SignalPolicyViolation     SignalType = "policy_violation"
	SignalPrivilegeEscalation SignalType = "privilege_escalation"
	SignalLateralMovement     SignalType = "lateral_movement"
	SignalPersistence         SignalType = "persistence"
	SignalExfiltration        SignalType = "exfiltration"
)

func (t SignalType) String() string { return string(t) }

type Signal struct {
	Type SignalType `json:"type"`

	Timestamp time.Time `json:"timestamp"`

	Evidence []string `json:"evidence"`

	Weight float64 `json:"weight"`
}
