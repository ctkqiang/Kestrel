package model

import (
	"fmt"
	"time"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) String() string { return string(s) }

// Numeric 返回用于严重度排序的可比较数值。
func (s Severity) Numeric() int {
	switch s {
	case SeverityInfo:
		return 1
	case SeverityLow:
		return 2
	case SeverityMedium:
		return 3
	case SeverityHigh:
		return 4
	case SeverityCritical:
		return 5
	default:
		return 0
	}
}

type Finding struct {
	ID string `json:"id"`

	DetectionID string `json:"detection_id"`
	TechniqueID string `json:"technique_id"`

	Severity   Severity `json:"severity"`
	Confidence float64  `json:"confidence"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	ActivityID string `json:"activity_id"`

	Evidence []Event  `json:"evidence"`
	Signals  []Signal `json:"signals"`

	Reason string `json:"reason"`
}

// Summary 返回检测结果的人类可读单行摘要。
func (f Finding) Summary() string {
	return fmt.Sprintf("[%s] confidence=%.0f%% | %s", f.Severity, f.Confidence*100, f.Reason)
}
