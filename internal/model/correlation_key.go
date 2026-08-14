package model

import "fmt"

type CorrelationKey struct {
	ActorID  string `json:"actor_id"`
	SourceIP string `json:"source_ip"`

	ClusterID string `json:"cluster_id"`

	SessionID string `json:"session_id"`
}

// Key returns a deterministic string suitable for use as a map key.
func (k CorrelationKey) Key() string {
	return fmt.Sprintf("%s|%s|%s|%s", k.ActorID, k.SourceIP, k.ClusterID, k.SessionID)
}
