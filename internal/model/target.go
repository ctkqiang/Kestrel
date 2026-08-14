package model

type Target struct {
	ClusterID string `json:"cluster_id"`
	Namespace string `json:"namespace"`

	PodID   string `json:"pod_id"`
	PodName string `json:"pod_name"`

	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
}
