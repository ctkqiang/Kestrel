package model

// Target 描述事件的目标容器环境（集群/命名空间/Pod/容器）。
type Target struct {
	ClusterID string `json:"cluster_id"`
	Namespace string `json:"namespace"`

	PodID   string `json:"pod_id"`
	PodName string `json:"pod_name"`

	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
}
