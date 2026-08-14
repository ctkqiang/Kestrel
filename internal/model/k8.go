package model

// Kubernetes 封装 Kubernetes 集群级别的上下文信息。
type Kubernetes struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
}
