package model

type Kubernetes struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
}
