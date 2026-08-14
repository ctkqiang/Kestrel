package model

type Context struct {
	UserAuthorized      bool `json:"user_authorized"`
	SourceAuthorized    bool `json:"source_authorized"`
	ContainerAuthorized bool `json:"container_authorized"`

	KnownUserAgent bool `json:"known_user_agent"`
	KnownWorkload  bool `json:"known_workload"`

	Production bool `json:"production"`
}
