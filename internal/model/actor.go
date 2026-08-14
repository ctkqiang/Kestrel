package model

type IdentityType string

const (
	IdentityUser           IdentityType = "user"
	IdentityServiceAccount IdentityType = "service_account"
	IdentityNode           IdentityType = "node"
	IdentityAnonymous      IdentityType = "anonymous"
)

func (t IdentityType) String() string { return string(t) }

type Actor struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`

	SourceIP  string `json:"source_ip"`
	UserAgent string `json:"user_agent"`

	ServiceAccount string `json:"service_account"`

	IdentityType IdentityType `json:"identity_type"`
}
