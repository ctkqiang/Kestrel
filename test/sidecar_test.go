package service_test

import (
	"kestrel/internal/model"
	"kestrel/internal/service"
	"testing"
	"time"
)

func TestK8sAudit_AnonymousExecProduction(t *testing.T) {
	raw := []byte(`{
		"kind": "Event",
		"apiVersion": "audit.k8s.io/v1",
		"level": "RequestResponse",
		"auditID": "audit-001",
		"stage": "ResponseComplete",
		"requestURI": "/api/v1/namespaces/production/pods/payment-svc/exec?command=/bin/sh",
		"verb": "create",
		"user": {
			"username": "system:anonymous",
			"uid": "",
			"groups": ["system:unauthenticated"]
		},
		"sourceIPs": ["203.0.113.50"],
		"userAgent": "kubectl/v1.28.0",
		"objectRef": {
			"resource": "pods",
			"namespace": "production",
			"name": "payment-svc",
			"subresource": "exec"
		},
		"responseStatus": {"code": 200},
		"stageTimestamp": "2026-08-14T03:00:00Z"
	}`)

	s := service.New("prod-eu-west", nil)
	events, err := s.Process(raw, service.SourceK8sAudit)
	if err != nil {
		t.Fatalf("Process error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]

	if ev.Actor.IdentityType != model.IdentityAnonymous {
		t.Errorf("identity type: got %s, want %s", ev.Actor.IdentityType, model.IdentityAnonymous)
	}
	if ev.Actor.Username != "system:anonymous" {
		t.Errorf("username: got %s, want system:anonymous", ev.Actor.Username)
	}

	if ev.Action.Type != model.ContainerExec {
		t.Errorf("action type: got %s, want %s", ev.Action.Type, model.ContainerExec)
	}
	if ev.Action.Command != "/bin/sh" {
		t.Errorf("command: got %q, want /bin/sh", ev.Action.Command)
	}
	if !ev.Action.Interactive {
		t.Error("interactive: got false, want true")
	}

	if ev.Target.Namespace != "production" {
		t.Errorf("namespace: got %s, want production", ev.Target.Namespace)
	}
	if ev.Target.PodName != "payment-svc" {
		t.Errorf("pod name: got %s, want payment-svc", ev.Target.PodName)
	}
	if ev.Target.ClusterID != "prod-eu-west" {
		t.Errorf("cluster ID: got %s, want prod-eu-west", ev.Target.ClusterID)
	}

	if ev.Source.IP != "203.0.113.50" {
		t.Errorf("source IP: got %s, want 203.0.113.50", ev.Source.IP)
	}

	if ev.Metadata["environment"] != "production" {
		t.Errorf("environment metadata: got %s, want production", ev.Metadata["environment"])
	}
	if ev.Metadata["denied"] != "" {
		t.Error("should not be marked denied for code 200")
	}
}

func TestK8sAudit_SREExecStaging(t *testing.T) {
	raw := []byte(`{
		"kind": "Event",
		"apiVersion": "audit.k8s.io/v1",
		"level": "Request",
		"auditID": "audit-002",
		"stage": "ResponseComplete",
		"requestURI": "/api/v1/namespaces/staging/pods/api-svc/exec?command=ls&command=/health",
		"verb": "create",
		"user": {
			"username": "sre-alice",
			"uid": "u-12345",
			"groups": ["system:authenticated", "sre-team"]
		},
		"sourceIPs": ["10.0.0.5"],
		"userAgent": "kubectl/v1.28.0",
		"objectRef": {
			"resource": "pods",
			"namespace": "staging",
			"name": "api-svc",
			"subresource": "exec"
		},
		"responseStatus": {"code": 200},
		"stageTimestamp": "2026-08-14T03:01:00Z"
	}`)

	s := service.New("prod-eu-west", nil)
	events, err := s.Process(raw, service.SourceK8sAudit)
	if err != nil {
		t.Fatalf("Process error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]

	if ev.Actor.IdentityType != model.IdentityUser {
		t.Errorf("identity type: got %s, want %s", ev.Actor.IdentityType, model.IdentityUser)
	}
	if ev.Actor.Username != "sre-alice" {
		t.Errorf("username: got %s, want sre-alice", ev.Actor.Username)
	}
	if ev.Actor.UserID != "u-12345" {
		t.Errorf("user ID: got %s, want u-12345", ev.Actor.UserID)
	}

	if ev.Action.Command != "ls /health" {
		t.Errorf("command: got %q, want 'ls /health'", ev.Action.Command)
	}

	if ev.Target.Namespace != "staging" {
		t.Errorf("namespace: got %s, want staging", ev.Target.Namespace)
	}

	if ev.Metadata["environment"] != "staging" {
		t.Errorf("environment: got %s, want staging", ev.Metadata["environment"])
	}
}

func TestK8sAudit_ServiceAccountExec(t *testing.T) {
	raw := []byte(`{
		"kind": "Event",
		"apiVersion": "audit.k8s.io/v1",
		"level": "Request",
		"auditID": "audit-003",
		"stage": "ResponseComplete",
		"requestURI": "/api/v1/namespaces/default/pods/worker/exec?command=curl&command=http://example.com",
		"verb": "create",
		"user": {
			"username": "system:serviceaccount:default:deploy-bot",
			"uid": "sa-67890",
			"groups": ["system:serviceaccounts", "system:authenticated"]
		},
		"sourceIPs": ["10.0.1.10"],
		"userAgent": "kubectl/v1.28.0",
		"objectRef": {
			"resource": "pods",
			"namespace": "default",
			"name": "worker",
			"subresource": "exec"
		},
		"responseStatus": {"code": 200},
		"stageTimestamp": "2026-08-14T03:02:00Z"
	}`)

	s := service.New("prod-eu-west", nil)
	events, err := s.Process(raw, service.SourceK8sAudit)
	if err != nil {
		t.Fatalf("Process error: %v", err)
	}

	ev := events[0]

	if ev.Actor.IdentityType != model.IdentityServiceAccount {
		t.Errorf("identity type: got %s, want %s", ev.Actor.IdentityType, model.IdentityServiceAccount)
	}
	if ev.Actor.ServiceAccount != "default/deploy-bot" {
		t.Errorf("service account: got %s, want default/deploy-bot", ev.Actor.ServiceAccount)
	}
}

func TestK8sAudit_DeniedExec(t *testing.T) {
	raw := []byte(`{
		"kind": "Event",
		"apiVersion": "audit.k8s.io/v1",
		"level": "Request",
		"auditID": "audit-004",
		"stage": "ResponseComplete",
		"requestURI": "/api/v1/namespaces/production/pods/payment-svc/exec?command=/bin/bash",
		"verb": "create",
		"user": {
			"username": "dev-bob",
			"uid": "u-bob",
			"groups": ["system:authenticated"]
		},
		"sourceIPs": ["10.0.0.20"],
		"userAgent": "kubectl/v1.28.0",
		"objectRef": {
			"resource": "pods",
			"namespace": "production",
			"name": "payment-svc",
			"subresource": "exec"
		},
		"responseStatus": {"code": 403, "reason": "Forbidden"},
		"stageTimestamp": "2026-08-14T03:03:00Z"
	}`)

	s := service.New("prod-eu-west", nil)
	events, err := s.Process(raw, service.SourceK8sAudit)
	if err != nil {
		t.Fatalf("Process error: %v", err)
	}

	ev := events[0]

	if ev.Metadata["denied"] != "true" {
		t.Error("expected metadata[denied]=true for 403 response")
	}
	if ev.Metadata["response_code"] != "403" {
		t.Errorf("response_code: got %s, want 403", ev.Metadata["response_code"])
	}
	if ev.Action.Type != model.ContainerExec {
		t.Errorf("action type: got %s, want %s", ev.Action.Type, model.ContainerExec)
	}
}

func TestK8sAudit_Batch(t *testing.T) {
	raw := []byte(`[
		{
			"kind": "Event",
			"apiVersion": "audit.k8s.io/v1",
			"auditID": "audit-a",
			"stage": "ResponseComplete",
			"requestURI": "/api/v1/namespaces/default/pods/p1/exec?command=ls",
			"verb": "create",
			"user": {"username": "user1", "uid": "u1", "groups": ["system:authenticated"]},
			"sourceIPs": ["10.0.0.1"],
			"objectRef": {"resource": "pods", "namespace": "default", "name": "p1", "subresource": "exec"},
			"responseStatus": {"code": 200},
			"stageTimestamp": "2026-08-14T03:00:00Z"
		},
		{
			"kind": "Event",
			"apiVersion": "audit.k8s.io/v1",
			"auditID": "audit-b",
			"stage": "ResponseComplete",
			"requestURI": "/api/v1/namespaces/default/pods/p2/exec?command=whoami",
			"verb": "create",
			"user": {"username": "user2", "uid": "u2", "groups": ["system:authenticated"]},
			"sourceIPs": ["10.0.0.2"],
			"objectRef": {"resource": "pods", "namespace": "default", "name": "p2", "subresource": "exec"},
			"responseStatus": {"code": 200},
			"stageTimestamp": "2026-08-14T03:01:00Z"
		}
	]`)

	s := service.New("test-cluster", nil)
	events, err := s.Process(raw, service.SourceK8sAudit)
	if err != nil {
		t.Fatalf("Process error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	if events[0].ID != "audit-a" || events[1].ID != "audit-b" {
		t.Errorf("event IDs: got %s, %s", events[0].ID, events[1].ID)
	}
	if events[0].Action.Command != "ls" {
		t.Errorf("event 0 command: got %q, want ls", events[0].Action.Command)
	}
	if events[1].Action.Command != "whoami" {
		t.Errorf("event 1 command: got %q, want whoami", events[1].Action.Command)
	}
}

func TestDocker_ExecCreate(t *testing.T) {
	raw := []byte(`{
		"Type": "container",
		"Action": "exec_create",
		"Actor": {
			"ID": "ctr-abc123",
			"Attributes": {
				"name": "my-container",
				"image": "nginx:latest"
			}
		},
		"scope": "local",
		"time": 1723606800,
		"timeNano": 1723606800000000000
	}`)

	s := service.New("docker-host-01", nil)
	events, err := s.Process(raw, service.SourceDocker)
	if err != nil {
		t.Fatalf("Process error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]

	if ev.Action.Type != model.ContainerExec {
		t.Errorf("action type: got %s, want %s", ev.Action.Type, model.ContainerExec)
	}
	if ev.Target.ContainerID != "ctr-abc123" {
		t.Errorf("container ID: got %s, want ctr-abc123", ev.Target.ContainerID)
	}
	if ev.Target.ContainerName != "my-container" {
		t.Errorf("container name: got %s, want my-container", ev.Target.ContainerName)
	}
	if ev.Metadata["image"] != "nginx:latest" {
		t.Errorf("image: got %s, want nginx:latest", ev.Metadata["image"])
	}

	if ev.Actor.IdentityType != model.IdentityAnonymous {
		t.Errorf("identity type: got %s, want %s", ev.Actor.IdentityType, model.IdentityAnonymous)
	}
	if ev.Actor.UserID != "unknown" {
		t.Errorf("user ID: got %s, want unknown", ev.Actor.UserID)
	}

	expected := time.Unix(0, 1723606800000000000)
	if !ev.Timestamp.Equal(expected) {
		t.Errorf("timestamp: got %v, want %v", ev.Timestamp, expected)
	}
}

func TestDocker_Attach(t *testing.T) {
	raw := []byte(`{
		"Type": "container",
		"Action": "attach",
		"Actor": {
			"ID": "ctr-def456",
			"Attributes": {"name": "worker", "image": "busybox"}
		},
		"scope": "local",
		"time": 1723606900
	}`)

	s := service.New("docker-host-01", nil)
	events, err := s.Process(raw, service.SourceDocker)
	if err != nil {
		t.Fatalf("Process error: %v", err)
	}

	ev := events[0]

	if ev.Action.Type != model.ContainerExec {
		t.Errorf("action type: got %s, want %s", ev.Action.Type, model.ContainerExec)
	}
	if !ev.Action.Interactive {
		t.Error("interactive: got false, want true for attach")
	}
}

func TestSidecar_UnknownSource(t *testing.T) {
	s := service.New("test-cluster", nil)
	_, err := s.Process([]byte(`{}`), "unknown_source")
	if err == nil {
		t.Fatal("expected error for unknown source, got nil")
	}
}

func TestSidecar_MalformedJSON(t *testing.T) {
	s := service.New("test-cluster", nil)
	_, err := s.Process([]byte(`{broken`), service.SourceK8sAudit)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}

	_, err = s.Process([]byte(`{broken`), service.SourceDocker)
	if err == nil {
		t.Fatal("expected error for malformed Docker JSON, got nil")
	}
}

func TestK8sAudit_EmptyPayload(t *testing.T) {
	s := service.New("test", nil)
	_, err := s.Process([]byte(``), service.SourceK8sAudit)
	if err == nil {
		t.Fatal("expected error for empty payload, got nil")
	}
}

func TestK8sAudit_NodeIdentity(t *testing.T) {
	raw := []byte(`{
		"kind": "Event",
		"apiVersion": "audit.k8s.io/v1",
		"auditID": "audit-node",
		"stage": "ResponseComplete",
		"requestURI": "/api/v1/namespaces/kube-system/pods/kube-proxy/exec?command=/bin/true",
		"verb": "create",
		"user": {
			"username": "system:node:worker-1",
			"uid": "node-1",
			"groups": ["system:nodes", "system:authenticated"]
		},
		"sourceIPs": ["10.0.0.3"],
		"objectRef": {"resource": "pods", "namespace": "kube-system", "name": "kube-proxy", "subresource": "exec"},
		"responseStatus": {"code": 200},
		"stageTimestamp": "2026-08-14T03:04:00Z"
	}`)

	s := service.New("prod-eu-west", nil)
	events, err := s.Process(raw, service.SourceK8sAudit)
	if err != nil {
		t.Fatalf("Process error: %v", err)
	}

	ev := events[0]

	if ev.Actor.IdentityType != model.IdentityNode {
		t.Errorf("identity type: got %s, want %s", ev.Actor.IdentityType, model.IdentityNode)
	}
}

func TestK8sAudit_MultiCommandExtraction(t *testing.T) {
	raw := []byte(`{
		"kind": "Event",
		"apiVersion": "audit.k8s.io/v1",
		"auditID": "audit-multi",
		"stage": "ResponseComplete",
		"requestURI": "/api/v1/namespaces/default/pods/foo/exec?command=/bin/sh&command=-c&command=cat%20%2Fetc%2Fpasswd",
		"verb": "create",
		"user": {"username": "attacker", "uid": "u-evil", "groups": ["system:authenticated"]},
		"sourceIPs": ["203.0.113.99"],
		"objectRef": {"resource": "pods", "namespace": "default", "name": "foo", "subresource": "exec"},
		"responseStatus": {"code": 200},
		"stageTimestamp": "2026-08-14T03:05:00Z"
	}`)

	s := service.New("prod-eu-west", nil)
	events, err := s.Process(raw, service.SourceK8sAudit)
	if err != nil {
		t.Fatalf("Process error: %v", err)
	}

	ev := events[0]

	expected := "/bin/sh -c cat /etc/passwd"
	if ev.Action.Command != expected {
		t.Errorf("command: got %q, want %q", ev.Action.Command, expected)
	}
}
