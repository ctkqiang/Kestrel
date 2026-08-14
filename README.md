# Kestrel

容器安全遥测归一化引擎，针对 MITRE ATT&CK **T1059.013 — Container CLI/API** 检测场景。

参考：[DET0083](https://attack.mitre.org/detectionstrategies/DET0083/) / AN0233

## 架构

```
原始遥测 (JSONL)          归一化事件 (JSONL)
     │                         │
     ▼                         ▼
┌──────────┐    ┌───────────────────────┐    ┌──────────┐
│  stdin   │───▶│  main.go (管道处理器)  │───▶│  stdout  │
└──────────┘    └───────────────────────┘    └──────────┘
                       │
                       ▼
              ┌──────────────────┐
              │  service.Sidecar  │
              │                   │
              │  ┌─────────────┐  │
              │  │ detectSource│  │  ← 推断 K8s audit / Docker
              │  └──────┬──────┘  │
              │         ▼         │
              │  ┌─────┐ ┌──────┐│
              │  │K8s  │ │Docker││  ← 各自的归一化器
              │  │Audit│ │Event ││
              │  └─────┘ └──────┘│
              │         │         │
              │         ▼         │
              │   model.Event     │
              └──────────────────┘
```

## 检测管线

```
RAW TELEMETRY → [SIDECAR] → NORMALIZED EVENT → SIGNAL → ACTIVITY → CONTEXT EVAL → RISK → FINDING → MITRE MAPPING
                 ✅ 已实现                                                                                   待实现
```

### 各层职责

| 层 | 状态 | 职责 |
|---|---|---|
| **Sidecar** (`internal/service/`) | ✅ 已实现 | 原始 JSON → `model.Event` 归一化 |
| **Detector** (`internal/engine/`) | 待实现 | Event → Signal 信号提取 |
| **Correlator** | 待实现 | Signal → Activity 事件关联 |
| **Scorer** | 待实现 | Activity → Finding 风险评分 |

## 项目结构

```
Kestrel/
├── main.go                          # 管道处理器入口 (stdin JSONL → stdout JSONL)
├── go.mod
├── internal/
│   ├── model/                       # 数据模型层
│   │   ├── action.go                #   动作类型 (container_exec, shell_spawn, ...)
│   │   ├── actor.go                 #   执行者 (身份类型: user/SA/node/anonymous)
│   │   ├── activity.go              #   活动 (关联事件的集合)
│   │   ├── context.go              #   上下文 (授权状态、环境标识)
│   │   ├── correlation_key.go       #   关联键 (ActorID + SourceIP + ClusterID + SessionID)
│   │   ├── event.go                 #   事件 (归一化后的安全事件)
│   │   ├── finding.go               #   检测结果 (严重度 + 置信度 + 证据)
│   │   ├── k8.go                    #   Kubernetes 集群信息
│   │   ├── network.go              #   网络元数据
│   │   ├── process.go              #   进程元数据
│   │   ├── signal.go               #   信号 (异常类型 + 权重 + 证据)
│   │   ├── source.go               #   事件来源
│   │   └── target.go               #   目标 (集群/命名空间/Pod/容器)
│   └── service/                     # 遥测归一化层
│       ├── sidecar.go               #   入口: Sidecar.Process(raw, source)
│       ├── k8s_audit.go             #   K8s 审计日志归一化器
│       └── docker_event.go          #   Docker daemon 事件归一化器
└── test/
    └── sidecar_test.go             # 归一化器测试 (12 个用例)
```

## 支持的遥测来源

### Kubernetes 审计日志

从 K8s API Server 审计日志接收 `container/exec`、`container/attach`、`container/portforward` 调用。

提取字段：
- `auditID` → `Event.ID`
- `stageTimestamp` → `Event.Timestamp`
- `user.username` + groups → `Actor.IdentityType`（anonymous / service_account / node / user）
- `requestURI` 查询参数 → `Action.Command`（多命令拼接）
- `objectRef.subresource` → `Action.Type`（exec → ContainerExec）
- `sourceIPs[0]` → `Actor.SourceIP`
- `responseStatus.code` → 403/401 标记为 `denied`
- `objectRef.namespace` → `Target.Namespace` + 环境推断

### Docker Daemon 事件

从 Docker daemon `/events` 流接收 `exec_create`、`exec_start`、`attach` 事件。

提取字段：
- `Actor.ID` → `Target.ContainerID`
- `Actor.Attributes["name"]` → `Target.ContainerName`
- `Actor.Attributes["image"]` → `Metadata["image"]`
- `Time` / `TimeNano` → `Event.Timestamp`
- 缺少用户身份 → 保守默认 `anonymous`

## 关键归一化逻辑

### 身份分类

| 用户名模式 | 身份类型 | 说明 |
|---|---|---|
| `system:anonymous` | `anonymous` | 匿名访问，高警觉 |
| `system:serviceaccount:{ns}:{name}` | `service_account` | 提取 SA 名称 |
| `system:node:{name}` | `node` | 节点身份 |
| 其他 | `user` | 普通用户 |

### 命令提取

K8s audit 的 `requestURI` 带有查询参数：

```
/api/v1/namespaces/default/pods/foo/exec?command=/bin/sh&command=-c&command=cat%20%2Fetc%2Fpasswd
```

归一化后：

```
/bin/sh -c cat /etc/passwd
```

### 被拒绝的 exec

403/401 响应仍然被归一化，标记 `metadata["denied"]=true`。被拒绝的执行尝试本身是有价值的检测信号。

## 使用方式

### 从文件处理

```bash
cat audit.log | KESTREL_CLUSTER_ID=prod-eu-west ./kestrel > events.jsonl
```

### 实时流处理

```bash
kubectl audit-stream | KESTREL_CLUSTER_ID=prod-eu-west ./kestrel | detector
```

### Docker 事件流

```bash
docker events --format '{{json .}}' | KESTREL_CLUSTER_ID=docker-host-01 ./kestrel
```

### 输出示例

```json
{
  "id": "audit-001",
  "timestamp": "2026-08-14T03:00:00Z",
  "actor": {
    "user_id": "",
    "username": "system:anonymous",
    "source_ip": "203.0.113.50",
    "user_agent": "kubectl/v1.28.0",
    "service_account": "",
    "identity_type": "anonymous"
  },
  "action": {
    "type": "container_exec",
    "command": "/bin/sh -c cat /etc/passwd",
    "interactive": true
  },
  "target": {
    "cluster_id": "prod-eu-west",
    "namespace": "production",
    "pod_id": "",
    "pod_name": "payment-svc",
    "container_id": "",
    "container_name": ""
  },
  "source": {
    "ip": "203.0.113.50",
    "port": 0,
    "hostname": "",
    "service": "kubectl/v1.28.0"
  },
  "metadata": {
    "audit_id": "audit-001",
    "audit_stage": "ResponseComplete",
    "environment": "production",
    "response_code": "200",
    "source_type": "k8s_audit",
    "subresource": "exec",
    "verb": "create"
  }
}
```

## 测试

```bash
go test ./test/ -v
```

覆盖 12 个用例：匿名 exec（真阳性）、SRE 调试（假阳性）、服务账号身份、被拒绝的 exec、批量摄入、Docker exec_create、Docker attach、未知来源错误、畸形 JSON、空载荷、节点身份、多命令提取。

## 设计原则

1. **归一化 ≠ 检测** — Sidecar 只负责把原始遥测变成干净的 `model.Event`，不生成信号或告警
2. **Denied exec 仍记录** — 被拒绝的尝试是宝贵的检测信号
3. **Docker 缺身份 → 保守匿名** — 让检测器以更高警觉评估
4. **零外部依赖** — 仅用 Go 标准库
5. **管道模式** — stdin/stdout JSONL，适合 Kubernetes sidecar 部署

## MITRE ATT&CK 映射

| 字段 | 值 |
|---|---|
| Technique | T1059.013 — Container CLI/API |
| Detection Strategy | DET0083 |
| Analytic | AN0233 |

参考：https://attack.mitre.org/detectionstrategies/DET0083/
