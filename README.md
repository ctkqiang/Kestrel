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
├── Makefile                         # 构建/测试/演示一站式工具
├── .gitignore
├── internal/
│   ├── config/                      # 配置管理
│   │   └── config.go                #   flag + 环境变量合并，校验与版本注入
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
│   ├── service/                     # 遥测归一化层
│   │   ├── sidecar.go               #   入口: Sidecar.Process(raw, source)
│   │   ├── k8s_audit.go             #   K8s 审计日志归一化器
│   │   └── docker_event.go          #   Docker daemon 事件归一化器
│   └── utilities/                   # 工具库
│       └── logger.go                #   结构化日志器 (4 级别 + verbose + 字段)
├── k8s/                             # Kubernetes 部署配置
│   ├── namespace.yaml               #   命名空间 (prod + dev)
│   ├── configmap.yaml               #   配置映射 (集群 ID、日志级别)
│   ├── rbac.yaml                    #   ServiceAccount + ClusterRole/Role
│   ├── deployment.yaml              #   Deployment (prod: 3 副本 / dev: 1 副本)
│   ├── service.yaml                 #   Service (prod: ClusterIP / dev: NodePort)
│   ├── ingress.yaml                 #   Ingress + NetworkPolicy
│   ├── test-target.yaml             #   测试目标 Pod (Gin 应用)
│   └── kustomization.yaml           #   Kustomize 入口
└── test/
    ├── sidecar_test.go             # 归一化器单元测试 (12 个用例)
    └── attack_test.go              # 安全测试套件 (集成构建标签)
```

## 快速开始

### 构建

```bash
make build    # 编译到 bin/kestrel
```

### 演示

```bash
make demo      # 内置演示数据，verbose 模式
```

### 测试

```bash
make test      # 运行全部测试
make vet       # 静态分析
make lint      # golangci-lint (需安装)
```

## 配置

### 命令行参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `-cluster-id` | 集群标识符 | 环境变量 `KESTREL_CLUSTER_ID` |
| `-v` | verbose 模式，输出 DEBUG 级别日志 | `false` |
| `-log-format` | 日志格式（text / json） | `text` |

### 环境变量

| 变量 | 说明 |
|---|---|
| `KESTREL_CLUSTER_ID` | 集群标识符，注入到所有归一化事件中 |

## 使用方式

### 从文件处理

```bash
cat audit.log | ./bin/kestrel -cluster-id prod-eu-west > events.jsonl
```

### 实时流处理

```bash
kubectl audit-stream | ./bin/kestrel -cluster-id prod-eu-west | detector
```

### Docker 事件流

```bash
docker events --format '{{json .}}' | ./bin/kestrel -cluster-id docker-host-01
```

### Verbose 模式

```bash
echo '{"auditID":"..."}' | ./bin/kestrel -cluster-id dev-cluster -v
```

### 信号

支持 `SIGINT`（Ctrl+C）和 `SIGTERM`优雅关停，收到信号后停止读取新输入，输出统计后退出。

## Kubernetes 部署

### 生产环境

```bash
# 应用全部配置（Kustomize）
kubectl apply -k k8s/

# 或单独应用
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
```

生产环境配置特点：
- 3 副本 RollingUpdate（maxSurge=1, maxUnavailable=0）
- ClusterIP Service + TLS Ingress（速率限制 + 安全头注入）
- NetworkPolicy（仅允许 ingress-nginx 和 kube-system 入站）
- ClusterRole 绑定（全局审计读取权限）
- 资源限制: CPU 100m-500m / Memory 64Mi-256Mi

### 开发环境

```bash
# 开发环境使用 dev 命名空间
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/rbac.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# NodePort 暴露到 30080
minikube service kestrel-sidecar -n kestrel-dev
```

开发环境配置特点：
- 1 副本 Recreate 策略
- NodePort Service（端口 30080）
- Role 限定在 dev 命名空间
- verbose 模式开启

### 测试目标部署

```bash
# 部署 Gin 测试应用 Pod
kubectl apply -f k8s/test-target.yaml
```

### 安全配置

所有环境共享的安全基线：

| 配置项 | 值 | 说明 |
|---|---|---|
| `runAsNonRoot` | `true` | 禁止 root 运行 |
| `runAsUser` | `1000` | 非特权用户 |
| `readOnlyRootFilesystem` | `true` | 只读文件系统 |
| `allowPrivilegeEscalation` | `false` | 禁止提权 |
| `capabilities.drop` | `ALL` | 丢弃所有 Linux capabilities |
| `seccompProfile` | `RuntimeDefault` | 默认 seccomp 配置 |

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

## 输出示例

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

### 一键全场景模拟 (make simulate)

`make simulate` 是最推荐的一键式测试入口，自动执行 6 个阶段并生成技术化表格报告：

```bash
make simulate         # 全自动：静态检查 + 构建 + 单元测试 + 演示 + e2e + 集成测试
make simulate-quick   # 快速模式：跳过 Minikube 部分，3 秒跑完
```

**6 个执行阶段：**

| 阶段 | 命令 | 依赖 | 说明 |
|---|---|---|---|
| 1/6 静态检查 | `go vet ./...` | 无 | 静态分析 |
| 2/6 构建 | `go build -o bin/kestrel .` | 无 | 编译二进制 |
| 3/6 单元测试 | 4 项子测试 | 无 | 归一化器 + exec 攻击方法论 |
| 4/6 演示模式 | `cat demo.jsonl \| ./bin/kestrel -v` | 构建产物 | 4 条样本归一化 |
| 5/6 e2e 真实测试 | `go test -tags e2e ./test/` | Minikube + 审计日志 | 真实 kubectl exec 场景 |
| 6/6 集成安全测试 | `go test -tags integration ./test/` | Minikube | 12 类 Web 攻击模拟 |

**输出报告示例：**

```
测试明细 (Test Details)
+----+--------------------------------------+--------+----------+----------+------------------------------------------+
| #  | 测试项 (Test Name)                   | 结果   | 耗时     | 日志行数 | 说明 (Detail)                            |
+----+--------------------------------------+--------+----------+----------+------------------------------------------+
| 1  | go vet ./...                         | [PASS] | 0s       |        0 | 耗时 0s, 日志 0 行                       |
| 2  | go build                             | [PASS] | 0s       |        0 | 耗时 0s, 日志 0 行                       |
| 3  | sidecar_test (12 用例)              | [PASS] | 1s       |        3 | 耗时 1s, 日志 3 行                       |
| 4  | exec_attack (20 场景)               | [PASS] | 0s       |        1 | 耗时 0s, 日志 1 行                       |
| 5  | quality_gates (6 门禁)              | [PASS] | 0s       |        8 | 耗时 0s, 日志 8 行                       |
| 6  | attack_report                        | [PASS] | 1s       |        1 | 耗时 1s, 日志 1 行                       |
| 7  | demo 归一化                          | [PASS] | 0s       |        0 | 输出 4 个事件, 退出码 0                  |
| 8  | e2e 真实测试                         | [SKIP] | 0s       |        0 | Minikube 未运行                         |
| 9  | 集成安全测试                          | [SKIP] | 0s       |        0 | Minikube 未运行                         |
+----+--------------------------------------+--------+----------+----------+------------------------------------------+

统计 (Statistics)
+--------------------------+-------------------+
| 指标 (Metric)            | 值 (Value)        |
+--------------------------+-------------------+
| 总测试项 (Total)         | 9                 |
| 通过 (Passed)            | 7                 |
| 失败 (Failed)            | 0                 |
| 跳过 (Skipped)           | 2                 |
| 通过率 (Pass Rate)       | 77.8%             |
| 总耗时 (Total Duration)  | 3s                |
+--------------------------+-------------------+
```

每项测试的详细日志保存在 `/tmp/kestrel-simulate-*.log`，失败时自动显示前 30 行 + 后 30 行。

### 单元测试

```bash
make test
# 或
go test ./test/ -v
```

覆盖 12 个用例：匿名 exec（真阳性）、SRE 调试（假阳性）、服务账号身份、被拒绝的 exec、批量摄入、Docker exec_create、Docker attach、未知来源错误、畸形 JSON、空载荷、节点身份、多命令提取。

### exec 攻击测试方法论

`exec_attack_test.go` 实现 5 层测试方法论，覆盖 20 个攻击场景：

```bash
go test ./test/ -run TestExecAttackScenarios -v      # 20 个场景
go test ./test/ -run TestExecAttackSuccessCriteria   # 6 个质量门禁（CI 用）
go test ./test/ -run TestExecAttackReport -v         # 汇总报告 + 缓解建议
```

| 类别 | 场景数 | 说明 |
|---|---|---|
| K8s exec 向量 | 12 | 匿名入侵、SA 滥用、反向 Shell、C2 外联、凭证窃取等 |
| Docker exec 向量 | 3 | exec_create、exec_start、attach |
| 健壮性测试 | 5 | URL 编码绕过、空命令、畸形 JSON、空载荷 |

### e2e 真实场景测试

`e2e_real_test.go` 在真实 Minikube 集群中执行真实 kubectl exec 命令，捕获审计日志并验证归一化：

```bash
# 1. 准备环境（启动带审计日志的 Minikube）
make e2e-setup
# 或 ./scripts/e2e-setup.sh --force

# 2. 运行 e2e 测试
make e2e
# 或 go test -tags e2e ./test/ -run TestE2ERealExec -v
```

5 个真实攻击场景：

| 场景 ID | 命令 | 严重度 |
|---|---|---|
| E2E-001 | `whoami` | 低 |
| E2E-002 | `/bin/sh -c cat /etc/passwd` | 高 |
| E2E-003 | `/bin/sh -c id` | 低 |
| E2E-004 | `ls /` | 低 |
| E2E-005 | `/bin/sh -c env` | 中 |

### 集成安全测试

集成测试使用 `//go:build integration` 构建标签，需要运行中的 Minikube 集群。

```bash
# 完整安全测试套件（需要 Minikube 运行中）
go test -tags integration ./test/ -v

# 仅运行安全评估
go test -tags integration ./test/ -run TestAttackSuite/Security_Assessment -v

# 仅运行边缘场景测试
go test -tags integration ./test/ -run "TestLargePayload|TestConcurrentRequests|TestMalformedJSON" -v

# 跳过长时间运行的测试
go test -tags integration ./test/ -short -v

# 带详细日志
go test -tags integration ./test/ -v -verbose

# 指定应用地址（跳过 Minikube 自动发现）
TEST_APP_URL=http://localhost:8080 go test -tags integration ./test/ -run TestSecurity -v
```

#### 测试框架结构

**4 个执行阶段：**

| 阶段 | 函数 | 职责 |
|---|---|---|
| Setup | `Setup_Kubernetes_Deployment` | 创建 Namespace → 部署 Deployment + Service + Ingress → 等待滚动更新 |
| Health Check | `Health_Check` | 轮询 `/health` → 验证所有端点响应 |
| Security Assessment | `Security_Assessment` | 12 类攻击模拟 → 生成报告 |
| Teardown | `Teardown` | 删除 Namespace（级联清理所有资源） |

**安全测试覆盖：**

| 测试类别 | 载荷数 | 严重度 | 检测内容 |
|---|---|---|---|
| 路径穿越 | 5 | 高 | `../` 序列、URL 编码绕过 |
| 命令注入 | 8 | 高 | Shell 元字符、子命令注入 |
| SSRF | 8 | 高 | 云元数据端点、内网扫描 |
| SQL 注入 | 6 | 高 | 布尔注入、UNION、堆叠查询 |
| 认证绕过 | 10 | 高 | 请求头伪造、路径绕过 |
| 跨站脚本 | 6 | 中 | 反射型 XSS、事件处理器注入 |
| 开放重定向 | 5 | 中 | 外部域名跳转、协议注入 |
| 目录列表 | 8 | 中 | 敏感文件暴露、`.git`/`.env` |
| 安全响应头 | 6 | 中 | HSTS、CSP、X-Frame-Options |
| HTTP 方法篡改 | 9 | 低 | TRACE/PROPFIND/CONNECT |
| HTTP 参数污染 | 4 | 低 | 重复参数绕过 |
| Host 头注入 | 4 | 低 | 恶意 Host 反射 |

**边缘场景测试：**

| 测试 | 验证内容 |
|---|---|
| `TestLargePayload` | 1MB 请求体不导致服务端崩溃 |
| `TestSlowLoris` | 慢速连接被正确拒绝或超时 |
| `TestConcurrentRequests` | 50 并发 200 请求无失败 |
| `TestEmptyBody` | 空请求体不导致 5xx 错误 |
| `TestMalformedJSON` | 8 种畸形 JSON 不导致 5xx 错误 |
| `TestHTTPTimeout` | 超时请求正确处理 |
| `TestUnicodeInput` | Unicode/Emoji/控制字符不导致崩溃 |

**错误处理测试：**

| 测试 | 验证内容 |
|---|---|
| `TestKubeClientConnectionError` | 无效 kubeconfig 路径正确报错 |
| `TestNamespaceDeletionTimeout` | 命名空间删除超时处理 |
| `TestInvalidDeploySpec` | 无效 Deployment 规格被 K8s API 拒绝 |

**集成点测试：**

| 测试 | 验证内容 |
|---|---|
| `TestServiceDNSResolution` | Service ClusterIP + selector 正确配置 |
| `TestPodRestartRecovery` | Pod 删除后自动恢复 |
| `TestRollingUpdate` | 滚动更新期间服务不中断 |
| `TestConfigMapPropagation` | ConfigMap 创建/更新/读取 |
| `TestServiceAccountToken` | SA Token 投影卷挂载 |
| `TestSecretMount` | Secret 创建与存储 |

**K8s 安全基线测试：**

| 测试 | 验证内容 |
|---|---|
| `TestDeploymentSecurityContext` | RunAsNonRoot、ReadOnlyRootFilesystem、NoPrivilegeEscalation |
| `TestPodSecurityContext` | Pod 级 SeccompProfile |
| `TestNetworkIsolation` | NetworkPolicy 存在性检查 |
| `TestResourceLimits` | CPU/Memory Limits + Requests |
| `TestNoSecretsInEnv` | 环境变量无硬编码密钥 |

## 设计原则

1. **归一化 ≠ 检测** — Sidecar 只负责把原始遥测变成干净的 `model.Event`，不生成信号或告警
2. **Denied exec 仍记录** — 被拒绝的尝试是宝贵的检测信号
3. **Docker 缺身份 → 保守匿名** — 让检测器以更高警觉评估
4. **零外部依赖** — 仅用 Go 标准库
5. **管道模式** — stdin/stdout JSONL，适合 Kubernetes sidecar 部署
6. **优雅关停** — SIGINT/SIGTERM 信号响应，不丢正在处理的事件

## MITRE ATT&CK 映射

| 字段 | 值 |
|---|---|
| Technique | T1059.013 — Container CLI/API |
| Detection Strategy | DET0083 |
| Analytic | AN0233 |

参考：https://attack.mitre.org/detectionstrategies/DET0083/
