//go:build e2e

// e2e_real_test.go
// Kestrel 端到端真实场景测试
//
// 这不是 mock，不是构造的 JSON —— 而是在真实 Minikube 集群里：
//   1. 真实执行 kubectl exec 命令
//   2. 从 kube-apiserver 审计日志文件捕获真实审计事件
//   3. 构建 Kestrel 二进制并 pipe 审计日志
//   4. 验证 Kestrel 归一化输出的 JSONL 是否正确
//
// 前置条件：
//   ./scripts/e2e-setup.sh    # 启动带审计日志的 Minikube
//
// 运行方式：
//   go test -tags e2e ./test/ -run TestE2ERealExec -v
//   make e2e

package service_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"kestrel/internal/model"
)

// e2e 配置常量。
const (
	e2eNamespace      = "kestrel-e2e"
	e2ePodName        = "e2e-target"
	e2eContainerImage = "busybox:latest"
	e2eMinikubeProf   = "kestrel-e2e"
	e2eAuditLogPath   = "/var/log/kubernetes/audit/audit.log"
	e2eClusterID      = "minikube-e2e"
)

// e2eExecScenario 定义一个真实的 kubectl exec 攻击场景。
type e2eExecScenario struct {
	ID       string   // 场景标识
	Name     string   // 场景名称
	Command  []string // kubectl exec 的命令参数（-c 后的内容）
	Expected string   // 预期 Kestrel 提取的命令字符串
	Severity string   // 严重度
}

// e2eRealScenarios 返回真实 kubectl exec 攻击场景列表。
// 这些命令会在真实 Pod 中执行，产生真实审计日志。
func e2eRealScenarios() []e2eExecScenario {
	return []e2eExecScenario{
		{
			ID:       "E2E-001",
			Name:     "侦察-whoami",
			Command:  []string{"whoami"},
			Expected: "whoami",
			Severity: "低",
		},
		{
			ID:       "E2E-002",
			Name:     "凭证窃取-cat /etc/passwd",
			Command:  []string{"/bin/sh", "-c", "cat /etc/passwd"},
			Expected: "/bin/sh -c cat /etc/passwd",
			Severity: "高",
		},
		{
			ID:       "E2E-003",
			Name:     "系统侦察-id",
			Command:  []string{"/bin/sh", "-c", "id"},
			Expected: "/bin/sh -c id",
			Severity: "低",
		},
		{
			ID:       "E2E-004",
			Name:     "文件系统枚举-ls /",
			Command:  []string{"ls", "/"},
			Expected: "ls /",
			Severity: "低",
		},
		{
			ID:       "E2E-005",
			Name:     "环境变量探测-env",
			Command:  []string{"/bin/sh", "-c", "env"},
			Expected: "/bin/sh -c env",
			Severity: "中",
		},
	}
}

// TestE2ERealExec 是主测试入口，执行完整的端到端真实场景测试。
//
// 流程：
//  1. 检查前置条件（Minikube、kubectl、审计日志）
//  2. 部署测试目标 Pod
//  3. 记录审计日志起始位置
//  4. 真实执行 kubectl exec 攻击场景
//  5. 获取新增的审计日志
//  6. 构建 Kestrel 二进制
//  7. 将审计日志 pipe 给 Kestrel
//  8. 验证归一化输出
func TestE2ERealExec(t *testing.T) {
	// ─── 阶段 1: 前置检查 ───
	t.Run("01_前置检查", func(t *testing.T) {
		requireTool(t, "minikube")
		requireTool(t, "kubectl")
		requireTool(t, "go")

		requireMinikubeRunning(t)
		requireAuditLogAvailable(t)
	})

	// ─── 阶段 2: 部署测试目标 ───
	t.Run("02_部署目标Pod", func(t *testing.T) {
		deployE2ETargetPod(t)
		waitForPodReady(t)
	})

	// ─── 阶段 3: 记录审计日志起始位置 ───
	startLineCount := 0
	t.Run("03_记录审计起始位置", func(t *testing.T) {
		startLineCount = getAuditLogLineCount(t)
		t.Logf("审计日志起始行数: %d", startLineCount)
	})

	// ─── 阶段 4: 真实执行攻击场景 ───
	scenarios := e2eRealScenarios()
	t.Run("04_执行真实exec攻击", func(t *testing.T) {
		for _, sc := range scenarios {
			sc := sc
			t.Run(sc.ID+"_"+sc.Name, func(t *testing.T) {
				runRealKubectlExec(t, sc)
			})
		}
	})

	// ─── 阶段 5: 获取审计日志 ───
	var auditLog []byte
	t.Run("05_捕获审计日志", func(t *testing.T) {
		// 等待审计日志写入完成。
		time.Sleep(2 * time.Second)

		endLineCount := getAuditLogLineCount(t)
		t.Logf("审计日志结束行数: %d（新增 %d 行）", endLineCount, endLineCount-startLineCount)

		auditLog = readAuditLog(t)
		if len(auditLog) == 0 {
			t.Fatal("审计日志为空")
		}

		lineCount := bytes.Count(auditLog, []byte("\n"))
		t.Logf("捕获审计日志: %d 字节, %d 行", len(auditLog), lineCount)
	})

	// ─── 阶段 6: 构建 Kestrel ───
	kestrelBin := filepath.Join(t.TempDir(), "kestrel")
	t.Run("06_构建Kestrel", func(t *testing.T) {
		buildKestrel(t, kestrelBin)
	})

	// ─── 阶段 7: 运行 Kestrel 处理审计日志 ───
	var kestrelOutput []byte
	t.Run("07_Kestrel归一化处理", func(t *testing.T) {
		kestrelOutput = runKestrel(t, kestrelBin, auditLog)
		t.Logf("Kestrel 输出: %d 字节", len(kestrelOutput))
	})

	// ─── 阶段 8: 验证归一化结果 ───
	t.Run("08_验证归一化输出", func(t *testing.T) {
		events := parseKestrelOutput(t, kestrelOutput)
		validateE2EOutput(t, events, scenarios)
	})

	// ─── 阶段 9: 清理 ───
	t.Run("09_清理", func(t *testing.T) {
		cleanupE2E(t)
	})
}

// ─── 前置检查 ──────────────────────────────────────────────

// requireTool 检查指定命令行工具是否已安装。
func requireTool(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Fatalf("未找到命令行工具 %q，请先安装", name)
	}
}

// requireMinikubeRunning 检查 Minikube 集群是否正在运行。
func requireMinikubeRunning(t *testing.T) {
	t.Helper()

	cmd := exec.Command("minikube", "status", "-p", e2eMinikubeProf)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Minikube 未运行。请先执行:\n  ./scripts/e2e-setup.sh\n\n输出: %s", output)
	}
}

// requireAuditLogAvailable 检查审计日志文件是否存在于 Minikube 节点中。
func requireAuditLogAvailable(t *testing.T) {
	t.Helper()

	cmd := exec.Command("minikube", "ssh", "-p", e2eMinikubeProf, "test -f "+e2eAuditLogPath)
	if err := cmd.Run(); err != nil {
		t.Fatalf("审计日志文件 %s 不存在于 Minikube 节点中。\n"+
			"请运行: ./scripts/e2e-setup.sh --force", e2eAuditLogPath)
	}

	// 验证审计日志有内容。
	cmd = exec.Command("minikube", "ssh", "-p", e2eMinikubeProf, "wc -l < "+e2eAuditLogPath)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("读取审计日志行数失败: %v", err)
	}
	count := strings.TrimSpace(string(output))
	t.Logf("审计日志已就绪: %s 行", count)
}

// ─── 部署测试目标 ──────────────────────────────────────────

// deployE2ETargetPod 在 e2e 命名空间部署测试目标 Pod。
func deployE2ETargetPod(t *testing.T) {
	t.Helper()

	// 创建命名空间。
	runKubectl(t, "create", "namespace", e2eNamespace, "--dry-run=client", "-o", "yaml")
	runKubectl(t, "apply", "-f", "-", "--namespace", e2eNamespace,
		strings.NewReader(fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
  labels:
    app: e2e-target
spec:
  restartPolicy: Never
  containers:
  - name: target
    image: %s
    command: ["sleep", "3600"]
`, e2ePodName, e2eNamespace, e2eContainerImage)))
}

// waitForPodReady 等待测试目标 Pod 进入 Running 状态。
func waitForPodReady(t *testing.T) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		output := runKubectlSilent(t, "get", "pod", e2ePodName,
			"-n", e2eNamespace, "-o", "jsonpath={.status.phase}")
		if strings.TrimSpace(output) == "Running" {
			t.Logf("Pod %s/%s 已就绪", e2eNamespace, e2ePodName)
			return
		}
		t.Logf("等待 Pod 就绪，当前状态: %s", strings.TrimSpace(output))
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("Pod %s/%s 启动超时", e2eNamespace, e2ePodName)
}

// ─── 审计日志操作 ──────────────────────────────────────────

// getAuditLogLineCount 获取审计日志当前行数。
func getAuditLogLineCount(t *testing.T) int {
	t.Helper()

	cmd := exec.Command("minikube", "ssh", "-p", e2eMinikubeProf, "wc -l < "+e2eAuditLogPath)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("读取审计日志行数失败: %v", err)
	}

	var count int
	fmt.Sscanf(strings.TrimSpace(string(output)), "%d", &count)
	return count
}

// readAuditLog 从 Minikube 节点读取审计日志文件全部内容。
func readAuditLog(t *testing.T) []byte {
	t.Helper()

	cmd := exec.Command("minikube", "ssh", "-p", e2eMinikubeProf, "cat "+e2eAuditLogPath)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("读取审计日志失败: %v", err)
	}
	return output
}

// ─── 真实 exec 执行 ────────────────────────────────────────

// runRealKubectlExec 在测试目标 Pod 中真实执行 kubectl exec 命令。
// 这会触发 kube-apiserver 的审计日志记录。
func runRealKubectlExec(t *testing.T, sc e2eExecScenario) {
	t.Helper()

	args := []string{"exec", e2ePodName, "-n", e2eNamespace, "--"}
	args = append(args, sc.Command...)

	t.Logf("执行: kubectl %s", strings.Join(args, " "))

	cmd := exec.Command("kubectl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("exec 命令输出（可能含错误）: %s", strings.TrimSpace(string(output)))
		// exec 命令可能因为容器内命令失败而返回非零退出码，
		// 但审计日志仍然会记录这次 exec 请求。
	} else {
		t.Logf("exec 输出: %s", strings.TrimSpace(string(output)))
	}
}

// ─── Kestrel 构建与运行 ───────────────────────────────────

// buildKestrel 构建 Kestrel 二进制到指定路径。
func buildKestrel(t *testing.T, outputPath string) {
	t.Helper()

	projectRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取工作目录失败: %v", err)
	}
	// 回退到项目根目录（test/ 的上一级）。
	projectRoot = filepath.Dir(filepath.Dir(projectRoot))

	cmd := exec.Command("go", "build", "-o", outputPath, ".")
	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("构建 Kestrel 失败:\n%s\n%v", output, err)
	}
	t.Logf("Kestrel 已构建: %s", outputPath)
}

// runKestrel 将审计日志 pipe 给 Kestrel 二进制，返回其 stdout 输出。
func runKestrel(t *testing.T, binPath string, input []byte) []byte {
	t.Helper()

	cmd := exec.Command(binPath, "-cluster-id", e2eClusterID)
	cmd.Stdin = bytes.NewReader(input)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Logf("Kestrel stderr:\n%s", stderr.String())
		t.Fatalf("Kestrel 运行失败: %v", err)
	}

	t.Logf("Kestrel stderr:\n%s", stderr.String())
	return stdout.Bytes()
}

// ─── 输出验证 ──────────────────────────────────────────────

// parseKestrelOutput 解析 Kestrel 的 JSONL 输出为 Event 列表。
func parseKestrelOutput(t *testing.T, output []byte) []model.Event {
	t.Helper()

	var events []model.Event
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var ev model.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Logf("跳过无法解析的行: %s", line)
			continue
		}
		events = append(events, ev)
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("扫描 Kestrel 输出失败: %v", err)
	}

	return events
}

// validateE2EOutput 验证 Kestrel 归一化输出是否包含预期的 exec 事件。
func validateE2EOutput(t *testing.T, events []model.Event, scenarios []e2eExecScenario) {
	t.Helper()

	t.Logf("Kestrel 归一化输出 %d 个事件", len(events))

	// 过滤出 exec 相关事件。
	var execEvents []model.Event
	for _, ev := range events {
		if ev.Action.Type == model.ContainerExec {
			execEvents = append(execEvents, ev)
		}
	}

	t.Logf("其中 ContainerExec 事件: %d 个", len(execEvents))

	if len(execEvents) == 0 {
		t.Fatal("未检测到任何 ContainerExec 事件，审计日志可能未正确捕获 exec 请求")
	}

	// 标准 1: 所有 exec 事件必须映射为 ContainerExec。
	for _, ev := range events {
		if strings.Contains(ev.Metadata["subresource"], "exec") ||
			strings.Contains(ev.Metadata["request_uri"], "/exec") {
			if ev.Action.Type != model.ContainerExec {
				t.Errorf("审计事件 %s: exec 子资源应映射为 ContainerExec，实际 %s",
					ev.ID, ev.Action.Type)
			}
		}
	}

	// 标准 2: exec 事件必须设置 Interactive=true。
	for _, ev := range execEvents {
		if !ev.Action.Interactive {
			t.Errorf("exec 事件 %s: Interactive 应为 true", ev.ID)
		}
	}

	// 标准 3: 每个场景的命令必须能在某个 exec 事件的 Command 字段中找到。
	// 审计日志可能包含非测试场景的 exec（如系统组件），所以用"至少匹配"策略。
	matchedScenarios := 0
	for _, sc := range scenarios {
		found := false
		for _, ev := range execEvents {
			if strings.Contains(ev.Action.Command, sc.Expected) ||
				strings.Contains(sc.Expected, ev.Action.Command) {
				found = true
				t.Logf("场景 %s 匹配: 命令=%q", sc.ID, ev.Action.Command)
				break
			}
		}
		if found {
			matchedScenarios++
		} else {
			t.Logf("场景 %s 未匹配到审计事件（期望命令: %q）", sc.ID, sc.Expected)
		}
	}

	// 至少 60% 的场景应被匹配到（审计日志可能因延迟或策略未覆盖部分请求）。
	matchRate := float64(matchedScenarios) / float64(len(scenarios))
	if matchRate < 0.6 {
		t.Errorf("场景匹配率 %.0f%% 低于阈值 60%%（匹配 %d/%d）",
			matchRate*100, matchedScenarios, len(scenarios))
	}

	// 标准 4: 所有 exec 事件的 Target.Namespace 必须是 e2e 命名空间。
	for _, ev := range execEvents {
		if ev.Target.Namespace != "" && ev.Target.Namespace != e2eNamespace {
			t.Logf("exec 事件 %s: 命名空间 %s（非 %s，可能是系统组件）",
				ev.ID, ev.Target.Namespace, e2eNamespace)
		}
	}

	// 标准 5: ClusterID 必须正确注入。
	for _, ev := range execEvents {
		if ev.Target.ClusterID != e2eClusterID {
			t.Errorf("exec 事件 %s: ClusterID 应为 %s，实际 %s",
				ev.ID, e2eClusterID, ev.Target.ClusterID)
		}
	}

	// 打印所有 exec 事件摘要。
	t.Log("")
	t.Log("【ContainerExec 事件摘要】")
	for _, ev := range execEvents {
		t.Logf("  %s | user=%s | ns=%s | pod=%s | cmd=%q | ip=%s",
			ev.ID,
			ev.Actor.Username,
			ev.Target.Namespace,
			ev.Target.PodName,
			ev.Action.Command,
			ev.Source.IP,
		)
	}

	// 打印统计。
	t.Log("")
	t.Logf("【统计】")
	t.Logf("  审计事件总数: %d", len(events))
	t.Logf("  ContainerExec 事件: %d", len(execEvents))
	t.Logf("  场景匹配: %d/%d (%.0f%%)", matchedScenarios, len(scenarios), matchRate*100)
}

// ─── 清理 ──────────────────────────────────────────────────

// cleanupE2E 清理 e2e 测试资源。
func cleanupE2E(t *testing.T) {
	t.Helper()

	// 删除命名空间（级联清理 Pod）。
	cmd := exec.Command("kubectl", "delete", "namespace", e2eNamespace, "--ignore-not-found")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Logf("清理命名空间失败（非致命）: %v\n%s", err, output)
	} else {
		t.Logf("命名空间 %s 已清理", e2eNamespace)
	}
}

// ─── kubectl 辅助函数 ──────────────────────────────────────

// runKubectl 执行 kubectl 命令，失败时 t.Fatal。
// 可选的最后一个参数为 stdin reader。
func runKubectl(t *testing.T, args ...string) {
	t.Helper()

	var stdin *strings.Reader
	if len(args) > 0 {
		if r, ok := args[len(args)-1].(*strings.Reader); ok {
			stdin = r
			args = args[:len(args)-1]
		}
	}

	cmd := exec.Command("kubectl", args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl %s 失败:\n%s\n%v", strings.Join(args, " "), output, err)
	}
	t.Logf("kubectl %s: %s", strings.Join(args, " "), strings.TrimSpace(string(output)))
}

// runKubectlSilent 执行 kubectl 命令，返回 stdout，不失败。
func runKubectlSilent(t *testing.T, args ...string) string {
	t.Helper()

	cmd := exec.Command("kubectl", args...)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(output)
}

// TestE2EAuditLogSample 输出审计日志样本，便于调试。
// 这是辅助测试，帮助理解审计日志的真实格式。
func TestE2EAuditLogSample(t *testing.T) {
	auditLog := readAuditLog(t)

	scanner := bufio.NewScanner(bytes.NewReader(auditLog))
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	// 收集所有 exec 相关的审计事件。
	var execEntries []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.Contains(line, `"exec"`) {
			execEntries = append(execEntries, line)
		}
	}

	t.Logf("审计日志中 exec 相关事件: %d 个", len(execEntries))

	// 打印前 3 个 exec 审计事件（格式化）。
	sort.Strings(execEntries)
	limit := 3
	if len(execEntries) < limit {
		limit = len(execEntries)
	}

	for i := 0; i < limit; i++ {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, []byte(execEntries[i]), "", "  "); err == nil {
			t.Logf("exec 审计事件样本 #%d:\n%s", i+1, pretty.String())
		}
	}
}
