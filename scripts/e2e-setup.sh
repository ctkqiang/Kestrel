#!/usr/bin/env bash
# e2e-setup.sh —— 启动带审计日志的 Minikube 集群
#
# 用途：为 Kestrel e2e 真实场景测试准备环境。
# 审计日志路径：Minikube 节点内 /var/log/kubernetes/audit/audit.log
#
# 用法：
#   ./scripts/e2e-setup.sh          # 启动或重启 Minikube
#   ./scripts/e2e-setup.sh --force   # 强制重启

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AUDIT_POLICY="$SCRIPT_DIR/audit-policy.yaml"
AUDIT_LOG_PATH="/var/log/kubernetes/audit/audit.log"
MINIKUBE_PROFILE="kestrel-e2e"

FORCE=false
if [[ "${1:-}" == "--force" ]]; then
    FORCE=true
fi

echo "=== Kestrel e2e 环境准备 ==="
echo "项目根目录: $PROJECT_ROOT"
echo "审计策略文件: $AUDIT_POLICY"
echo ""

# 检查 minikube 是否已安装。
if ! command -v minikube >/dev/null 2>&1; then
    echo "[错误] 未找到 minikube，请先安装: https://minikube.sigs.k8s.io/docs/start/"
    exit 1
fi

if ! command -v kubectl >/dev/null 2>&1; then
    echo "[错误] 未找到 kubectl，请先安装。"
    exit 1
fi

# 检查是否已有同名 profile 在运行。
EXISTING=$(minikube profile list 2>/dev/null | grep "$MINIKUBE_PROFILE" || true)

if [[ -n "$EXISTING" && "$FORCE" == "false" ]]; then
    # 检查审计日志是否已配置。
    echo "检测到已有 Minikube profile: $MINIKUBE_PROFILE"
    echo "检查审计日志配置..."

    if minikube ssh -p "$MINIKUBE_PROFILE" "test -f $AUDIT_LOG_PATH" 2>/dev/null; then
        echo "审计日志已配置: $AUDIT_LOG_PATH"
        echo "如需重新配置，请运行: $0 --force"
        exit 0
    fi
    echo "审计日志未配置，需要重启 Minikube..."
    FORCE=true
fi

if [[ "$FORCE" == "true" ]]; then
    echo "停止并删除现有 Minikube 实例..."
    minikube delete -p "$MINIKUBE_PROFILE" 2>/dev/null || true
fi

echo ""
echo "启动 Minikube（带审计日志配置）..."
echo "  Profile: $MINIKUBE_PROFILE"
echo "  审计日志路径: $AUDIT_LOG_PATH"
echo "  审计策略文件: /etc/kubernetes/audit-policy.yaml"
echo ""

# 启动 Minikube 时同时指定 audit-log-path 和 audit-policy-file。
# 注意：audit-policy-file 必须先存在于节点上，但 Minikube 启动时文件还不存在。
# 解决方案：先启动（policy-file 指向不存在的文件，apiserver 会启动失败），
# 然后立即拷贝 policy 文件到节点，apiserver 会自动重试启动。
#
# 更可靠的方式：直接启动后再用 minikube cp 复制并 patch apiserver 静态 manifest。
minikube start -p "$MINIKUBE_PROFILE" \
    --extra-config="apiserver.audit-log-path=$AUDIT_LOG_PATH" \
    --extra-config="apiserver.audit-log-maxsize=100" \
    --extra-config="apiserver.audit-log-maxbackup=3" \
    --extra-config="apiserver.audit-log-maxage=1"

echo ""
echo "Minikube 已启动，注入审计策略文件..."

# 拷贝 audit-policy.yaml 到 Minikube 节点的 /etc/kubernetes/ 目录。
AUDIT_POLICY_NODE_PATH="/etc/kubernetes/audit-policy.yaml"
minikube cp "$AUDIT_POLICY" "$MINIKUBE_PROFILE:$AUDIT_POLICY_NODE_PATH" 2>/dev/null || {
    echo "  minikube cp 失败，改用 ssh 写入..."
    # 兜底方案：通过 ssh 直接写入。
    minikube ssh -p "$MINIKUBE_PROFILE" "sudo mkdir -p $(dirname $AUDIT_POLICY_NODE_PATH)"
    cat "$AUDIT_POLICY" | minikube ssh -p "$MINIKUBE_PROFILE" "sudo tee $AUDIT_POLICY_NODE_PATH > /dev/null"
}

echo "审计策略文件已写入: $AUDIT_POLICY_NODE_PATH"

# 通过 patch kube-apiserver 静态 manifest，添加 audit-policy-file 参数。
# Minikube 节点上 apiserver 静态 manifest 路径：/etc/kubernetes/manifests/kube-apiserver.yaml
APISERVER_MANIFEST="/etc/kubernetes/manifests/kube-apiserver.yaml"

# 检查是否已存在 audit-policy-file 参数，不存在则添加。
HAS_POLICY=$(minikube ssh -p "$MINIKUBE_PROFILE" "grep -c audit-policy-file $APISERVER_MANIFEST 2>/dev/null || echo 0")

if [[ "$HAS_POLICY" == "0" ]]; then
    echo "注入 audit-policy-file 参数到 apiserver 静态 manifest..."
    minikube ssh -p "$MINIKUBE_PROFILE" "sudo sed -i 's|- --audit-log-path=\(.*\)|- --audit-log-path=\1\n    - --audit-policy-file=$AUDIT_POLICY_NODE_PATH|' $APISERVER_MANIFEST"
    echo "apiserver 静态 manifest 已更新，等待 apiserver 重启..."

    # kubelet 会检测到 manifest 变化并重启 apiserver，等待 15 秒。
    sleep 15

    # 触发一次 API 调用让 apiserver 重新就绪。
    kubectl --context="$MINIKUBE_PROFILE" get --raw='/healthz' >/dev/null 2>&1 || true
    sleep 3
fi

# 验证审计日志文件是否创建。
echo "验证审计日志..."
sleep 2

if minikube ssh -p "$MINIKUBE_PROFILE" "test -f $AUDIT_LOG_PATH" 2>/dev/null; then
    echo "审计日志文件已创建: $AUDIT_LOG_PATH"
    # 触发一次 API 调用产生审计记录。
    kubectl --context="$MINIKUBE_PROFILE" get pods --all-namespaces >/dev/null 2>&1 || true
    sleep 2

    LINE_COUNT=$(minikube ssh -p "$MINIKUBE_PROFILE" "wc -l < $AUDIT_LOG_PATH" 2>/dev/null || echo "0")
    echo "当前审计日志行数: $LINE_COUNT"

    if [[ "$LINE_COUNT" == "0" ]]; then
        echo "[警告] 审计日志仍为空。"
        echo "  可能原因：audit-policy-file 未被 apiserver 加载。"
        echo "  请检查 apiserver pod 日志："
        echo "    kubectl --context=$MINIKUBE_PROFILE logs -n kube-system kube-apiserver-$(minikube ip -p $MINIKUBE_PROFILE | tr '.' '-')"
    fi
else
    echo "[错误] 审计日志文件未创建。"
    exit 1
fi

echo ""
echo "=== 环境准备完成 ==="
echo ""
echo "下一步："
echo "  make e2e           # 运行真实场景测试"
echo "  go test -tags e2e ./test/ -run TestE2ERealExec -v"
echo ""
echo "清理环境："
echo "  minikube delete -p $MINIKUBE_PROFILE"
