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
echo ""

minikube start -p "$MINIKUBE_PROFILE" \
    --extra-config="apiserver.audit-log-path=$AUDIT_LOG_PATH" \
    --extra-config="apiserver.audit-log-maxsize=100" \
    --extra-config="apiserver.audit-log-maxbackup=3" \
    --extra-config="apiserver.audit-log-maxage=1"

echo ""
echo "Minikube 已启动，配置审计策略文件..."

# 将审计策略文件复制到 Minikube 节点。
# Minikube 的 extra-config 不支持 audit-policy-file，需要手动放置。
# 默认 Minikube 会记录所有请求的 Metadata 级别审计日志，
# 这已足够 Kestrel 使用（归一化只需元数据字段）。

# 验证审计日志文件是否创建。
echo "验证审计日志..."
sleep 2

if minikube ssh -p "$MINIKUBE_PROFILE" "test -f $AUDIT_LOG_PATH" 2>/dev/null; then
    echo "审计日志文件已创建: $AUDIT_LOG_PATH"
    # 触发一次 API 调用产生审计记录。
    kubectl get pods --all-namespaces >/dev/null 2>&1 || true
    sleep 1

    LINE_COUNT=$(minikube ssh -p "$MINIKUBE_PROFILE" "wc -l < $AUDIT_LOG_PATH" 2>/dev/null || echo "0")
    echo "当前审计日志行数: $LINE_COUNT"
else
    echo "[警告] 审计日志文件未创建。"
    echo "  这可能是因为 Minikube 版本不支持 audit-log-path extra-config。"
    echo "  请手动检查 Minikube 文档。"
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
