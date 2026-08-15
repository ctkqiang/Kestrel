#!/usr/bin/env bash
# e2e-real.sh —— Kestrel 端到端真实场景测试一键编排
#
# 完整流程：
#   1. 检查/启动 Minikube（带审计日志）
#   2. 构建 Kestrel 二进制
#   3. 运行 e2e 真实场景测试
#   4. 输出结果报告
#
# 用法：
#   ./scripts/e2e-real.sh           # 全流程
#   ./scripts/e2e-real.sh --skip-setup  # 跳过环境准备（已启动 Minikube）

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SKIP_SETUP=false
if [[ "${1:-}" == "--skip-setup" ]]; then
    SKIP_SETUP=true
fi

echo "═══════════════════════════════════════════════════════"
echo "       Kestrel 端到端真实场景测试"
echo "═══════════════════════════════════════════════════════"
echo ""

# 阶段 1: 环境准备
if [[ "$SKIP_SETUP" == "true" ]]; then
    echo "[1/3] 跳过环境准备"
else
    echo "[1/3] 准备 Minikube 环境..."
    "$SCRIPT_DIR/e2e-setup.sh"
fi

echo ""

# 阶段 2: 构建 Kestrel
echo "[2/3] 构建 Kestrel..."
cd "$PROJECT_ROOT"
make build
echo "Kestrel 已构建: $(ls -la bin/kestrel 2>/dev/null || echo '未找到')"
echo ""

# 阶段 3: 运行 e2e 测试
echo "[3/3] 运行 e2e 真实场景测试..."
echo ""

go test -tags e2e ./test/ -run TestE2ERealExec -v -count=1 -timeout 300s

echo ""
echo "═══════════════════════════════════════════════════════"
echo "       e2e 测试完成"
echo "═══════════════════════════════════════════════════════"
