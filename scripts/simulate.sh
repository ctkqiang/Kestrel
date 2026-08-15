#!/usr/bin/env bash
# simulate.sh —— Kestrel 全场景自动化模拟
#
# 一键执行全部测试与演示，生成技术化表格报告：
#   1. 静态检查（go vet）
#   2. 构建 Kestrel 二进制
#   3. 单元测试（归一化器 + exec 攻击方法论）
#   4. 演示模式（demo 数据归一化）
#   5. e2e 真实场景测试（需 Minikube，自动检测）
#   6. 集成安全测试（需 Minikube，自动检测）
#
# 退出码：0 全部通过，1 有失败
#
# 用法：
#   make simulate           # 全自动
#   ./scripts/simulate.sh   # 直接运行
#   ./scripts/simulate.sh --skip-e2e    # 跳过 e2e（只跑本地）

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# 参数解析
SKIP_E2E=false
if [[ "${1:-}" == "--skip-e2e" ]]; then
    SKIP_E2E=true
fi

# 颜色定义
if [[ -t 1 ]]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    DIM='\033[2m'
    RESET='\033[0m'
else
    GREEN='' RED='' YELLOW='' BLUE='' CYAN='' BOLD='' DIM='' RESET=''
fi

# 计数器
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
TOTAL_START=$(date +%s)

# 结果数组：格式 "STATUS~NAME~DETAIL~DURATION~LINES"（用 ~ 避免与内容中的 | 冲突）
declare -a RESULTS=()

# 打印阶段标题
print_header() {
    local num="$1"
    local title="$2"
    echo ""
    echo -e "${CYAN}${BOLD}[$num] $title${RESET}"
    echo -e "${CYAN}+----------------------------------------------------------+${RESET}"
}

# 打印单项结果
print_result() {
    local name="$1"
    local status="$2"
    local detail="${3:-}"
    local duration="${4:-0}"
    local lines="${5:-0}"

    case "$status" in
        PASS)
            echo -e "  ${GREEN}[PASS]${RESET} $name"
            if [[ -n "$detail" ]]; then echo -e "         $detail"; fi
            PASS_COUNT=$((PASS_COUNT + 1))
            RESULTS+=("PASS~${name}~${detail}~${duration}~${lines}")
            ;;
        FAIL)
            echo -e "  ${RED}[FAIL]${RESET} $name"
            if [[ -n "$detail" ]]; then echo -e "         $detail"; fi
            FAIL_COUNT=$((FAIL_COUNT + 1))
            RESULTS+=("FAIL~${name}~${detail}~${duration}~${lines}")
            ;;
        SKIP)
            echo -e "  ${YELLOW}[SKIP]${RESET} $name"
            if [[ -n "$detail" ]]; then echo -e "         $detail"; fi
            SKIP_COUNT=$((SKIP_COUNT + 1))
            RESULTS+=("SKIP~${name}~${detail}~${duration}~${lines}")
            ;;
    esac
}

# 执行步骤并记录结果，失败时输出详细日志
run_step() {
    local name="$1"
    local cmd="$2"

    # 清理 name 中的特殊字符作为日志文件名
    local safe_name="${name//\//_}"
    safe_name="${safe_name// /_}"
    safe_name="${safe_name//./_}"
    local log_file="/tmp/kestrel-simulate-${safe_name}.log"

    echo -e "  ${BLUE}CMD:${RESET} $cmd"
    local start_time=$(date +%s)
    eval "$cmd" > "$log_file" 2>&1
    local exit_code=$?
    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    local lines=$(wc -l < "$log_file" 2>/dev/null || echo "0")

    if [[ $exit_code -eq 0 ]]; then
        print_result "$name" "PASS" "耗时 ${elapsed}s, 日志 ${lines} 行" "${elapsed}" "${lines}"
    else
        print_result "$name" "FAIL" "退出码 $exit_code, 耗时 ${elapsed}s, 日志 ${lines} 行" "${elapsed}" "${lines}"
        echo -e "  ${RED}--- 详细日志 ($log_file) ---${RESET}"
        if [[ "$lines" -le 80 ]]; then
            cat "$log_file" | sed 's/^/      /'
        else
            echo "      ... (前 30 行) ..."
            head -30 "$log_file" | sed 's/^/      /'
            echo "      ... (省略 $((lines - 60)) 行, 完整日志: $log_file) ..."
            echo "      ... (后 30 行) ..."
            tail -30 "$log_file" | sed 's/^/      /'
        fi
        echo -e "  ${RED}--- 日志结束 ---${RESET}"
    fi
    return $exit_code
}

# ============================================================
# 开始
# ============================================================
echo -e "${BOLD}${CYAN}"
echo "+============================================================+"
echo "|              Kestrel 全场景自动化模拟                       |"
echo "+============================================================+"
echo -e "${RESET}"
echo -e "${DIM}项目路径: $PROJECT_ROOT${RESET}"
echo -e "${DIM}开始时间: $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
echo -e "${DIM}Skip e2e: $SKIP_E2E${RESET}"

# ============================================================
# [1/6] 静态检查
# ============================================================
print_header "1/6" "静态检查 (go vet)"

if command -v go >/dev/null 2>&1; then
    run_step "go vet ./..." "go vet ./..."
else
    print_result "go vet" "SKIP" "go 未安装"
fi

# ============================================================
# [2/6] 构建
# ============================================================
print_header "2/6" "构建 Kestrel 二进制"

if command -v go >/dev/null 2>&1; then
    if run_step "go build" "mkdir -p bin && go build -ldflags '-X kestrel/internal/config.Version=simulate' -o bin/kestrel ."; then
        local_bin_size=$(ls -la bin/kestrel 2>/dev/null | awk '{print $5}')
        echo -e "  ${DIM}产物: bin/kestrel ($local_bin_size bytes)${RESET}"
    fi
else
    print_result "go build" "SKIP" "go 未安装"
    exit 1
fi

# ============================================================
# [3/6] 单元测试
# ============================================================
print_header "3/6" "单元测试 (归一化器 + exec 攻击方法论)"

echo -e "  ${BOLD}[3a] 归一化器单元测试 (sidecar_test.go)${RESET}"
run_step "sidecar_test (12 用例)" "go test ./test/ -run 'TestK8sAudit|TestDocker|TestSidecar' -v -count=1 2>&1 | tail -3"

echo ""
echo -e "  ${BOLD}[3b] exec 攻击场景测试 (exec_attack_test.go)${RESET}"
run_step "exec_attack (20 场景)" "go test ./test/ -run TestExecAttackScenarios -count=1 2>&1 | tail -3"

echo ""
echo -e "  ${BOLD}[3c] 质量门禁验证 (6 项)${RESET}"
run_step "quality_gates (6 门禁)" "go test ./test/ -run TestExecAttackSuccessCriteria -v -count=1 2>&1 | tail -8"

echo ""
echo -e "  ${BOLD}[3d] 攻击报告生成${RESET}"
run_step "attack_report" "go test ./test/ -run TestExecAttackReport -count=1 2>&1 | tail -3"

# ============================================================
# [4/6] 演示模式
# ============================================================
print_header "4/6" "演示模式 (demo 数据归一化)"

DEMO_INPUT='/tmp/kestrel-simulate-input.jsonl'
cat > "$DEMO_INPUT" <<'EOF'
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"RequestResponse","auditID":"sim-001","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/production/pods/payment-svc/exec?command=/bin/sh&command=-c&command=cat%20%2Fetc%2Fpasswd","verb":"create","user":{"username":"system:anonymous","groups":["system:unauthenticated"]},"sourceIPs":["203.0.113.50"],"userAgent":"kubectl/v1.28.0","objectRef":{"resource":"pods","namespace":"production","name":"payment-svc","subresource":"exec"},"responseStatus":{"code":200},"stageTimestamp":"2026-08-14T03:00:00Z"}
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Request","auditID":"sim-002","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/staging/pods/api-svc/exec?command=ls&command=/health","verb":"create","user":{"username":"sre-alice","uid":"u-12345","groups":["system:authenticated","sre-team"]},"sourceIPs":["10.0.0.5"],"userAgent":"kubectl/v1.28.0","objectRef":{"resource":"pods","namespace":"staging","name":"api-svc","subresource":"exec"},"responseStatus":{"code":200},"stageTimestamp":"2026-08-14T03:01:00Z"}
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Request","auditID":"sim-003","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/production/pods/payment-svc/exec?command=/bin/bash","verb":"create","user":{"username":"dev-bob","uid":"u-bob","groups":["system:authenticated"]},"sourceIPs":["10.0.0.20"],"userAgent":"kubectl/v1.28.0","objectRef":{"resource":"pods","namespace":"production","name":"payment-svc","subresource":"exec"},"responseStatus":{"code":403,"reason":"Forbidden"},"stageTimestamp":"2026-08-14T03:02:00Z"}
{"Type":"container","Action":"exec_create","Actor":{"ID":"ctr-abc123","Attributes":{"name":"compromised","image":"nginx:latest"}},"scope":"local","time":1723606800,"timeNano":1723606800000000000}
EOF

echo -e "  ${DIM}输入: 4 条遥测样本 (3 K8s audit + 1 Docker event)${RESET}"
echo -e "  ${BLUE}CMD:${RESET} cat \$DEMO | ./bin/kestrel -cluster-id simulate -v"

DEMO_OUTPUT=$(cat "$DEMO_INPUT" | ./bin/kestrel -cluster-id simulate -v 2>/dev/null)
DEMO_EXIT=$?
DEMO_LINES=$(echo "$DEMO_OUTPUT" | grep -c '"id"' || echo "0")

if [[ $DEMO_EXIT -eq 0 && "$DEMO_LINES" -gt 0 ]]; then
    print_result "demo 归一化" "PASS" "输出 $DEMO_LINES 个事件, 退出码 $DEMO_EXIT"
    echo -e "  ${BOLD}归一化事件摘要:${RESET}"
    echo "$DEMO_OUTPUT" | python3 -c "
import sys, json
print('  +----------+----------------+----------------+------------------+------------------------------------------+')
print('  | ID       | Identity       | Action         | Namespace        | Command                                  |')
print('  +----------+----------------+----------------+------------------+------------------------------------------+')
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        ev = json.loads(line)
        actor = ev.get('actor', {})
        action = ev.get('action', {})
        target = ev.get('target', {})
        print(f\"  | {ev.get('id','?')[:8]:8} | {actor.get('identity_type','?'):14} | {action.get('type','?'):14} | {target.get('namespace','?'):16} | {action.get('command','')[:40]:40} |\")
    except: pass
print('  +----------+----------------+----------------+------------------+------------------------------------------+')
" 2>/dev/null || echo "$DEMO_OUTPUT" | head -4 | sed 's/^/    /'
else
    print_result "demo 归一化" "FAIL" "退出码 $DEMO_EXIT, 输出 $DEMO_LINES 行"
fi

rm -f "$DEMO_INPUT"

# ============================================================
# [5/6] e2e 真实场景测试
# ============================================================
print_header "5/6" "e2e 真实场景测试 (Minikube + 真实 kubectl exec)"

if [[ "$SKIP_E2E" == "true" ]]; then
    print_result "e2e 真实测试" "SKIP" "用户指定 --skip-e2e"
elif ! command -v minikube >/dev/null 2>&1; then
    print_result "e2e 真实测试" "SKIP" "minikube 未安装"
elif ! minikube status -p kestrel-e2e >/dev/null 2>&1; then
    print_result "e2e 真实测试" "SKIP" "Minikube 未运行 (运行 make e2e-setup)"
else
    echo -e "  ${BLUE}CMD:${RESET} go test -tags e2e ./test/ -run TestE2ERealExec -v"
    run_step "e2e 真实 exec 场景" "go test -tags e2e ./test/ -run TestE2ERealExec -v -count=1 -timeout 300s 2>&1"
fi

# ============================================================
# [6/6] 集成安全测试
# ============================================================
print_header "6/6" "集成安全测试 (Minikube + 12 类 Web 攻击)"

if [[ "$SKIP_E2E" == "true" ]]; then
    print_result "集成安全测试" "SKIP" "用户指定 --skip-e2e"
elif ! command -v minikube >/dev/null 2>&1; then
    print_result "集成安全测试" "SKIP" "minikube 未安装"
elif ! minikube status -p kestrel-e2e >/dev/null 2>&1 && ! minikube status >/dev/null 2>&1; then
    print_result "集成安全测试" "SKIP" "Minikube 未运行"
else
    echo -e "  ${BLUE}CMD:${RESET} go test -tags integration ./test/ -run TestAttackSuite -v"
    echo -e "  ${YELLOW}注意: 此测试耗时较长 (部署 + 12 类攻击 + 清理)${RESET}"
    run_step "集成安全测试套件" "go test -tags integration ./test/ -run TestAttackSuite -v -count=1 -timeout 600s 2>&1"
fi

# ============================================================
# 汇总报告（技术化表格）
# ============================================================
TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$((TOTAL_END - TOTAL_START))

echo ""
echo -e "${CYAN}${BOLD}+============================================================+${RESET}"
echo -e "${CYAN}${BOLD}|              模拟结果汇总 (Test Summary)                  |${RESET}"
echo -e "${CYAN}${BOLD}+============================================================+${RESET}"
echo ""

# 明细表格
echo -e "  ${BOLD}测试明细 (Test Details)${RESET}"
echo -e "  +----+--------------------------------------+--------+----------+----------+------------------------------------------+"
echo -e "  | #  | 测试项 (Test Name)                   | 结果   | 耗时     | 日志行数 | 说明 (Detail)                            |"
echo -e "  +----+--------------------------------------+--------+----------+----------+------------------------------------------+"

idx=0
for r in "${RESULTS[@]}"; do
    idx=$((idx + 1))
    IFS='~' read -r status name detail duration lines <<< "$r"
    case "$status" in
        PASS) color="$GREEN" ;;
        FAIL) color="$RED" ;;
        SKIP) color="$YELLOW" ;;
        *)    color="" ;;
    esac
    # 截断长字段
    short_name="${name:0:36}"
    short_detail="${detail:0:42}"
    printf "  | %-2s | %-36s | ${color}%-6s${RESET} | %-8s | %-8s | %-40s |\n" \
        "$idx" "$short_name" "[$status]" "${duration}s" "$lines" "$short_detail"
done

echo -e "  +----+--------------------------------------+--------+----------+----------+------------------------------------------+"
echo ""

# 统计表格
echo -e "  ${BOLD}统计 (Statistics)${RESET}"
echo -e "  +--------------------------+-------------------+"
echo -e "  | 指标 (Metric)            | 值 (Value)        |"
echo -e "  +--------------------------+-------------------+"
printf "  | %-24s | %-17s |\n" "总测试项 (Total)" "$((PASS_COUNT + FAIL_COUNT + SKIP_COUNT))"
printf "  | %-24s | ${GREEN}%-17s${RESET} |\n" "通过 (Passed)" "$PASS_COUNT"
printf "  | %-24s | ${RED}%-17s${RESET} |\n" "失败 (Failed)" "$FAIL_COUNT"
printf "  | %-24s | ${YELLOW}%-17s${RESET} |\n" "跳过 (Skipped)" "$SKIP_COUNT"
printf "  | %-24s | %-17s |\n" "通过率 (Pass Rate)" "$(awk -v p=$PASS_COUNT -v f=$FAIL_COUNT -v s=$SKIP_COUNT 'BEGIN{t=p+f+s; if(t>0) printf "%.1f%%", p/t*100; else print "N/A"}')"
printf "  | %-24s | %-17s |\n" "总耗时 (Total Duration)" "${TOTAL_ELAPSED}s"
echo -e "  +--------------------------+-------------------+"
echo ""

# 失败项详情
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo -e "  ${BOLD}${RED}失败项详情 (Failed Tests)${RESET}"
    echo -e "  +--------------------------------------+------------------------------------------+"
    echo -e "  | 测试项                               | 说明                                     |"
    echo -e "  +--------------------------------------+------------------------------------------+"
    for r in "${RESULTS[@]}"; do
        IFS='~' read -r status name detail duration lines <<< "$r"
        if [[ "$status" == "FAIL" ]]; then
            short_name="${name:0:36}"
            short_detail="${detail:0:42}"
            printf "  | %-36s | %-40s |\n" "$short_name" "$short_detail"
        fi
    done
    echo -e "  +--------------------------------------+------------------------------------------+"
    echo ""
fi

# 日志文件索引
echo -e "  ${BOLD}日志文件索引 (Log Files)${RESET}"
echo -e "  +--------------------------------------+---------------------------------------------------+"
echo -e "  | 测试项                               | 日志路径                                          |"
echo -e "  +--------------------------------------+---------------------------------------------------+"
for r in "${RESULTS[@]}"; do
    IFS='~' read -r status name detail duration lines <<< "$r"
    safe_name="${name//\//_}"
    safe_name="${safe_name// /_}"
    safe_name="${safe_name//./_}"
    log_path="/tmp/kestrel-simulate-${safe_name}.log"
    short_name="${name:0:36}"
    printf "  | %-36s | %-49s |\n" "$short_name" "$log_path"
done
echo -e "  +--------------------------------------+---------------------------------------------------+"
echo ""

# 最终结论
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo -e "${RED}${BOLD}+============================================================+${RESET}"
    echo -e "${RED}${BOLD}| [FAIL] 模拟完成, $FAIL_COUNT 项失败                         |${RESET}"
    echo -e "${RED}${BOLD}+============================================================+${RESET}"
    echo -e "${DIM}排查建议: 查看上方失败项详情和日志文件索引${RESET}"
    exit 1
else
    echo -e "${GREEN}${BOLD}+============================================================+${RESET}"
    echo -e "${GREEN}${BOLD}| [PASS] 模拟完成, 全部通过                                   |${RESET}"
    echo -e "${GREEN}${BOLD}+============================================================+${RESET}"
    exit 0
fi
