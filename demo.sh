#!/bin/bash
# 本地演示脚本：用学院模型 + examples/ 日志跑 Agent，产出可演示报告。
# 在能访问学院模型端点的环境（校园网）运行。
# 用法：bash demo.sh
set -e
cd "$(dirname "$0")"

# 激活虚拟环境（如有）
source venv/bin/activate 2>/dev/null || true

# 确保已安装
python -c "import logscan" 2>/dev/null || pip install -e ".[dev]"

echo ""
echo "=========================================="
echo "  演示1: LLM 模式 — access.log（含攻击）"
echo "=========================================="
logscan scan examples/access.log --verbose --format markdown -o report_access.md
echo "→ 报告已写入 report_access.md"

echo ""
echo "=========================================="
echo "  演示2: LLM 模式 — app.json.log"
echo "=========================================="
logscan scan examples/app.json.log --verbose --format markdown -o report_app.md
echo "→ 报告已写入 report_app.md"

echo ""
echo "=========================================="
echo "  演示3: LLM 模式 — syslog.log"
echo "=========================================="
logscan scan examples/syslog.log --verbose --format markdown -o report_syslog.md
echo "→ 报告已写入 report_syslog.md"

echo ""
echo "=========================================="
echo "  演示4: mock 模式（不调 LLM，保底）"
echo "=========================================="
logscan scan examples/access.log --mock --verbose --format markdown -o report_mock.md
echo "→ 报告已写入 report_mock.md"

echo ""
echo "全部完成。答辩时展示 report_access.md 的 trace（工具调用链）与复核状态。"