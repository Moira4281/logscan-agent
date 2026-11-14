#!/bin/bash
# AgentArts 运行时部署脚本（在鲲鹏 ECS / ARM64 Ubuntu 22.04 上执行）
# 用法：cd 到项目根目录，bash deploy.sh
set -e
cd "$(dirname "$0")"

echo "=== 1/5 创建虚拟环境 ==="
python3 -m venv venv
source venv/bin/activate

echo "=== 2/5 安装依赖 ==="
pip install agentarts-sdk -i https://repo.huaweicloud.com/repository/pypi/simple --trusted-host repo.huaweicloud.com
pip install -r requirements.txt

echo "=== 3/5 检查华为云凭证 ==="
if [ -z "$HUAWEICLOUD_SDK_AK" ] || [ -z "$HUAWEICLOUD_SDK_SK" ]; then
  echo "请先设置 AK/SK（控制台 我的凭证 → 访问密钥）："
  echo "  export HUAWEICLOUD_SDK_AK='你的AK'"
  echo "  export HUAWEICLOUD_SDK_SK='你的SK'"
  echo "然后重新运行本脚本。"
  exit 1
fi

echo "=== 4/5 配置运行时（按交互提示填写）==="
echo "  Agent name:        logscan-agent-runtime"
echo "  Region:            cn-southwest-2"
echo "  Dependency file:   requirements.txt"
echo "  SWR Organization:  回车留空（自动创建）"
echo "  SWR Repository:    回车留空（自动创建）"
agentarts configure --entrypoint app:app

echo "=== 5/5 构建镜像 + 推送 SWR + 部署运行时 ==="
agentarts launch

echo ""
echo "=== 部署完成，验证调用 ==="
agentarts invoke --agent logscan-agent-runtime \
  '{"mode":"mock","sources":[{"content":"{\"timestamp\":\"2024-01-15T10:00:00Z\",\"level\":\"WARN\",\"source_ip\":\"192.168.1.100\",\"message\":\"UNION SELECT password FROM users\"}"}]}'

echo ""
echo "如需用真实日志验证，把 examples/ 日志内容放进 sources[].content。"