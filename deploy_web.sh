#!/bin/bash
# Flexus L / ECS（Linux）网页部署脚本
# 作用：把「安鉴智能体」演示网页注册成常驻服务（开机自启、崩溃自动拉起）
# 用法：先把项目上传到服务器，然后在项目根目录执行  bash deploy_web.sh
set -e

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_USER="$(whoami)"
PORT=8080
SERVICE="logscan-web"

echo "==> 项目目录: $APP_DIR"
echo "==> 运行用户: $APP_USER"

echo "=== 1/5 安装系统依赖 ==="
sudo apt-get update -y >/dev/null 2>&1 || true
sudo apt-get install -y python3 python3-venv >/dev/null

echo "=== 2/5 创建虚拟环境并安装依赖 ==="
python3 -m venv "$APP_DIR/venv"
# shellcheck disable=SC1091
source "$APP_DIR/venv/bin/activate"
pip install --upgrade pip -q \
  -i https://repo.huaweicloud.com/repository/pypi/simple \
  --trusted-host repo.huaweicloud.com
pip install -q fastapi "uvicorn[standard]" openai python-dotenv pydantic \
  -i https://repo.huaweicloud.com/repository/pypi/simple \
  --trusted-host repo.huaweicloud.com

echo "=== 3/5 写入 .env（已存在则保留）==="
if [ ! -f "$APP_DIR/.env" ]; then
  cat > "$APP_DIR/.env" <<'EOF'
OPENAI_API_KEY=ideal@2026
OPENAI_BASE_URL=http://59.65.232.180:18000/v1
LOGSCAN_MODEL=qwen3.6-35b-a3b
LOGSCAN_DISABLE_THINKING=1
EOF
  echo "已生成 .env（使用公网可达的学院模型）"
else
  echo ".env 已存在，跳过"
fi

echo "=== 4/5 注册 systemd 常驻服务 ==="
sudo tee "/etc/systemd/system/$SERVICE.service" >/dev/null <<EOF
[Unit]
Description=LogScan Web Demo (AgentArts 安鉴智能体)
After=network.target

[Service]
Type=simple
User=$APP_USER
WorkingDirectory=$APP_DIR
Environment=PYTHONPATH=$APP_DIR/src
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/venv/bin/python -m logscan.agentarts.runtime
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable "$SERVICE" >/dev/null 2>&1
sudo systemctl restart "$SERVICE"

echo "=== 5/5 自检 ==="
sleep 4
if curl -fsS --max-time 5 "http://127.0.0.1:$PORT/health" >/dev/null; then
  PUB_IP="$(curl -s --max-time 3 ifconfig.me || echo '<公网IP>')"
  echo "✅ 部署成功"
  echo "   本机访问: http://127.0.0.1:$PORT/"
  echo "   公网访问: http://$PUB_IP:$PORT/"
  echo "   注意：还需在华为云控制台「防火墙」放行 TCP $PORT"
else
  echo "❌ 服务未正常启动，查看日志："
  echo "   sudo journalctl -u $SERVICE -n 50 --no-pager"
  exit 1
fi
