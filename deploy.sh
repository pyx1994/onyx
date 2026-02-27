#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if ! command -v docker >/dev/null 2>&1; then
  echo "未检测到 Docker，请先安装 Docker 后再执行。"
  exit 1
fi

if docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD=(docker-compose)
else
  echo "未检测到 docker compose，请先安装 docker compose。"
  exit 1
fi

mkdir -p logs
docker network create chatgpt_pool_net >/dev/null 2>&1 || true

if [ ! -f .env ]; then
  cat > .env <<'EOF'
PANEL_PASSWORD=pyx19940301
PANEL_PORT=8099
EOF
  echo "已生成 .env，按需修改 PANEL_PASSWORD / PANEL_PORT。"
fi

"${COMPOSE_CMD[@]}" up -d --build
"${COMPOSE_CMD[@]}" ps

PANEL_PORT="$(grep -E '^PANEL_PORT=' .env | cut -d= -f2- || true)"
PANEL_PORT="${PANEL_PORT:-8099}"

SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
SERVER_IP="${SERVER_IP:-<你的服务器IP>}"

echo "部署完成。"
echo "面板访问地址: http://${SERVER_IP}:${PANEL_PORT}"
