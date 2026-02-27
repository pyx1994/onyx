#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "用法: ./link_cpa_network.sh <CPA容器名>"
  exit 1
fi

CPA_CONTAINER="$1"
PANEL_CONTAINER="chatgpt_pool_panel"
NET_NAME="chatgpt_pool_net"

if ! command -v docker >/dev/null 2>&1; then
  echo "未检测到 Docker"
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -Fxq "$PANEL_CONTAINER"; then
  echo "未找到面板容器: $PANEL_CONTAINER"
  echo "先执行: docker compose up -d --build"
  exit 1
fi

if ! docker ps --format '{{.Names}}' | grep -Fxq "$CPA_CONTAINER"; then
  echo "未找到 CPA 容器: $CPA_CONTAINER"
  exit 1
fi

docker network inspect "$NET_NAME" >/dev/null 2>&1 || docker network create "$NET_NAME"

docker network connect "$NET_NAME" "$PANEL_CONTAINER" 2>/dev/null || true
docker network connect "$NET_NAME" "$CPA_CONTAINER" 2>/dev/null || true

echo "已连接网络: $NET_NAME"
echo "面板里 CPA地址 请填写: http://$CPA_CONTAINER:8317"
echo "可验证连通性:"
echo "docker exec -it $PANEL_CONTAINER python - <<'PY'"
echo "import requests; u='http://$CPA_CONTAINER:8317/v0/management/auth-files'; print(requests.get(u, timeout=5).status_code)"
echo "PY"
