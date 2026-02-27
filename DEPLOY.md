# Chatgpt 号池控制台部署说明

作者: 暮光下的少年  
GitHub: https://github.com/pyx1994

## 1. 你需要先明确的两件事
1. `CPA地址` 是面板容器去访问 CPA 服务时使用的地址，不是你本地电脑访问地址。  
2. `CPA管理密码` 和 `面板登录密码` 是两套密码。

默认值：
- `CPA地址`: `http://cli-proxy-api:8317`
- `CPA管理密码`: `admin`
- `面板登录密码`: `admin123`
- `面板端口`: `8099`

建议：首次登录后请在后台控制面板里使用“修改登录密码”按钮修改默认密码。

## 2. 通用部署（先做）
在项目目录执行：
```bash
chmod +x deploy.sh
./deploy.sh
```

常用命令：
```bash
docker compose ps
docker compose logs -f
```

## 3. 场景A：面板和 CPA 在同一台服务器，且都跑在 Docker
这是推荐方案，最稳定。

### 3.1 找到 CPA 容器名
```bash
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}"
```

### 3.2 把两个容器接入同一网络
```bash
chmod +x link_cpa_network.sh
./link_cpa_network.sh 你的CPA容器名
```

如果你的 CPA 容器名是 `cli-proxy-api`，则面板里填写：
```text
http://cli-proxy-api:8317
```

### 3.3 在面板容器内验证连通性
```bash
docker exec -it chatgpt_pool_panel python - <<'PY'
import requests
u="http://cli-proxy-api:8317/v0/management/auth-files"
try:
    r=requests.get(u, timeout=8)
    print("status:", r.status_code)
    print(r.text[:200])
except Exception as e:
    print(type(e).__name__, e)
PY
```

判断：
- `200/401/403` 表示网络已通。
- `ConnectTimeout` 表示网络不通。

## 4. 场景B：面板和 CPA 不在同一台服务器
例如：
- 面板在服务器A（Docker）
- CPA在服务器B（Docker 或裸机）

### 4.1 在 CPA 所在服务器开放端口
- 确认 CPA 监听 `0.0.0.0:8317`
- 云安全组/防火墙允许服务器A访问服务器B的 `8317`

### 4.2 面板里填写 CPA地址
填写 CPA 的“服务器B可达地址”，优先内网：
```text
http://服务器B内网IP:8317
```
或：
```text
http://你的CPA域名:8317
```

不要填写：
- `http://127.0.0.1:8317`（在容器里是容器自己）
- 宿主机公网 IP 回环地址（部分云厂商会超时）

### 4.3 在面板容器内验证连通性
```bash
docker exec -it chatgpt_pool_panel python - <<'PY'
import requests
u="http://服务器B内网IP:8317/v0/management/auth-files"
try:
    r=requests.get(u, timeout=8)
    print("status:", r.status_code)
    print(r.text[:200])
except Exception as e:
    print(type(e).__name__, e)
PY
```

## 5. 错误对照（快速定位）
- `ConnectTimeout`: 网络不通（地址、端口、路由、防火墙、容器网络）。
- `Connection refused`: 服务未监听或端口未映射。
- `401/403`: 网络已通，但 Token/权限错误。
- `Name or service not known`: 容器名或域名解析失败。

## 6. 修改面板登录密码和端口
编辑 `.env`：
```env
PANEL_PASSWORD=你的新面板密码
PANEL_PORT=8099
```

重启：
```bash
docker compose up -d --build
```

也可以在后台控制面板中使用“修改登录密码”按钮直接修改登录密码（会写入 `config.json`）。

## 7. 更新与卸载
更新：
```bash
docker compose down
docker compose up -d --build
```

停止：
```bash
docker compose down
```

清理镜像：
```bash
docker compose down --rmi local
```
