# Chatgpt 号池控制台

作者: 暮光下的少年  

感觉不错Star一下

一个用于账号池自动维护的控制台，支持：
- 面板登录与运行状态监控
- 活跃账号目标保活
- 401/周限额低账号清理
- DuckMail API Key 面板配置
- 在线修改面板登录密码

## 默认信息
- 面板地址: `http://127.0.0.1:8099`
- 默认登录密码: `admin123`

建议首次登录后在管理页点击“修改登录密码”。

## 快速启动
```bash
# Linux/macOS
cp config.example.json config.json
# Windows PowerShell
copy config.example.json config.json
python admin_panel.py --host 0.0.0.0 --port 8099
```

或 Docker：
```bash
docker compose up -d --build
```

## DuckMail Key
可在管理页面直接填写 DuckMail API Key。  
参考文档: https://www.duckmail.sbs/api-docs  
获取 API 密钥: https://domain.duckmail.sbs

## 部署文档
完整部署与排障见 `DEPLOY.md`。
