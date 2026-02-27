#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import datetime as dt
import hmac
import json
import math
import re
import secrets
import subprocess
import sys
import threading
import time
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Deque, Dict, Optional
from urllib.parse import parse_qs, urlparse

from auto_pool_maintainer import get_candidates_count, load_json, pick_conf

PANEL_DEFAULT_PASSWORD = "admin123"
DEFAULT_CPA_BASE_URL = "http://cli-proxy-api:8317"
DEFAULT_CPA_TOKEN = "admin"
SESSION_COOKIE_NAME = "chatgpt_pool_session"
SESSION_TTL_SECONDS = 12 * 60 * 60
ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
LOG_TS_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \| ")
ACTIVE_FROM_CLEAN_RE = re.compile(r"清理后统计:.*candidates=(\d+)")
ACTIVE_FROM_REFILL_RE = re.compile(r"补号后统计:.*codex账号=(\d+)")
DELETE_SUMMARY_RE = re.compile(r"清理阶段汇总:.*删除成功=(\d+),\s*删除失败=(\d+)")
REFILL_SUMMARY_RE = re.compile(r"补号阶段汇总:.*收敛账号=(\d+)")
ROUND_EXIT_RE = re.compile(r"\[daemon\].*退出码=([+-]?\d+)")

LOGIN_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Chatgpt 号池控制台 - 登录</title>
  <style>
    :root {
      --bg-0: #071119;
      --bg-1: #11253a;
      --bg-2: #1a3f60;
      --panel: rgba(9, 20, 31, 0.84);
      --line: rgba(123, 171, 214, 0.32);
      --text: #e8f4ff;
      --muted: #9eb7d0;
      --accent: #55d5a8;
      --mono: "IBM Plex Mono", "JetBrains Mono", "Consolas", monospace;
      --sans: "Space Grotesk", "Manrope", "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      font-family: var(--sans);
      color: var(--text);
      background:
        radial-gradient(900px 560px at 0% 0%, #2a6ca1 0%, transparent 58%),
        radial-gradient(700px 500px at 100% 0%, #1f8f71 0%, transparent 60%),
        linear-gradient(145deg, var(--bg-0), var(--bg-1) 45%, var(--bg-2) 100%);
    }
    .card {
      width: min(430px, 92vw);
      border: 1px solid var(--line);
      background: var(--panel);
      border-radius: 16px;
      backdrop-filter: blur(8px);
      box-shadow: 0 20px 44px rgba(0, 0, 0, 0.24);
      padding: 22px;
    }
    h1 {
      margin: 0 0 8px;
      font-size: 1.35rem;
    }
    p {
      margin: 0 0 16px;
      color: var(--muted);
      font-size: 0.92rem;
    }
    label {
      font-size: 0.78rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    input {
      margin-top: 7px;
      width: 100%;
      border: 1px solid rgba(144, 188, 226, 0.35);
      background: rgba(9, 19, 29, 0.95);
      color: var(--text);
      border-radius: 12px;
      padding: 10px 12px;
      font-family: var(--mono);
      font-size: 0.95rem;
      outline: none;
    }
    input:focus { border-color: #58b9ff; }
    button {
      margin-top: 12px;
      width: 100%;
      border: 0;
      border-radius: 12px;
      padding: 10px 12px;
      font-weight: 700;
      cursor: pointer;
      color: #03211b;
      background: linear-gradient(145deg, #6be6ba, #44c9a2);
    }
    .msg {
      min-height: 18px;
      margin-top: 10px;
      font-size: 0.85rem;
      color: #ffd2d8;
    }
    .meta-line {
      margin-top: 8px;
      font-size: 0.8rem;
      color: var(--muted);
      line-height: 1.5;
    }
    .meta-line a {
      color: #8ed0ff;
      text-decoration: none;
    }
    .meta-line a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <section class="card">
    <h1>Chatgpt 号池控制台</h1>
    <p>请输入密码后进入管理页面。</p>
    <div class="meta-line">
      作者: 暮光下的少年 |
      GitHub:
      <a href="https://github.com/pyx1994" target="_blank" rel="noopener noreferrer">https://github.com/pyx1994</a>
    </div>
    <label for="pwd">登录密码</label>
    <input id="pwd" type="password" autocomplete="current-password" />
    <button id="loginBtn">登录</button>
    <div class="msg" id="msg"></div>
  </section>
  <script>
    const pwd = document.getElementById("pwd");
    const btn = document.getElementById("loginBtn");
    const msg = document.getElementById("msg");
    function detectBasePath() {
      const p = window.location.pathname || "/";
      if (p === "/" || p === "/index.html" || p === "/login") return "";
      let trimmed = p.endsWith("/") ? p.slice(0, -1) : p;
      if (trimmed.endsWith("/index.html")) trimmed = trimmed.slice(0, -11);
      if (trimmed.endsWith("/login")) trimmed = trimmed.slice(0, -6);
      return trimmed === "/" ? "" : trimmed;
    }

    const BASE_PATH = detectBasePath();

    function withBase(path) {
      const suffix = path.startsWith("/") ? path : ("/" + path);
      return (BASE_PATH || "") + suffix;
    }

    async function login() {
      const password = pwd.value || "";
      if (!password) {
        msg.textContent = "请输入密码";
        return;
      }
      btn.disabled = true;
      msg.textContent = "";
      try {
        const resp = await fetch(withBase("/api/login"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password }),
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          msg.textContent = data.message || ("登录失败: HTTP " + resp.status);
          return;
        }
        window.location.href = withBase("/");
      } catch (e) {
        msg.textContent = String(e.message || e);
      } finally {
        btn.disabled = false;
      }
    }

    btn.addEventListener("click", login);
    pwd.addEventListener("keydown", (e) => {
      if (e.key === "Enter") login();
    });
    pwd.focus();
  </script>
</body>
</html>
"""


INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Chatgpt 号池控制台</title>
  <style>
    :root {
      --bg-0: #070e15;
      --bg-1: #0d1f30;
      --bg-2: #1b3d59;
      --surface: rgba(10, 20, 32, 0.76);
      --surface-strong: rgba(7, 15, 24, 0.92);
      --line: rgba(132, 178, 217, 0.24);
      --line-soft: rgba(132, 178, 217, 0.14);
      --text: #ecf6ff;
      --muted: #a0bdd7;
      --accent: #5fe0b4;
      --accent-2: #67c0ff;
      --warn: #ffbe6b;
      --danger: #ff7381;
      --shadow: 0 18px 42px rgba(0, 0, 0, 0.28);
      --mono: "IBM Plex Mono", "JetBrains Mono", "Consolas", monospace;
      --sans: "Space Grotesk", "Manrope", "Segoe UI", sans-serif;
      --radius: 18px;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      font-family: var(--sans);
      background:
        radial-gradient(950px 620px at -10% -10%, #2a6fa3 0%, transparent 55%),
        radial-gradient(780px 560px at 110% -20%, #1f8f70 0%, transparent 55%),
        linear-gradient(145deg, var(--bg-0), var(--bg-1) 45%, var(--bg-2) 100%);
      overflow-x: hidden;
    }

    .halo {
      position: fixed;
      width: 340px;
      height: 340px;
      border-radius: 999px;
      filter: blur(70px);
      opacity: 0.26;
      pointer-events: none;
      z-index: 0;
      animation: drift 10s ease-in-out infinite alternate;
    }
    .halo.a { top: 8%; left: -2%; background: #45dcb0; }
    .halo.b { top: 60%; right: -4%; background: #62bbff; animation-delay: 1.8s; }

    @keyframes drift {
      from { transform: translateY(-8px) scale(1); }
      to { transform: translateY(10px) scale(1.08); }
    }

    .wrap {
      position: relative;
      z-index: 1;
      width: min(1160px, 94vw);
      margin: 20px auto 26px;
      display: grid;
      grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
      gap: 12px;
      align-items: stretch;
    }

    .hero {
      grid-column: 1 / -1;
      padding: 18px 20px;
      border-radius: var(--radius);
      border: 1px solid var(--line);
      background: linear-gradient(160deg, rgba(14, 32, 49, 0.88), rgba(9, 18, 28, 0.76));
      backdrop-filter: blur(8px);
      box-shadow: var(--shadow);
      animation: intro 420ms ease-out;
    }

    .hero h1 {
      margin: 0 0 6px;
      font-size: clamp(1.24rem, 2.1vw, 1.85rem);
      letter-spacing: 0.015em;
    }

    .hero p {
      margin: 0;
      color: var(--muted);
      font-size: 0.92rem;
    }
    .hero .meta-line {
      margin-top: 8px;
      font-size: 0.82rem;
      color: var(--muted);
      line-height: 1.45;
    }
    .hero .meta-line a {
      color: #9ad7ff;
      text-decoration: none;
    }
    .hero .meta-line a:hover { text-decoration: underline; }

    @keyframes intro {
      from { transform: translateY(10px); opacity: 0; }
      to { transform: translateY(0); opacity: 1; }
    }

    .panel {
      border-radius: var(--radius);
      border: 1px solid var(--line);
      background: var(--surface);
      backdrop-filter: blur(9px);
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.22);
    }

    .controls {
      grid-column: 1 / 2;
      padding: 16px;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      align-items: end;
      align-content: start;
      height: 100%;
    }

    .field {
      display: grid;
      gap: 6px;
      grid-column: span 1;
    }
    .field.wide { grid-column: span 1; }
    .field.narrow { grid-column: span 1; }
    .field.full { grid-column: 1 / -1; }
    .field.secret input { letter-spacing: 0.04em; }

    .field label {
      font-size: 0.74rem;
      letter-spacing: 0.06em;
      color: var(--muted);
      text-transform: uppercase;
      font-weight: 700;
    }

    input {
      width: 100%;
      padding: 11px 12px;
      border-radius: 11px;
      border: 1px solid rgba(153, 196, 233, 0.3);
      background: rgba(7, 17, 28, 0.92);
      color: var(--text);
      font-family: var(--mono);
      font-size: 0.92rem;
      outline: none;
      transition: border-color .15s ease, box-shadow .15s ease;
    }
    input::placeholder { color: rgba(166, 192, 215, 0.48); }
    input:focus {
      border-color: var(--accent-2);
      box-shadow: 0 0 0 3px rgba(103, 192, 255, 0.16);
    }

    .btns {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
      grid-column: 1 / -1;
      padding-top: 2px;
    }
    .btns button { min-height: 40px; }

    button {
      border: 0;
      border-radius: 11px;
      padding: 10px 14px;
      font-weight: 700;
      cursor: pointer;
      transition: transform 120ms ease, filter 120ms ease, box-shadow 120ms ease;
      color: #0a1d31;
      background: linear-gradient(145deg, #8ccfff, #67bff8);
      min-width: 0;
      width: 100%;
      box-shadow: 0 6px 16px rgba(0, 0, 0, 0.18);
    }
    button:hover {
      transform: translateY(-1px);
      filter: brightness(1.05);
      box-shadow: 0 9px 20px rgba(0, 0, 0, 0.24);
    }
    button:disabled { opacity: 0.45; cursor: not-allowed; transform: none; }
    .accent { color: #03221b; background: linear-gradient(145deg, #74ecc0, #52d9ad); }
    .warn { color: #311500; background: linear-gradient(145deg, #ffcd89, #f6ac54); }
    .subtle { color: #06213a; background: linear-gradient(145deg, #9ad7ff, #75c2fd); }
    .ghost {
      color: #cae8ff;
      background: rgba(12, 28, 45, 0.92);
      border: 1px solid rgba(147, 190, 227, 0.34);
      box-shadow: none;
    }

    .meta {
      grid-column: 2 / 3;
      padding: 12px;
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
      align-content: start;
      grid-auto-rows: minmax(68px, auto);
      height: 100%;
    }

    .item {
      padding: 10px 11px;
      border: 1px solid var(--line-soft);
      border-radius: 12px;
      background: linear-gradient(160deg, rgba(11, 24, 37, 0.76), rgba(8, 16, 25, 0.48));
      min-height: 64px;
    }

    .item b {
      display: block;
      font-size: 0.76rem;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 3px;
    }

    .item span {
      font-family: var(--mono);
      font-size: 0.9rem;
      word-break: break-word;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-weight: 700;
      padding: 7px 11px;
      border-radius: 999px;
      border: 1px solid rgba(120, 228, 187, 0.44);
      background: rgba(83, 214, 168, 0.15);
      color: #b8ffe0;
    }
    .badge.offline {
      border-color: rgba(255, 165, 130, 0.48);
      background: rgba(255, 111, 122, 0.15);
      color: #ffd3d6;
    }

    .logs {
      grid-column: 1 / -1;
      padding: 12px;
      background: var(--surface-strong);
    }

    .logs-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
      gap: 10px;
    }

    .logs-head h2 {
      margin: 0;
      font-size: 1.02rem;
      font-weight: 700;
      letter-spacing: 0.02em;
    }

    pre {
      margin: 0;
      height: min(56vh, 620px);
      overflow: auto;
      border-radius: 12px;
      border: 1px solid rgba(124, 170, 212, 0.2);
      background: #08121a;
      color: #d7edff;
      font: 12.5px/1.45 var(--mono);
      padding: 12px;
      white-space: pre-wrap;
      word-break: break-word;
    }

    .note {
      font-size: 0.84rem;
      color: var(--muted);
      min-height: 18px;
    }

    .hint {
      margin-top: 4px;
      font-size: 0.78rem;
      color: var(--muted);
      line-height: 1.45;
    }

    .hint a {
      color: #9ad7ff;
      text-decoration: none;
    }

    .hint a:hover { text-decoration: underline; }

    .inline-btn {
      margin-top: 8px;
      width: auto;
      min-width: 170px;
    }

    @media (max-width: 980px) {
      .wrap { grid-template-columns: 1fr; }
      .controls { grid-column: 1 / -1; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px; }
      .meta { grid-column: 1 / -1; }
      .field, .field.wide, .field.narrow { grid-column: span 1; }
      .field.full { grid-column: 1 / -1; }
      .btns { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .meta { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }

    @media (max-width: 560px) {
      .wrap { width: min(96vw, 1120px); margin: 14px auto; }
      .hero { padding: 15px 14px; }
      .controls { padding: 12px; grid-template-columns: 1fr; }
      .field, .field.wide, .field.narrow, .field.full { grid-column: 1 / -1; }
      .btns { grid-template-columns: 1fr; }
      .meta { grid-template-columns: 1fr; }
      pre { height: 48vh; }
    }
  </style>
</head>
<body>
  <div class="halo a"></div>
  <div class="halo b"></div>
  <main class="wrap">
    <section class="hero">
      <h1>Chatgpt 号池控制台</h1>
      <p>按活跃账号目标自动计算补号缺口，支持启动、停止和实时日志查看。</p>
      <div class="meta-line">
        作者: 暮光下的少年 |
        GitHub:
        <a href="https://github.com/pyx1994" target="_blank" rel="noopener noreferrer">https://github.com/pyx1994</a>
      </div>
    </section>

    <section class="panel controls">
      <div class="field narrow">
        <label for="targetActive">维持活跃账号数</label>
        <input id="targetActive" type="number" min="1" step="1" value="800" />
      </div>
      <div class="field wide">
        <label for="cpaBaseUrl">CPA地址</label>
        <input id="cpaBaseUrl" type="text" placeholder="http://cli-proxy-api:8317" value="http://cli-proxy-api:8317" />
      </div>
      <div class="field wide secret">
        <label for="cpaToken">管理密码</label>
        <input id="cpaToken" type="password" placeholder="填写管理密码/Token" value="admin" />
      </div>
      <div class="field narrow">
        <label for="weeklyThreshold">周限额删除阈值(%)</label>
        <input id="weeklyThreshold" type="number" min="0" max="100" step="0.1" value="10" />
      </div>
      <div class="field full secret">
        <label for="duckmailBearer">DuckMail API Key</label>
        <input id="duckmailBearer" type="password" placeholder="填写 DuckMail API Key" value="" />
        <span class="hint">
          DuckMail 文档：
          <a href="https://www.duckmail.sbs/api-docs" target="_blank" rel="noopener noreferrer">https://www.duckmail.sbs/api-docs</a>。
          您可以访问
          <a href="https://domain.duckmail.sbs" target="_blank" rel="noopener noreferrer">https://domain.duckmail.sbs</a>
          获取您的 API 密钥。
        </span>
      </div>
      <div class="field full secret">
        <label for="panelPwd">面板登录密码</label>
        <input id="panelPwd" type="password" placeholder="新登录密码（至少6位）" value="" />
        <button id="panelPwdBtn" class="subtle inline-btn">修改登录密码</button>
        <span class="hint">默认登录密码为 <code>admin123</code>，建议修改后使用。</span>
      </div>
      <div class="btns">
        <button id="saveBtn" class="ghost">保存配置</button>
        <button id="startBtn" class="accent">开启自动补号</button>
        <button id="stopBtn" class="warn">关闭自动补号</button>
        <button id="refreshBtn" class="subtle">立即刷新</button>
        <button id="clearBtn" class="ghost">清空面板日志</button>
        <button id="logoutBtn" class="subtle">退出登录</button>
      </div>
      <div class="field full">
        <span class="note" id="formMsg"></span>
      </div>
    </section>

    <section class="panel meta">
      <div class="item"><b>状态</b><span id="statusBadge" class="badge offline">已停止</span></div>
      <div class="item"><b>PID</b><span id="pid">-</span></div>
      <div class="item"><b>目标活跃</b><span id="targetMeta">-</span></div>
      <div class="item"><b>当前活跃</b><span id="activeMeta">-</span></div>
      <div class="item"><b>本次补号数</b><span id="refillMeta">-</span></div>
      <div class="item"><b>周限额阈值</b><span id="weeklyMeta">-</span></div>
      <div class="item"><b>启动时间</b><span id="startedAt">-</span></div>
      <div class="item"><b>运行时长</b><span id="uptime">-</span></div>
      <div class="item"><b>最近退出码</b><span id="lastExit">-</span></div>
      <div class="item"><b>最近错误</b><span id="lastError">-</span></div>
    </section>

    <section class="panel logs">
      <div class="logs-head">
        <h2>实时日志</h2>
        <span class="note" id="logMeta">0 行</span>
      </div>
      <pre id="logBox"></pre>
    </section>
  </main>

  <script>
    const el = {
      targetActive: document.getElementById("targetActive"),
      cpaBaseUrl: document.getElementById("cpaBaseUrl"),
      cpaToken: document.getElementById("cpaToken"),
      weeklyThreshold: document.getElementById("weeklyThreshold"),
      duckmailBearer: document.getElementById("duckmailBearer"),
      panelPwd: document.getElementById("panelPwd"),
      panelPwdBtn: document.getElementById("panelPwdBtn"),
      saveBtn: document.getElementById("saveBtn"),
      startBtn: document.getElementById("startBtn"),
      stopBtn: document.getElementById("stopBtn"),
      refreshBtn: document.getElementById("refreshBtn"),
      logoutBtn: document.getElementById("logoutBtn"),
      clearBtn: document.getElementById("clearBtn"),
      formMsg: document.getElementById("formMsg"),
      statusBadge: document.getElementById("statusBadge"),
      pid: document.getElementById("pid"),
      targetMeta: document.getElementById("targetMeta"),
      activeMeta: document.getElementById("activeMeta"),
      refillMeta: document.getElementById("refillMeta"),
      weeklyMeta: document.getElementById("weeklyMeta"),
      startedAt: document.getElementById("startedAt"),
      uptime: document.getElementById("uptime"),
      lastExit: document.getElementById("lastExit"),
      lastError: document.getElementById("lastError"),
      logBox: document.getElementById("logBox"),
      logMeta: document.getElementById("logMeta"),
    };

    function detectBasePath() {
      const p = window.location.pathname || "/";
      if (p === "/" || p === "/index.html" || p === "/login") return "";
      let trimmed = p.endsWith("/") ? p.slice(0, -1) : p;
      if (trimmed.endsWith("/index.html")) trimmed = trimmed.slice(0, -11);
      if (trimmed.endsWith("/login")) trimmed = trimmed.slice(0, -6);
      return trimmed === "/" ? "" : trimmed;
    }

    const BASE_PATH = detectBasePath();

    function withBase(path) {
      const suffix = path.startsWith("/") ? path : ("/" + path);
      return (BASE_PATH || "") + suffix;
    }
    const cachedTarget = Number.parseInt(window.localStorage.getItem("pool_target_active") || "", 10);
    if (Number.isFinite(cachedTarget) && cachedTarget > 0) {
      el.targetActive.value = cachedTarget;
    }
    let currentEmailProvider = "cloudflare";

    async function request(path, method = "GET", payload = null) {
      const opt = { method, headers: {} };
      if (payload !== null) {
        opt.headers["Content-Type"] = "application/json";
        opt.body = JSON.stringify(payload);
      }
      const controller = new AbortController();
      const timer = window.setTimeout(() => controller.abort(), 15000);
      opt.signal = controller.signal;
      let resp;
      try {
        resp = await fetch(withBase(path), opt);
      } catch (err) {
        if (err && err.name === "AbortError") {
          throw new Error("请求超时，请检查反向代理和服务状态");
        }
        throw new Error("请求失败: " + String((err && err.message) || err));
      } finally {
        window.clearTimeout(timer);
      }
      const data = await resp.json().catch(() => ({}));
      if (resp.status === 401) {
        window.location.href = withBase("/");
        throw new Error("未登录或登录已过期");
      }
      if (!resp.ok) {
        const msg = data && data.message ? data.message : ("HTTP " + resp.status);
        throw new Error(msg);
      }
      return data;
    }

    function applyStatus(s) {
      const running = !!s.running;
      el.statusBadge.textContent = running ? "运行中" : "已停止";
      el.statusBadge.className = running ? "badge" : "badge offline";
      el.pid.textContent = s.pid ?? "-";
      el.targetMeta.textContent = s.target_active ?? "-";
      if (s.target_active != null && document.activeElement !== el.targetActive) {
        el.targetActive.value = s.target_active;
        window.localStorage.setItem("pool_target_active", String(s.target_active));
      }
      if (s.current_active_count != null) {
        el.activeMeta.textContent = s.current_active_count;
      }
      el.refillMeta.textContent = s.refill_tokens ?? "-";
      el.weeklyMeta.textContent = s.min_weekly_remaining_percent != null ? (s.min_weekly_remaining_percent + "%") : "-";
      if (s.min_weekly_remaining_percent != null) {
        el.weeklyThreshold.value = s.min_weekly_remaining_percent;
      }
      el.startedAt.textContent = s.started_at ?? "-";
      el.uptime.textContent = s.uptime_sec != null ? (s.uptime_sec + "s") : "-";
      if (s.last_exit_code != null) {
        el.lastExit.textContent = s.last_exit_code;
      }
      el.lastError.textContent = s.last_error || "-";
      el.startBtn.disabled = running;
      el.stopBtn.disabled = !running;
    }

    function cleanLogLine(line) {
      return String(line || "")
        .replace(/\\x1b\\[[0-9;?]*[ -/]*[@-~]/g, "")
        .replace(/\\uFFFD/g, "")
        .replace(/[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]/g, "");
    }

    function parseMetricsFromLogs(lines) {
      const result = { currentActive: null, lastExit: null, deletedOk: null, deletedFail: null };
      for (const line of (lines || [])) {
        let m = line.match(/清理后统计:.*candidates=(\\d+)/);
        if (m) result.currentActive = Number.parseInt(m[1], 10);

        m = line.match(/补号后统计:.*codex账号=(\\d+)/);
        if (m) result.currentActive = Number.parseInt(m[1], 10);

        m = line.match(/清理阶段汇总:.*删除成功=(\\d+),\\s*删除失败=(\\d+)/);
        if (m) {
          result.deletedOk = Number.parseInt(m[1], 10);
          result.deletedFail = Number.parseInt(m[2], 10);
        }

        m = line.match(/\\[daemon\\].*退出码=([+-]?\\d+)/);
        if (m) result.lastExit = Number.parseInt(m[1], 10);
      }
      return result;
    }

    function applyLogs(lines) {
      const atBottom = Math.abs(el.logBox.scrollHeight - el.logBox.scrollTop - el.logBox.clientHeight) < 20;
      const cleaned = (lines || []).map(cleanLogLine).filter(Boolean);
      el.logBox.textContent = cleaned.join("\\n");
      el.logMeta.textContent = cleaned.length + " 行";

      const m = parseMetricsFromLogs(cleaned);
      if (m.currentActive != null) {
        el.activeMeta.textContent = m.currentActive;
      }
      if (m.lastExit != null) {
        if (m.deletedOk != null || m.deletedFail != null) {
          const ok = m.deletedOk != null ? m.deletedOk : 0;
          const fail = m.deletedFail != null ? m.deletedFail : 0;
          el.lastExit.textContent = m.lastExit + " (删" + ok + "/" + fail + ")";
        } else {
          el.lastExit.textContent = m.lastExit;
        }
      }

      if (atBottom) {
        el.logBox.scrollTop = el.logBox.scrollHeight;
      }
    }

    async function refreshConfig() {
      const data = await request("/api/config");
      el.cpaBaseUrl.value = data.clean_base_url || "http://cli-proxy-api:8317";
      el.cpaToken.value = data.clean_token || "admin";
      el.duckmailBearer.value = data.duckmail_bearer || "";
      currentEmailProvider = String(data.email_provider || "cloudflare").toLowerCase();
      if (data.target_active != null && document.activeElement !== el.targetActive) {
        el.targetActive.value = data.target_active;
        window.localStorage.setItem("pool_target_active", String(data.target_active));
      }
      if (data.min_weekly_remaining_percent != null) {
        el.weeklyThreshold.value = data.min_weekly_remaining_percent;
      }
    }

    async function refreshStatus() {
      const data = await request("/api/status");
      applyStatus(data);
    }

    async function refreshLogs() {
      const data = await request("/api/logs?lines=500");
      applyLogs(data.lines || []);
    }

    async function refreshAll() {
      try {
        await Promise.all([refreshStatus(), refreshLogs()]);
      } catch (err) {
        el.lastError.textContent = String(err.message || err);
      }
    }

    el.startBtn.addEventListener("click", async () => {
      const targetActive = Number.parseInt(el.targetActive.value, 10);
      const cleanBaseUrl = (el.cpaBaseUrl.value || "").trim();
      const cleanToken = (el.cpaToken.value || "").trim();
      const duckmailBearer = (el.duckmailBearer.value || "").trim();
      const weeklyThreshold = Number.parseFloat(el.weeklyThreshold.value);
      if (!Number.isFinite(targetActive) || targetActive < 1) {
        alert("维持活跃账号数必须 >= 1");
        return;
      }
      if (!cleanBaseUrl) {
        alert("请填写 CPA地址");
        return;
      }
      if (!cleanToken) {
        alert("请填写管理密码");
        return;
      }
      if (currentEmailProvider === "duckmail" && !duckmailBearer) {
        alert("请填写 DuckMail API Key");
        return;
      }
      if (!Number.isFinite(weeklyThreshold) || weeklyThreshold < 0 || weeklyThreshold > 100) {
        alert("周限额删除阈值必须在 0 到 100 之间");
        return;
      }
      window.localStorage.setItem("pool_target_active", String(targetActive));
      el.startBtn.disabled = true;
      el.formMsg.textContent = "";
      try {
        const resp = await request("/api/start", "POST", {
          target_active: targetActive,
          min_weekly_remaining_percent: weeklyThreshold,
          clean_base_url: cleanBaseUrl,
          clean_token: cleanToken,
          duckmail_bearer: duckmailBearer,
        });
        el.formMsg.textContent = resp.message || "补号任务已启动";
        await refreshConfig().catch(() => {});
        await refreshAll();
      } catch (err) {
        alert(err.message || String(err));
      } finally {
        await refreshStatus().catch(() => {});
      }
    });

    el.saveBtn.addEventListener("click", async () => {
      const targetActive = Number.parseInt(el.targetActive.value, 10);
      const cleanBaseUrl = (el.cpaBaseUrl.value || "").trim();
      const cleanToken = (el.cpaToken.value || "").trim();
      const duckmailBearer = (el.duckmailBearer.value || "").trim();
      const weeklyThreshold = Number.parseFloat(el.weeklyThreshold.value);
      if (!Number.isFinite(targetActive) || targetActive < 1) {
        alert("维持活跃账号数必须 >= 1");
        return;
      }
      if (!cleanBaseUrl) {
        alert("请填写 CPA地址");
        return;
      }
      if (!cleanToken) {
        alert("请填写管理密码");
        return;
      }
      if (currentEmailProvider === "duckmail" && !duckmailBearer) {
        alert("请填写 DuckMail API Key");
        return;
      }
      if (!Number.isFinite(weeklyThreshold) || weeklyThreshold < 0 || weeklyThreshold > 100) {
        alert("周限额删除阈值必须在 0 到 100 之间");
        return;
      }
      window.localStorage.setItem("pool_target_active", String(targetActive));
      el.saveBtn.disabled = true;
      el.formMsg.textContent = "保存中...";
      try {
        const resp = await request("/api/config", "POST", {
          target_active: targetActive,
          clean_base_url: cleanBaseUrl,
          clean_token: cleanToken,
          duckmail_bearer: duckmailBearer,
          min_weekly_remaining_percent: weeklyThreshold,
        });
        el.formMsg.textContent = resp.message || "配置已保存";
        await refreshConfig();
        await refreshStatus();
      } catch (err) {
        const msg = err.message || String(err);
        el.formMsg.textContent = "保存失败: " + msg;
        alert(msg);
      } finally {
        el.saveBtn.disabled = false;
      }
    });

    el.panelPwdBtn.addEventListener("click", async () => {
      const newPassword = (el.panelPwd.value || "").trim();
      if (newPassword.length < 6) {
        alert("新登录密码长度至少 6 位");
        return;
      }
      el.panelPwdBtn.disabled = true;
      try {
        const resp = await request("/api/panel_password", "POST", {
          new_password: newPassword,
        });
        el.formMsg.textContent = resp.message || "登录密码已更新";
        el.panelPwd.value = "";
      } catch (err) {
        const msg = err.message || String(err);
        el.formMsg.textContent = "修改登录密码失败: " + msg;
        alert(msg);
      } finally {
        el.panelPwdBtn.disabled = false;
      }
    });

    el.stopBtn.addEventListener("click", async () => {
      el.stopBtn.disabled = true;
      try {
        await request("/api/stop", "POST", {});
        await refreshAll();
      } catch (err) {
        alert(err.message || String(err));
      } finally {
        await refreshStatus().catch(() => {});
      }
    });

    el.refreshBtn.addEventListener("click", async () => {
      el.refreshBtn.disabled = true;
      try {
        await refreshAll();
      } finally {
        el.refreshBtn.disabled = false;
      }
    });

    el.logoutBtn.addEventListener("click", async () => {
      try {
        await request("/api/logout", "POST", {});
      } catch (_) {}
      window.location.href = withBase("/");
    });

    el.clearBtn.addEventListener("click", async () => {
      try {
        await request("/api/clear_logs", "POST", {});
        await refreshLogs();
      } catch (err) {
        alert(err.message || String(err));
      }
    });

    refreshConfig().catch((err) => {
      el.lastError.textContent = String(err.message || err);
    });
    refreshAll();
    setInterval(refreshAll, 2000);
  </script>
</body>
</html>
"""


def now_iso() -> str:
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def fmt_time(epoch: Optional[float]) -> Optional[str]:
    if epoch is None:
        return None
    return dt.datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")


def sanitize_log_line(text: str) -> str:
    if not text:
        return ""
    s = ANSI_ESCAPE_RE.sub("", text)
    out_chars = []
    for ch in s:
        code = ord(ch)
        if ch in ("\t",):
            out_chars.append(ch)
            continue
        if code < 32 or code == 127:
            continue
        if ch == "\ufffd":
            continue
        out_chars.append(ch)
    return "".join(out_chars).strip()


class RefillController:
    def __init__(self, base_dir: Path, config_path: Path, max_log_lines: int = 4000):
        self.base_dir = base_dir
        self.default_config_path = config_path
        self.max_log_lines = max(200, int(max_log_lines))

        self.lock = threading.Lock()
        self.logs: Deque[str] = deque(maxlen=self.max_log_lines)
        self.proc: Optional[subprocess.Popen[str]] = None
        self.started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None
        self.last_exit_code: Optional[int] = None
        self.last_error: str = ""
        self.target_active: Optional[int] = None
        self.current_active_count: Optional[int] = None
        self.refill_tokens: Optional[int] = None
        self.min_weekly_remaining_percent: Optional[float] = None
        self.last_deleted_ok: Optional[int] = None
        self.last_deleted_fail: Optional[int] = None
        self.current_config_path: str = str(self.default_config_path)

        try:
            conf = load_json(self.default_config_path.resolve())
            threshold = float(
                pick_conf(conf, "clean", "min_weekly_remaining_percent", "weekly_remaining_min_percent", default=10) or 10
            )
            if threshold < 0:
                threshold = 0.0
            if threshold > 100:
                threshold = 100.0
            self.min_weekly_remaining_percent = round(threshold, 2)
        except Exception:
            self.min_weekly_remaining_percent = 10.0

    def append_log(self, line: str) -> None:
        text = str(line or "").strip()
        if not text:
            return
        entry = text if LOG_TS_PREFIX_RE.match(text) else f"{now_iso()} | {text}"
        with self.lock:
            self.logs.append(entry)

    def read_logs(self, lines: int) -> list[str]:
        limit = max(1, min(int(lines), self.max_log_lines))
        with self.lock:
            return list(self.logs)[-limit:]

    def clear_logs(self) -> None:
        with self.lock:
            self.logs.clear()

    def status(self) -> Dict[str, Any]:
        with self.lock:
            running = self.proc is not None and self.proc.poll() is None
            pid = self.proc.pid if running and self.proc else None
            uptime_sec = int(time.time() - self.started_at) if running and self.started_at else None
            return {
                "running": running,
                "pid": pid,
                "target_active": self.target_active,
                "current_active_count": self.current_active_count,
                "refill_tokens": self.refill_tokens,
                "min_weekly_remaining_percent": self.min_weekly_remaining_percent,
                "last_deleted_ok": self.last_deleted_ok,
                "last_deleted_fail": self.last_deleted_fail,
                "config_path": self.current_config_path,
                "started_at": fmt_time(self.started_at),
                "stopped_at": fmt_time(self.stopped_at),
                "uptime_sec": uptime_sec,
                "last_exit_code": self.last_exit_code,
                "last_error": self.last_error,
            }

    def _update_runtime_metrics_from_log(self, line: str) -> None:
        text = str(line or "")
        m = ACTIVE_FROM_CLEAN_RE.search(text)
        if m:
            try:
                self.current_active_count = int(m.group(1))
            except Exception:
                pass
        m = ACTIVE_FROM_REFILL_RE.search(text)
        if m:
            try:
                self.current_active_count = int(m.group(1))
            except Exception:
                pass
        m = DELETE_SUMMARY_RE.search(text)
        if m:
            try:
                deleted_ok = int(m.group(1))
                deleted_fail = int(m.group(2))
                self.last_deleted_ok = deleted_ok
                self.last_deleted_fail = deleted_fail
                if self.current_active_count is not None and deleted_ok > 0:
                    # Quick UI feedback: reflect successful deletions immediately.
                    self.current_active_count = max(0, int(self.current_active_count) - deleted_ok)
            except Exception:
                pass
        m = REFILL_SUMMARY_RE.search(text)
        if m:
            try:
                synced = int(m.group(1))
                if self.current_active_count is not None and synced > 0:
                    # Provisional increase; final value will be corrected by 补号后统计.
                    self.current_active_count = max(0, int(self.current_active_count) + synced)
            except Exception:
                pass
        m = ROUND_EXIT_RE.search(text)
        if m:
            try:
                self.last_exit_code = int(m.group(1))
            except Exception:
                pass

    def _resolve_config_path(self, config_path: Optional[str]) -> Path:
        raw = (config_path or "").strip()
        if not raw:
            return self.default_config_path.resolve()
        p = Path(raw)
        if not p.is_absolute():
            p = (self.base_dir / p).resolve()
        return p

    def _load_config(self, cfg: Path) -> Dict[str, Any]:
        return load_json(cfg)

    def _save_config(self, cfg: Path, conf: Dict[str, Any]) -> None:
        with cfg.open("w", encoding="utf-8") as f:
            json.dump(conf, f, ensure_ascii=False, indent=2)

    def get_config(self, config_path: Optional[str] = None) -> tuple[bool, int, Dict[str, Any]]:
        cfg = self._resolve_config_path(config_path)
        if not cfg.exists():
            return False, HTTPStatus.BAD_REQUEST, {"message": f"配置文件不存在: {cfg}"}
        try:
            conf = self._load_config(cfg)
            clean_base_url = str(pick_conf(conf, "clean", "base_url", default=DEFAULT_CPA_BASE_URL) or "")
            clean_token = str(pick_conf(conf, "clean", "token", "cpa_password", default=DEFAULT_CPA_TOKEN) or "")
            duckmail_bearer = str(
                pick_conf(conf, "email", "duckmail_bearer", default=conf.get("duckmail_bearer", "")) or ""
            )
            email_provider = str(pick_conf(conf, "email", "provider", default="cloudflare") or "cloudflare").lower()
            threshold = float(
                pick_conf(conf, "clean", "min_weekly_remaining_percent", "weekly_remaining_min_percent", default=10)
                or 10
            )
            if not math.isfinite(threshold):
                threshold = 10.0
            if threshold < 0:
                threshold = 0.0
            if threshold > 100:
                threshold = 100.0
            target_active = pick_conf(conf, "maintainer", "min_candidates", default=None)
            if target_active is not None:
                try:
                    target_active = int(target_active)
                except Exception:
                    target_active = None
            return True, HTTPStatus.OK, {
                "clean_base_url": clean_base_url,
                "clean_token": clean_token,
                "duckmail_bearer": duckmail_bearer,
                "email_provider": email_provider,
                "min_weekly_remaining_percent": round(threshold, 2),
                "target_active": target_active,
                "config_path": str(cfg),
            }
        except Exception as e:
            return False, HTTPStatus.BAD_REQUEST, {"message": f"读取配置失败: {e}"}

    def save_config(
        self,
        *,
        target_active: Optional[int],
        clean_base_url: str,
        clean_token: str,
        duckmail_bearer: Optional[str],
        min_weekly_remaining_percent: float,
        config_path: Optional[str] = None,
    ) -> tuple[bool, int, str]:
        cfg = self._resolve_config_path(config_path)
        if not cfg.exists():
            return False, HTTPStatus.BAD_REQUEST, f"配置文件不存在: {cfg}"

        base_url = str(clean_base_url or "").strip()
        token = str(clean_token or "").strip()
        if not base_url:
            return False, HTTPStatus.BAD_REQUEST, "clean.base_url 不能为空"
        if not token:
            return False, HTTPStatus.BAD_REQUEST, "clean.token 不能为空"
        try:
            threshold = float(min_weekly_remaining_percent)
        except Exception:
            return False, HTTPStatus.BAD_REQUEST, "min_weekly_remaining_percent 必须是数字"
        if (not math.isfinite(threshold)) or threshold < 0 or threshold > 100:
            return False, HTTPStatus.BAD_REQUEST, "min_weekly_remaining_percent 必须在 0~100 之间"
        if target_active is not None:
            try:
                target_active = int(target_active)
            except Exception:
                return False, HTTPStatus.BAD_REQUEST, "target_active 必须是整数"
            if target_active <= 0:
                return False, HTTPStatus.BAD_REQUEST, "target_active 必须大于 0"

        try:
            conf = self._load_config(cfg)
            clean_cfg = conf.get("clean")
            if not isinstance(clean_cfg, dict):
                clean_cfg = {}
                conf["clean"] = clean_cfg
            clean_cfg["base_url"] = base_url
            clean_cfg["token"] = token
            clean_cfg["min_weekly_remaining_percent"] = round(threshold, 2)
            if duckmail_bearer is not None:
                email_cfg = conf.get("email")
                if not isinstance(email_cfg, dict):
                    email_cfg = {}
                    conf["email"] = email_cfg
                bearer_val = str(duckmail_bearer).strip()
                conf["duckmail_bearer"] = bearer_val
                email_cfg["duckmail_bearer"] = bearer_val
                if bearer_val:
                    email_cfg["provider"] = "duckmail"
            if target_active is not None:
                maintain_cfg = conf.get("maintainer")
                if not isinstance(maintain_cfg, dict):
                    maintain_cfg = {}
                    conf["maintainer"] = maintain_cfg
                maintain_cfg["min_candidates"] = int(target_active)
                self.target_active = int(target_active)
            self._save_config(cfg, conf)
            self.min_weekly_remaining_percent = round(threshold, 2)
            self.current_config_path = str(cfg)
            return True, HTTPStatus.OK, "配置已保存"
        except Exception as e:
            return False, HTTPStatus.BAD_REQUEST, f"保存配置失败: {e}"

    def save_panel_password(
        self,
        *,
        new_password: str,
        config_path: Optional[str] = None,
    ) -> tuple[bool, int, str]:
        cfg = self._resolve_config_path(config_path)
        if not cfg.exists():
            return False, HTTPStatus.BAD_REQUEST, f"配置文件不存在: {cfg}"

        pwd = str(new_password or "").strip()
        if len(pwd) < 6:
            return False, HTTPStatus.BAD_REQUEST, "新登录密码长度至少 6 位"

        try:
            conf = self._load_config(cfg)
            conf["panel_password"] = pwd
            panel_cfg = conf.get("panel")
            if not isinstance(panel_cfg, dict):
                panel_cfg = {}
                conf["panel"] = panel_cfg
            panel_cfg["password"] = pwd
            self._save_config(cfg, conf)
            self.current_config_path = str(cfg)
            return True, HTTPStatus.OK, "登录密码已更新"
        except Exception as e:
            return False, HTTPStatus.BAD_REQUEST, f"保存登录密码失败: {e}"

    def start(
        self,
        target_active: int,
        min_weekly_remaining_percent: Optional[float],
        clean_base_url: Optional[str] = None,
        clean_token: Optional[str] = None,
        duckmail_bearer: Optional[str] = None,
        config_path: Optional[str] = None,
    ) -> tuple[bool, int, str]:
        if target_active <= 0:
            return False, HTTPStatus.BAD_REQUEST, "target_active 必须大于 0"

        cfg = self._resolve_config_path(config_path)
        if not cfg.exists():
            return False, HTTPStatus.BAD_REQUEST, f"配置文件不存在: {cfg}"

        runner = (self.base_dir / "daemon_runner.py").resolve()
        if not runner.exists():
            return False, HTTPStatus.INTERNAL_SERVER_ERROR, f"守护运行器不存在: {runner}"

        initial_candidates: Optional[int] = None
        try:
            conf = self._load_config(cfg)
            if min_weekly_remaining_percent is None:
                threshold = float(
                    pick_conf(conf, "clean", "min_weekly_remaining_percent", "weekly_remaining_min_percent", default=10) or 10
                )
            else:
                threshold = float(min_weekly_remaining_percent)
            if (not math.isfinite(threshold)) or threshold < 0 or threshold > 100:
                return False, HTTPStatus.BAD_REQUEST, "min_weekly_remaining_percent 必须在 0~100 之间"

            clean_cfg = conf.get("clean")
            if not isinstance(clean_cfg, dict):
                clean_cfg = {}
                conf["clean"] = clean_cfg

            if clean_base_url is not None:
                clean_base_url = str(clean_base_url).strip()
                if not clean_base_url:
                    return False, HTTPStatus.BAD_REQUEST, "clean.base_url 不能为空"
                clean_cfg["base_url"] = clean_base_url

            if clean_token is not None:
                clean_token = str(clean_token).strip()
                if not clean_token:
                    return False, HTTPStatus.BAD_REQUEST, "clean.token 不能为空"
                clean_cfg["token"] = clean_token

            if duckmail_bearer is not None:
                email_cfg = conf.get("email")
                if not isinstance(email_cfg, dict):
                    email_cfg = {}
                    conf["email"] = email_cfg
                bearer_val = str(duckmail_bearer).strip()
                conf["duckmail_bearer"] = bearer_val
                email_cfg["duckmail_bearer"] = bearer_val
                if bearer_val:
                    email_cfg["provider"] = "duckmail"

            clean_cfg["min_weekly_remaining_percent"] = round(threshold, 2)
            maintain_cfg = conf.get("maintainer")
            if not isinstance(maintain_cfg, dict):
                maintain_cfg = {}
                conf["maintainer"] = maintain_cfg
            maintain_cfg["min_candidates"] = int(target_active)
            self._save_config(cfg, conf)

            base_url = str(pick_conf(conf, "clean", "base_url", default="") or "").rstrip("/")
            token = str(pick_conf(conf, "clean", "token", "cpa_password", default="") or "").strip()
            target_type = str(pick_conf(conf, "clean", "target_type", default="codex") or "codex")
            timeout = int(pick_conf(conf, "clean", "timeout", default=15) or 15)
            if not base_url or not token:
                return False, HTTPStatus.BAD_REQUEST, "配置缺少 clean.base_url 或 clean.token/cpa_password"
            try:
                _, initial_candidates = get_candidates_count(
                    base_url=base_url,
                    token=token,
                    target_type=target_type,
                    timeout=timeout,
                )
            except Exception as probe_err:
                self.append_log(f"[panel] 启动前探测失败（已忽略）: {probe_err}")
                initial_candidates = None
        except Exception as e:
            return False, HTTPStatus.BAD_REQUEST, f"读取配置失败: {e}"

        with self.lock:
            if self.proc is not None and self.proc.poll() is None:
                return False, HTTPStatus.CONFLICT, "已有补号任务在运行"

            self.target_active = int(target_active)
            self.current_active_count = int(initial_candidates) if initial_candidates is not None else None
            self.min_weekly_remaining_percent = round(threshold, 2)
            self.current_config_path = str(cfg)
            self.refill_tokens = None
            cmd = [
                sys.executable,
                str(runner),
                "--config",
                str(cfg),
                "--target-active",
                str(int(target_active)),
                "--interval-seconds",
                "60",
                "--timeout",
                str(int(timeout)),
            ]
            try:
                self.proc = subprocess.Popen(
                    cmd,
                    cwd=str(self.base_dir),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                )
            except Exception as e:
                self.last_error = str(e)
                return False, HTTPStatus.INTERNAL_SERVER_ERROR, f"启动补号进程失败: {e}"

            proc = self.proc
            self.started_at = time.time()
            self.stopped_at = None
            self.last_exit_code = None
            self.last_error = ""
            self.refill_tokens = None
            self.last_deleted_ok = None
            self.last_deleted_fail = None

        self.append_log(
            "[panel] 启动自动补号守护任务: "
            f"target_active={target_active} current_active={initial_candidates if initial_candidates is not None else '-'} "
            "interval=60s "
            f"weekly_threshold={round(threshold, 2)}% config={cfg}"
        )

        reader = threading.Thread(target=self._pump_output, args=(proc,), daemon=True)
        watcher = threading.Thread(target=self._watch_exit, args=(proc,), daemon=True)
        reader.start()
        watcher.start()
        return (
            True,
            HTTPStatus.OK,
            f"已开启自动补号守护任务，目标活跃={target_active}，当前活跃={initial_candidates if initial_candidates is not None else '-'}，"
            f"巡检间隔=60秒，周限额阈值={round(threshold, 2)}%",
        )

    def stop(self) -> tuple[bool, int, str]:
        with self.lock:
            proc = self.proc
            running = proc is not None and proc.poll() is None
        if not running or proc is None:
            return False, HTTPStatus.CONFLICT, "当前没有运行中的补号任务"

        self.append_log("[panel] 收到停止请求")
        try:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.append_log("[panel] terminate 超时，执行强制结束")
                proc.kill()
                proc.wait(timeout=5)
        except Exception as e:
            with self.lock:
                self.last_error = str(e)
            self.append_log(f"[panel] 停止失败: {e}")
            return False, HTTPStatus.INTERNAL_SERVER_ERROR, f"停止补号失败: {e}"
        return True, HTTPStatus.OK, "已停止补号任务"

    def _pump_output(self, proc: subprocess.Popen[str]) -> None:
        if proc.stdout is None:
            return
        try:
            for raw in proc.stdout:
                line = raw.rstrip("\r\n")
                clean_line = sanitize_log_line(line)
                if clean_line:
                    with self.lock:
                        self._update_runtime_metrics_from_log(clean_line)
                    self.append_log(clean_line)
        except Exception as e:
            self.append_log(f"[panel] 读取输出异常: {e}")
        finally:
            try:
                proc.stdout.close()
            except Exception:
                pass

    def _watch_exit(self, proc: subprocess.Popen[str]) -> None:
        exit_code = proc.wait()
        with self.lock:
            if self.proc is proc:
                self.last_exit_code = int(exit_code)
                self.stopped_at = time.time()
                self.proc = None
        self.append_log(f"[panel] 补号任务已退出 code={exit_code}")


class PanelServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address: tuple[str, int],
        handler_cls: type[BaseHTTPRequestHandler],
        controller: RefillController,
        panel_password: str,
    ):
        super().__init__(server_address, handler_cls)
        self.controller = controller
        self.panel_password = panel_password or PANEL_DEFAULT_PASSWORD
        self.session_lock = threading.Lock()
        self.sessions: Dict[str, float] = {}

    def create_session(self) -> str:
        sid = secrets.token_urlsafe(32)
        expires = time.time() + SESSION_TTL_SECONDS
        with self.session_lock:
            self.sessions[sid] = expires
        return sid

    def is_session_valid(self, sid: str) -> bool:
        if not sid:
            return False
        now = time.time()
        with self.session_lock:
            expires = self.sessions.get(sid)
            if expires is None:
                return False
            if expires <= now:
                self.sessions.pop(sid, None)
                return False
            # Sliding expiration.
            self.sessions[sid] = now + SESSION_TTL_SECONDS
            return True

    def remove_session(self, sid: str) -> None:
        if not sid:
            return
        with self.session_lock:
            self.sessions.pop(sid, None)


class PanelHandler(BaseHTTPRequestHandler):
    server: PanelServer

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_json(self, status: int, payload: Dict[str, Any], extra_headers: Optional[Dict[str, str]] = None) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html: str, extra_headers: Optional[Dict[str, str]] = None) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _parse_cookies(self) -> Dict[str, str]:
        raw = self.headers.get("Cookie", "")
        out: Dict[str, str] = {}
        if not raw:
            return out
        for part in raw.split(";"):
            p = part.strip()
            if not p or "=" not in p:
                continue
            k, v = p.split("=", 1)
            out[k.strip()] = v.strip()
        return out

    def _current_session_id(self) -> str:
        cookies = self._parse_cookies()
        return cookies.get(SESSION_COOKIE_NAME, "")

    def _is_authenticated(self) -> bool:
        sid = self._current_session_id()
        return self.server.is_session_valid(sid)

    def _require_auth_json(self) -> bool:
        if self._is_authenticated():
            return True
        self._send_json(HTTPStatus.UNAUTHORIZED, {"message": "未登录或登录已过期"})
        return False

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html", "/login"):
            if self._is_authenticated():
                self._send_html(HTTPStatus.OK, INDEX_HTML)
            else:
                self._send_html(HTTPStatus.OK, LOGIN_HTML)
            return
        if parsed.path == "/api/status":
            if not self._require_auth_json():
                return
            self._send_json(HTTPStatus.OK, self.server.controller.status())
            return
        if parsed.path == "/api/config":
            if not self._require_auth_json():
                return
            ok, code, payload = self.server.controller.get_config()
            self._send_json(code, payload if ok else {"message": payload.get("message", "读取配置失败")})
            return
        if parsed.path == "/api/logs":
            if not self._require_auth_json():
                return
            qs = parse_qs(parsed.query)
            lines_raw = qs.get("lines", ["500"])[0]
            try:
                lines = int(lines_raw)
            except Exception:
                lines = 500
            payload = {"lines": self.server.controller.read_logs(lines)}
            self._send_json(HTTPStatus.OK, payload)
            return
        self._send_json(HTTPStatus.NOT_FOUND, {"message": "接口不存在"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        body = self._read_json_body()

        if parsed.path == "/api/login":
            password = str(body.get("password") or "")
            if not hmac.compare_digest(password, self.server.panel_password):
                self._send_json(HTTPStatus.UNAUTHORIZED, {"ok": False, "message": "密码错误"})
                return
            sid = self.server.create_session()
            cookie_val = (
                f"{SESSION_COOKIE_NAME}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECONDS}"
            )
            self._send_json(
                HTTPStatus.OK,
                {"ok": True, "message": "登录成功"},
                extra_headers={"Set-Cookie": cookie_val},
            )
            return

        if parsed.path == "/api/logout":
            sid = self._current_session_id()
            self.server.remove_session(sid)
            clear_cookie = f"{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
            self._send_json(
                HTTPStatus.OK,
                {"ok": True, "message": "已退出登录"},
                extra_headers={"Set-Cookie": clear_cookie},
            )
            return

        if not self._require_auth_json():
            return

        if parsed.path == "/api/config":
            clean_base_url = str(body.get("clean_base_url") or "")
            clean_token = str(body.get("clean_token") or "")
            duckmail_bearer = (
                None if ("duckmail_bearer" not in body) else str(body.get("duckmail_bearer") or "")
            )
            raw_target = body.get("target_active")
            target_active: Optional[int]
            if raw_target is None or str(raw_target).strip() == "":
                target_active = None
            else:
                try:
                    target_active = int(raw_target)
                except Exception:
                    target_active = -1
            try:
                threshold = float(body.get("min_weekly_remaining_percent"))
            except Exception:
                threshold = float("nan")
            print(f"{now_iso()} | [panel] 收到保存配置请求", flush=True)
            self.server.controller.append_log(
                "[panel] 收到保存配置请求"
            )
            ok, code, message = self.server.controller.save_config(
                target_active=target_active,
                clean_base_url=clean_base_url,
                clean_token=clean_token,
                duckmail_bearer=duckmail_bearer,
                min_weekly_remaining_percent=threshold,
            )
            print(f"{now_iso()} | [panel] 保存配置结果: ok={ok}, code={code}, message={message}", flush=True)
            self.server.controller.append_log(
                f"[panel] 保存配置结果: ok={ok}, code={code}, message={message}"
            )
            self._send_json(code, {"ok": ok, "message": message, "status": self.server.controller.status()})
            return

        if parsed.path == "/api/panel_password":
            new_password = str(body.get("new_password") or "")
            ok, code, message = self.server.controller.save_panel_password(new_password=new_password)
            if ok:
                self.server.panel_password = new_password.strip()
            self._send_json(code, {"ok": ok, "message": message})
            return

        if parsed.path == "/api/start":
            try:
                target_active = int(body.get("target_active") or 0)
            except Exception:
                target_active = 0
            try:
                threshold = float(body.get("min_weekly_remaining_percent"))
            except Exception:
                threshold = None
            duckmail_bearer = (
                None if ("duckmail_bearer" not in body) else str(body.get("duckmail_bearer") or "")
            )
            config_path = body.get("config_path")
            ok, code, message = self.server.controller.start(
                target_active,
                threshold,
                str(body.get("clean_base_url")) if body.get("clean_base_url") is not None else None,
                str(body.get("clean_token")) if body.get("clean_token") is not None else None,
                duckmail_bearer,
                str(config_path) if config_path is not None else None,
            )
            self._send_json(code, {"ok": ok, "message": message, "status": self.server.controller.status()})
            return

        if parsed.path == "/api/stop":
            ok, code, message = self.server.controller.stop()
            self._send_json(code, {"ok": ok, "message": message, "status": self.server.controller.status()})
            return

        if parsed.path == "/api/clear_logs":
            self.server.controller.clear_logs()
            self._send_json(HTTPStatus.OK, {"ok": True, "message": "已清空"})
            return

        self._send_json(HTTPStatus.NOT_FOUND, {"message": "接口不存在"})


def parse_args() -> argparse.Namespace:
    base_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Chatgpt 号池控制台")
    parser.add_argument("--host", default="127.0.0.1", help="绑定地址，默认 127.0.0.1")
    parser.add_argument("--port", type=int, default=8099, help="绑定端口，默认 8099")
    parser.add_argument("--config", default=str(base_dir / "config.json"), help="默认配置文件路径")
    parser.add_argument("--max-log-lines", type=int, default=4000, help="面板内存日志最大行数")
    parser.add_argument("--password", default=PANEL_DEFAULT_PASSWORD, help="登录密码")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_dir = Path(__file__).resolve().parent
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = (base_dir / config_path).resolve()

    controller = RefillController(base_dir=base_dir, config_path=config_path, max_log_lines=args.max_log_lines)
    controller.append_log("[panel] 控制台启动")
    panel_password = str(args.password or PANEL_DEFAULT_PASSWORD).strip() or PANEL_DEFAULT_PASSWORD
    if panel_password == PANEL_DEFAULT_PASSWORD:
        try:
            conf = load_json(config_path)
            cfg_pwd = str(pick_conf(conf, "panel", "password", default=conf.get("panel_password", "")) or "").strip()
            if cfg_pwd:
                panel_password = cfg_pwd
        except Exception:
            pass

    server = PanelServer((args.host, int(args.port)), PanelHandler, controller, panel_password=panel_password)
    print(f"Chatgpt 号池控制台已启动: http://{args.host}:{args.port}")
    print(f"默认配置文件: {config_path}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            server.server_close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())






