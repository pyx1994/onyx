#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import datetime as dt
import hashlib
import json
import logging
import os
import random
import re
import secrets
import string
import sys
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlencode, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import aiohttp
except Exception:
    aiohttp = None


OPENAI_AUTH_BASE = "https://auth.openai.com"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)
DEFAULT_MGMT_UA = "codex_cli_rs/0.76.0 (Debian 13.0.0; x86_64) WindowsTerminal"

COMMON_HEADERS = {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "origin": OPENAI_AUTH_BASE,
    "user-agent": USER_AGENT,
    "sec-ch-ua": '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}
NAVIGATE_HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "user-agent": USER_AGENT,
    "sec-ch-ua": '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
}

FREEMAIL_DOMAIN_BAG_LOCK = threading.Lock()
FREEMAIL_DOMAIN_BAGS: Dict[str, Dict[str, Any]] = {}


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise RuntimeError(f"配置文件格式错误，顶层必须是对象: {path}")
    return data


def setup_logger(log_dir: Path) -> tuple[logging.Logger, Path]:
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = log_dir / f"pool_maintainer_{ts}.log"

    logger = logging.getLogger("pool_maintainer")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger, log_path


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def mgmt_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def get_item_type(item: Dict[str, Any]) -> str:
    return str(item.get("type") or item.get("typo") or "")


def extract_chatgpt_account_id(item: Dict[str, Any]) -> Optional[str]:
    for key in ("chatgpt_account_id", "chatgptAccountId", "account_id", "accountId"):
        val = item.get(key)
        if val:
            return str(val)
    return None


def safe_json_text(text: str) -> Dict[str, Any]:
    try:
        return json.loads(text)
    except Exception:
        return {}


def parse_percent_value(value: Any) -> Optional[float]:
    try:
        val = float(value)
    except Exception:
        return None
    if val < 0:
        return 0.0
    if val > 100:
        return 100.0
    return val


def extract_weekly_remaining_percent(api_call_data: Dict[str, Any]) -> Optional[float]:
    body = api_call_data.get("body")
    usage: Dict[str, Any] = {}
    if isinstance(body, dict):
        usage = body
    elif isinstance(body, str):
        parsed = safe_json_text(body)
        if isinstance(parsed, dict):
            usage = parsed

    if not usage:
        return None

    used_candidates: List[float] = []
    for key in ("rate_limit", "code_review_rate_limit"):
        rl = usage.get(key)
        if not isinstance(rl, dict):
            continue
        primary = rl.get("primary_window")
        if not isinstance(primary, dict):
            continue
        used = parse_percent_value(primary.get("used_percent"))
        if used is not None:
            used_candidates.append(used)

    if not used_candidates:
        return None

    used_max = max(used_candidates)
    remaining = 100.0 - used_max
    if remaining < 0:
        return 0.0
    if remaining > 100:
        return 100.0
    return round(remaining, 2)


def pick_conf(root: Dict[str, Any], section: str, key: str, *legacy_keys: str, default: Any = None) -> Any:
    sec = root.get(section)
    if not isinstance(sec, dict):
        sec = {}

    v = sec.get(key)
    if v is None:
        for lk in legacy_keys:
            v = sec.get(lk)
            if v is not None:
                break
    if v is not None:
        return v

    v = root.get(key)
    if v is None:
        for lk in legacy_keys:
            v = root.get(lk)
            if v is not None:
                break
    if v is not None:
        return v
    return default


def get_candidates_count(base_url: str, token: str, target_type: str, timeout: int) -> tuple[int, int]:
    url = f"{base_url.rstrip('/')}/v0/management/auth-files"
    resp = requests.get(url, headers=mgmt_headers(token), timeout=timeout)
    resp.raise_for_status()
    raw = resp.json()
    payload = raw if isinstance(raw, dict) else {}
    files = payload.get("files", []) if isinstance(payload, dict) else []
    candidates = []
    for f in files:
        if get_item_type(f).lower() != target_type.lower():
            continue
        candidates.append(f)
    return len(files), len(candidates)


def create_session(proxy: str = "") -> requests.Session:
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def generate_pkce() -> tuple[str, str]:
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def generate_datadog_trace() -> Dict[str, str]:
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    trace_hex = format(int(trace_id), "016x")
    parent_hex = format(int(parent_id), "016x")
    return {
        "traceparent": f"00-0000000000000000{trace_hex}-{parent_hex}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def generate_random_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%"
    pwd = list(
        secrets.choice(string.ascii_uppercase)
        + secrets.choice(string.ascii_lowercase)
        + secrets.choice(string.digits)
        + secrets.choice("!@#$%")
        + "".join(secrets.choice(chars) for _ in range(length - 4))
    )
    random.shuffle(pwd)
    return "".join(pwd)


def generate_random_name() -> tuple[str, str]:
    first = ["James", "Robert", "John", "Michael", "David", "Mary", "Jennifer", "Linda", "Emma", "Olivia"]
    last = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller"]
    return random.choice(first), random.choice(last)


def generate_random_birthday() -> str:
    year = random.randint(1996, 2006)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    return f"{year:04d}-{month:02d}-{day:02d}"


class SentinelTokenGenerator:
    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id: Optional[str] = None):
        self.device_id = device_id or str(uuid.uuid4())
        self.requirements_seed = str(random.random())
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= (h >> 16)
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= (h >> 13)
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= (h >> 16)
        h &= 0xFFFFFFFF
        return format(h, "08x")

    @staticmethod
    def _base64_encode(data: Any) -> str:
        js = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        return base64.b64encode(js.encode("utf-8")).decode("ascii")

    def _get_config(self) -> List[Any]:
        now = dt.datetime.now(dt.timezone.utc).strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)")
        perf_now = random.uniform(1000, 50000)
        time_origin = time.time() * 1000 - perf_now
        return [
            "1920x1080",
            now,
            4294705152,
            random.random(),
            USER_AGENT,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None,
            None,
            "en-US",
            "en-US,en",
            random.random(),
            "vendorSub−undefined",
            "location",
            "Object",
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            time_origin,
        ]

    def _run_check(self, start_time: float, seed: str, difficulty: str, config: List[Any], nonce: int) -> Optional[str]:
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        data = self._base64_encode(config)
        hash_hex = self._fnv1a_32(seed + data)
        if hash_hex[: len(difficulty)] <= difficulty:
            return data + "~S"
        return None

    def generate_requirements_token(self) -> str:
        cfg = self._get_config()
        cfg[3] = 1
        cfg[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._base64_encode(cfg)

    def generate_token(self, seed: Optional[str] = None, difficulty: Optional[str] = None) -> str:
        if seed is None:
            seed = self.requirements_seed
            difficulty = difficulty or "0"
        cfg = self._get_config()
        start = time.time()
        for i in range(self.MAX_ATTEMPTS):
            result = self._run_check(start, seed, difficulty or "0", cfg, i)
            if result:
                return "gAAAAAB" + result
        return "gAAAAAB" + self.ERROR_PREFIX + self._base64_encode(str(None))


def fetch_sentinel_challenge(session: requests.Session, device_id: str, flow: str = "authorize_continue") -> Optional[Dict[str, Any]]:
    gen = SentinelTokenGenerator(device_id=device_id)
    body = {"p": gen.generate_requirements_token(), "id": device_id, "flow": flow}
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "User-Agent": USER_AGENT,
        "Origin": "https://sentinel.openai.com",
        "sec-ch-ua": '"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    try:
        resp = session.post(
            "https://sentinel.openai.com/backend-api/sentinel/req",
            data=json.dumps(body),
            headers=headers,
            timeout=15,
            verify=False,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def build_sentinel_token(session: requests.Session, device_id: str, flow: str = "authorize_continue") -> Optional[str]:
    challenge = fetch_sentinel_challenge(session, device_id, flow)
    if not challenge:
        return None
    c_value = challenge.get("token", "")
    pow_data = challenge.get("proofofwork", {})
    gen = SentinelTokenGenerator(device_id=device_id)
    if isinstance(pow_data, dict) and pow_data.get("required") and pow_data.get("seed"):
        p_value = gen.generate_token(seed=pow_data.get("seed"), difficulty=pow_data.get("difficulty", "0"))
    else:
        p_value = gen.generate_requirements_token()
    return json.dumps({"p": p_value, "t": "", "c": c_value, "id": device_id, "flow": flow})


def create_temp_email(
    session: requests.Session,
    worker_domain: str,
    email_domains: List[str],
    admin_password: str,
    logger: logging.Logger,
) -> tuple[Optional[str], Optional[str]]:
    name_len = random.randint(10, 14)
    name_chars = list(random.choices(string.ascii_lowercase, k=name_len))
    for _ in range(random.choice([1, 2])):
        pos = random.randint(2, len(name_chars) - 1)
        name_chars.insert(pos, random.choice(string.digits))
    name = "".join(name_chars)

    chosen_domain = random.choice(email_domains) if email_domains else "tuxixilax.cfd"

    try:
        res = session.post(
            f"https://{worker_domain}/admin/new_address",
            json={"enablePrefix": True, "name": name, "domain": chosen_domain},
            headers={"x-admin-auth": admin_password, "Content-Type": "application/json"},
            timeout=10,
            verify=False,
        )
        if res.status_code == 200:
            data = res.json()
            email = data.get("address")
            token = data.get("jwt")
            if email:
                logger.info("创建临时邮箱成功: %s (domain=%s)", email, chosen_domain)
                return str(email), str(token or "")
        logger.warning("创建临时邮箱失败: HTTP %s", res.status_code)
    except Exception as e:
        logger.warning("创建临时邮箱异常: %s", e)
    return None, None


def fetch_emails(session: requests.Session, worker_domain: str, cf_token: str) -> List[Dict[str, Any]]:
    try:
        res = session.get(
            f"https://{worker_domain}/api/mails",
            params={"limit": 10, "offset": 0},
            headers={"Authorization": f"Bearer {cf_token}"},
            verify=False,
            timeout=30,
        )
        if res.status_code == 200:
            rows = res.json().get("results", [])
            return rows if isinstance(rows, list) else []
    except Exception:
        pass
    return []


def extract_verification_code(content: str) -> Optional[str]:
    if not content:
        return None
    m = re.search(r"background-color:\s*#F3F3F3[^>]*>[\s\S]*?(\d{6})[\s\S]*?</p>", content)
    if m:
        return m.group(1)
    m = re.search(r"Subject:.*?(\d{6})", content)
    if m and m.group(1) != "177010":
        return m.group(1)
    for pat in [r">\s*(\d{6})\s*<", r"(?<![#&])\b(\d{6})\b"]:
        for code in re.findall(pat, content):
            if code != "177010":
                return code
    return None


def wait_for_verification_code(
    session: requests.Session,
    worker_domain: str,
    cf_token: str,
    timeout: int = 120,
) -> Optional[str]:
    old_ids = set()
    old = fetch_emails(session, worker_domain, cf_token)
    if old:
        old_ids = {e.get("id") for e in old if isinstance(e, dict) and "id" in e}
        for item in old:
            if not isinstance(item, dict):
                continue
            raw = str(item.get("raw") or "")
            code = extract_verification_code(raw)
            if code:
                return code

    start = time.time()
    while time.time() - start < timeout:
        emails = fetch_emails(session, worker_domain, cf_token)
        if emails:
            for item in emails:
                if not isinstance(item, dict):
                    continue
                if item.get("id") in old_ids:
                    continue
                raw = str(item.get("raw") or "")
                code = extract_verification_code(raw)
                if code:
                    return code
        time.sleep(3)
    return None


def create_temp_email_duckmail(
    session: requests.Session,
    duckmail_api_base: str,
    duckmail_bearer: str,
    logger: logging.Logger,
) -> tuple[Optional[str], Optional[str]]:
    chars = string.ascii_lowercase + string.digits
    length = random.randint(8, 13)
    email_local = "".join(random.choice(chars) for _ in range(length))
    email = f"{email_local}@duckmail.sbs"
    password = "".join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=14))

    api_base = duckmail_api_base.rstrip("/")
    bearer = duckmail_bearer.replace("Bearer ", "") if duckmail_bearer.startswith("Bearer ") else duckmail_bearer
    headers = {"Authorization": f"Bearer {bearer}"}

    try:
        res = session.post(
            f"{api_base}/accounts",
            json={"address": email, "password": password},
            headers=headers,
            timeout=30,
            verify=False,
        )
        if res.status_code not in [200, 201]:
            logger.warning("DuckMail 创建邮箱失败: HTTP %s", res.status_code)
            return None, None

        time.sleep(0.5)
        token_res = session.post(
            f"{api_base}/token",
            json={"address": email, "password": password},
            timeout=30,
            verify=False,
        )
        if token_res.status_code == 200:
            token_data = token_res.json()
            mail_token = token_data.get("token")
            if mail_token:
                logger.info("DuckMail 创建临时邮箱成功: %s", email)
                return email, mail_token
        logger.warning("DuckMail 获取邮件Token失败: HTTP %s", token_res.status_code)
    except Exception as e:
        logger.warning("DuckMail 创建临时邮箱异常: %s", e)
    return None, None


def fetch_emails_duckmail(session: requests.Session, duckmail_api_base: str, mail_token: str) -> List[Dict[str, Any]]:
    api_base = duckmail_api_base.rstrip("/")
    headers = {"Authorization": f"Bearer {mail_token}"}
    try:
        res = session.get(
            f"{api_base}/messages",
            headers=headers,
            timeout=30,
            verify=False,
        )
        if res.status_code == 200:
            data = res.json()
            messages = data.get("hydra:member") or data.get("member") or data.get("data") or []
            return messages if isinstance(messages, list) else []
    except Exception:
        pass
    return []


def fetch_email_detail_duckmail(session: requests.Session, duckmail_api_base: str, mail_token: str, msg_id: str) -> Optional[Dict[str, Any]]:
    api_base = duckmail_api_base.rstrip("/")
    headers = {"Authorization": f"Bearer {mail_token}"}
    if isinstance(msg_id, str) and msg_id.startswith("/messages/"):
        msg_id = msg_id.split("/")[-1]
    try:
        res = session.get(
            f"{api_base}/messages/{msg_id}",
            headers=headers,
            timeout=30,
            verify=False,
        )
        if res.status_code == 200:
            return res.json()
    except Exception:
        pass
    return None


def wait_for_verification_code_duckmail(
    session: requests.Session,
    duckmail_api_base: str,
    mail_token: str,
    timeout: int = 120,
) -> Optional[str]:
    start = time.time()
    while time.time() - start < timeout:
        messages = fetch_emails_duckmail(session, duckmail_api_base, mail_token)
        if messages:
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = msg.get("id") or msg.get("@id")
                if not msg_id:
                    continue
                detail = fetch_email_detail_duckmail(session, duckmail_api_base, mail_token, str(msg_id))
                if detail:
                    content = detail.get("text") or detail.get("html") or ""
                    code = extract_verification_code(content)
                    if code:
                        return code
        time.sleep(3)
    return None


def next_freemail_domain_pick(api_base: str, domains: List[str]) -> tuple[int, str]:
    if not domains:
        return 0, ""

    key = api_base.rstrip("/").lower()
    current_domains = tuple(str(d) for d in domains)
    with FREEMAIL_DOMAIN_BAG_LOCK:
        bag_state = FREEMAIL_DOMAIN_BAGS.get(key)
        if not bag_state or bag_state.get("domains") != current_domains or not bag_state.get("bag"):
            bag = list(range(len(current_domains)))
            random.shuffle(bag)
            bag_state = {"domains": current_domains, "bag": bag}
            FREEMAIL_DOMAIN_BAGS[key] = bag_state

        bag = bag_state["bag"]
        idx = int(bag.pop())
        return idx, str(current_domains[idx])


def create_temp_email_freemail(
    session: requests.Session,
    freemail_api_base: str,
    freemail_bearer: str,
    logger: logging.Logger,
) -> tuple[Optional[str], Optional[str]]:
    api_base = freemail_api_base.rstrip("/")
    bearer = freemail_bearer.replace("Bearer ", "") if freemail_bearer.startswith("Bearer ") else freemail_bearer
    headers = {"Authorization": f"Bearer {bearer}"}

    try:
        domains_res = session.get(
            f"{api_base}/api/domains",
            headers=headers,
            timeout=10,
            verify=False,
        )
        if domains_res.status_code != 200:
            logger.warning("Freemail 获取域名失败: HTTP %s", domains_res.status_code)
            return None, None
        domains_data = domains_res.json()
        domains = domains_data if isinstance(domains_data, list) else []
        if not domains:
            logger.warning("Freemail 域名列表为空")
            return None, None

        domain_index, chosen_domain = next_freemail_domain_pick(api_base, domains)
        username_len = random.randint(8, 13)
        gen_res = session.get(
            f"{api_base}/api/generate",
            params={"length": username_len, "domainIndex": domain_index},
            headers=headers,
            timeout=10,
            verify=False,
        )
        if gen_res.status_code != 200:
            logger.warning("Freemail 创建邮箱失败: HTTP %s", gen_res.status_code)
            return None, None
        gen_data = gen_res.json()
        email = gen_data.get("email") if isinstance(gen_data, dict) else None
        if email:
            logger.info("Freemail 创建临时邮箱成功: %s (domain=%s)", email, chosen_domain)
            # Freemail 所有接口都使用同一个 Bearer，无单独邮箱 token。
            return str(email), bearer
        logger.warning("Freemail 创建邮箱失败: 响应缺少 email 字段")
    except Exception as e:
        logger.warning("Freemail 创建邮箱异常: %s", e)
    return None, None


def fetch_emails_freemail(
    session: requests.Session,
    freemail_api_base: str,
    freemail_bearer: str,
    mailbox: str,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    if not mailbox:
        return []
    api_base = freemail_api_base.rstrip("/")
    bearer = freemail_bearer.replace("Bearer ", "") if freemail_bearer.startswith("Bearer ") else freemail_bearer
    headers = {"Authorization": f"Bearer {bearer}"}
    try:
        res = session.get(
            f"{api_base}/api/emails",
            params={"mailbox": mailbox, "limit": limit},
            headers=headers,
            timeout=10,
            verify=False,
        )
        if res.status_code == 200:
            data = res.json()
            return data if isinstance(data, list) else []
    except Exception:
        pass
    return []


def fetch_email_detail_freemail(
    session: requests.Session,
    freemail_api_base: str,
    freemail_bearer: str,
    msg_id: str,
) -> Optional[Dict[str, Any]]:
    if not msg_id:
        return None
    api_base = freemail_api_base.rstrip("/")
    bearer = freemail_bearer.replace("Bearer ", "") if freemail_bearer.startswith("Bearer ") else freemail_bearer
    headers = {"Authorization": f"Bearer {bearer}"}
    try:
        res = session.get(
            f"{api_base}/api/email/{quote(str(msg_id), safe='')}",
            headers=headers,
            timeout=10,
            verify=False,
        )
        if res.status_code == 200:
            data = res.json()
            return data if isinstance(data, dict) else None
    except Exception:
        pass
    return None


def wait_for_verification_code_freemail(
    session: requests.Session,
    freemail_api_base: str,
    freemail_bearer: str,
    mailbox: str,
    timeout: int = 120,
) -> Optional[str]:
    tried_message_ids: set[str] = set()
    start = time.time()
    while time.time() - start < timeout:
        messages = fetch_emails_freemail(
            session=session,
            freemail_api_base=freemail_api_base,
            freemail_bearer=freemail_bearer,
            mailbox=mailbox,
            limit=20,
        )
        if messages:
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                msg_id = str(msg.get("id") or "")
                if not msg_id or msg_id in tried_message_ids:
                    continue
                tried_message_ids.add(msg_id)

                # 先尝试主题，减少一次详情请求。
                subject_code = extract_verification_code(str(msg.get("subject") or ""))
                if subject_code:
                    return subject_code

                detail = fetch_email_detail_freemail(
                    session=session,
                    freemail_api_base=freemail_api_base,
                    freemail_bearer=freemail_bearer,
                    msg_id=msg_id,
                )
                if not detail:
                    continue
                content = str(detail.get("content") or "")
                html_content = str(detail.get("html_content") or "")
                code = extract_verification_code(content) or extract_verification_code(html_content)
                if code:
                    return code
        time.sleep(3)
    return None


class ProtocolRegistrar:
    def __init__(self, proxy: str, logger: logging.Logger):
        self.session = create_session(proxy=proxy)
        self.device_id = str(uuid.uuid4())
        self.logger = logger
        self.sentinel_gen = SentinelTokenGenerator(device_id=self.device_id)
        self.code_verifier: Optional[str] = None
        self.state: Optional[str] = None

    def _build_headers(self, referer: str, with_sentinel: bool = False) -> Dict[str, str]:
        h = dict(COMMON_HEADERS)
        h["referer"] = referer
        h["oai-device-id"] = self.device_id
        h.update(generate_datadog_trace())
        if with_sentinel:
            h["openai-sentinel-token"] = self.sentinel_gen.generate_token()
        return h

    def step0_init_oauth_session(self, email: str, client_id: str, redirect_uri: str) -> bool:
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")

        code_verifier, code_challenge = generate_pkce()
        self.code_verifier = code_verifier
        self.state = secrets.token_urlsafe(32)

        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid profile email offline_access",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": self.state,
            "screen_hint": "signup",
            "prompt": "login",
        }

        url = f"{OPENAI_AUTH_BASE}/oauth/authorize?{urlencode(params)}"
        try:
            resp = self.session.get(url, headers=NAVIGATE_HEADERS, allow_redirects=True, verify=False, timeout=30)
        except Exception as e:
            self.logger.warning("步骤0a失败: %s", e)
            return False
        if resp.status_code not in (200, 302):
            self.logger.warning(
                "步骤0a失败: OAuth初始化状态码异常 status=%s, url=%s, 响应预览=%s",
                resp.status_code,
                str(resp.url),
                (resp.text or "")[:300].replace("\n", " "),
            )
            return False

        has_login_session = any(c.name == "login_session" for c in self.session.cookies)
        if not has_login_session:
            cookie_names = [c.name for c in self.session.cookies]
            self.logger.warning(
                "步骤0a失败: 未获取 login_session cookie, cookies=%s, status=%s, url=%s, 响应预览=%s",
                cookie_names,
                resp.status_code,
                str(resp.url),
                (resp.text or "")[:300].replace("\n", " "),
            )
            return False

        headers = self._build_headers(f"{OPENAI_AUTH_BASE}/create-account")
        sentinel = build_sentinel_token(self.session, self.device_id, flow="authorize_continue")
        if sentinel:
            headers["openai-sentinel-token"] = sentinel
        try:
            r2 = self.session.post(
                f"{OPENAI_AUTH_BASE}/api/accounts/authorize/continue",
                json={"username": {"kind": "email", "value": email}, "screen_hint": "signup"},
                headers=headers,
                verify=False,
                timeout=30,
            )
            if r2.status_code != 200:
                self.logger.warning(
                    "步骤0b失败: authorize/continue 返回异常 status=%s, email=%s, 响应预览=%s",
                    r2.status_code,
                    email,
                    (r2.text or "")[:300].replace("\n", " "),
                )
            return r2.status_code == 200
        except Exception as e:
            self.logger.warning("步骤0b异常: %s | email=%s", e, email)
            return False

    def step2_register_user(self, email: str, password: str) -> bool:
        headers = self._build_headers(
            f"{OPENAI_AUTH_BASE}/create-account/password",
            with_sentinel=True,
        )
        try:
            resp = self.session.post(
                f"{OPENAI_AUTH_BASE}/api/accounts/user/register",
                json={"username": email, "password": password},
                headers=headers,
                verify=False,
                timeout=30,
            )
            if resp.status_code == 200:
                return True
            if resp.status_code in (301, 302):
                loc = resp.headers.get("Location", "")
                ok_redirect = "email-otp" in loc or "email-verification" in loc
                if not ok_redirect:
                    self.logger.warning(
                        "步骤2失败: register重定向异常 status=%s, location=%s, email=%s",
                        resp.status_code,
                        loc,
                        email,
                    )
                return ok_redirect
            self.logger.warning(
                "步骤2失败: register返回异常 status=%s, email=%s, 响应预览=%s",
                resp.status_code,
                email,
                (resp.text or "")[:300].replace("\n", " "),
            )
            return False
        except Exception as e:
            self.logger.warning("步骤2异常: %s | email=%s", e, email)
            return False

    def step3_send_otp(self) -> bool:
        try:
            h = dict(NAVIGATE_HEADERS)
            h["referer"] = f"{OPENAI_AUTH_BASE}/create-account/password"
            r_send = self.session.get(
                f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/send",
                headers=h,
                verify=False,
                timeout=30,
                allow_redirects=True,
            )
            r_page = self.session.get(
                f"{OPENAI_AUTH_BASE}/email-verification",
                headers=h,
                verify=False,
                timeout=30,
                allow_redirects=True,
            )
            if r_send.status_code >= 400 or r_page.status_code >= 400:
                self.logger.warning(
                    "步骤3告警: 发送OTP或进入验证页状态异常 send=%s page=%s",
                    r_send.status_code,
                    r_page.status_code,
                )
            return True
        except Exception as e:
            self.logger.warning("步骤3异常: %s", e)
            return False

    def step4_validate_otp(self, code: str) -> bool:
        h = self._build_headers(f"{OPENAI_AUTH_BASE}/email-verification")
        try:
            r = self.session.post(
                f"{OPENAI_AUTH_BASE}/api/accounts/email-otp/validate",
                json={"code": code},
                headers=h,
                verify=False,
                timeout=30,
            )
            if r.status_code != 200:
                self.logger.warning(
                    "步骤4失败: OTP验证失败 status=%s, code=%s, 响应预览=%s",
                    r.status_code,
                    code,
                    (r.text or "")[:300].replace("\n", " "),
                )
            return r.status_code == 200
        except Exception as e:
            self.logger.warning("步骤4异常: %s", e)
            return False

    def step5_create_account(self, first_name: str, last_name: str, birthdate: str) -> bool:
        h = self._build_headers(f"{OPENAI_AUTH_BASE}/about-you")
        body = {"name": f"{first_name} {last_name}", "birthdate": birthdate}
        try:
            r = self.session.post(
                f"{OPENAI_AUTH_BASE}/api/accounts/create_account",
                json=body,
                headers=h,
                verify=False,
                timeout=30,
            )
            if r.status_code == 200:
                return True
            if r.status_code == 403 and "sentinel" in r.text.lower():
                self.logger.warning("步骤5告警: create_account 命中sentinel风控，尝试重试")
                h["openai-sentinel-token"] = SentinelTokenGenerator(self.device_id).generate_token()
                rr = self.session.post(
                    f"{OPENAI_AUTH_BASE}/api/accounts/create_account",
                    json=body,
                    headers=h,
                    verify=False,
                    timeout=30,
                )
                if rr.status_code != 200:
                    self.logger.warning(
                        "步骤5失败: sentinel重试后仍失败 status=%s, 响应预览=%s",
                        rr.status_code,
                        (rr.text or "")[:300].replace("\n", " "),
                    )
                return rr.status_code == 200
            if r.status_code not in (301, 302):
                self.logger.warning(
                    "步骤5失败: create_account返回异常 status=%s, 响应预览=%s",
                    r.status_code,
                    (r.text or "")[:300].replace("\n", " "),
                )
            return r.status_code in (301, 302)
        except Exception as e:
            self.logger.warning("步骤5异常: %s", e)
            return False

    def register(
        self,
        email: str,
        worker_domain: str,
        cf_token: str,
        password: str,
        client_id: str,
        redirect_uri: str,
        email_provider: str = "cloudflare",
        duckmail_api_base: str = "",
        freemail_api_base: str = "",
    ) -> bool:
        first_name, last_name = generate_random_name()
        birthdate = generate_random_birthday()
        if not self.step0_init_oauth_session(email, client_id, redirect_uri):
            self.logger.warning("注册失败: step0_init_oauth_session | email=%s", email)
            return False
        time.sleep(1)
        if not self.step2_register_user(email, password):
            self.logger.warning("注册失败: step2_register_user | email=%s", email)
            return False
        time.sleep(1)
        if not self.step3_send_otp():
            self.logger.warning("注册失败: step3_send_otp | email=%s", email)
            return False
        mail_session = create_session()
        if email_provider == "duckmail":
            code = wait_for_verification_code_duckmail(mail_session, duckmail_api_base, cf_token)
        elif email_provider == "freemail":
            code = wait_for_verification_code_freemail(mail_session, freemail_api_base, cf_token, email)
        else:
            code = wait_for_verification_code(mail_session, worker_domain, cf_token)
        if not code:
            self.logger.warning("注册失败: 未收到验证码 | email=%s", email)
            return False
        if not self.step4_validate_otp(code):
            self.logger.warning("注册失败: step4_validate_otp | email=%s", email)
            return False
        time.sleep(1)
        ok = self.step5_create_account(first_name, last_name, birthdate)
        if not ok:
            self.logger.warning("注册失败: step5_create_account | email=%s", email)
        return ok


def codex_exchange_code(
    code: str,
    code_verifier: str,
    oauth_issuer: str,
    oauth_client_id: str,
    oauth_redirect_uri: str,
    proxy: str,
) -> Optional[Dict[str, Any]]:
    session = create_session(proxy=proxy)
    try:
        resp = session.post(
            f"{oauth_issuer}/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": oauth_redirect_uri,
                "client_id": oauth_client_id,
                "code_verifier": code_verifier,
            },
            verify=False,
            timeout=60,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data if isinstance(data, dict) else None
        return None
    except Exception:
        return None


def perform_codex_oauth_login_http(
    email: str,
    password: str,
    cf_token: str,
    worker_domain: str,
    oauth_issuer: str,
    oauth_client_id: str,
    oauth_redirect_uri: str,
    proxy: str,
    email_provider: str = "cloudflare",
    duckmail_api_base: str = "",
    freemail_api_base: str = "",
) -> Optional[Dict[str, Any]]:
    session = create_session(proxy=proxy)
    device_id = str(uuid.uuid4())

    session.cookies.set("oai-did", device_id, domain=".auth.openai.com")
    session.cookies.set("oai-did", device_id, domain="auth.openai.com")

    code_verifier, code_challenge = generate_pkce()
    state = secrets.token_urlsafe(32)

    authorize_params = {
        "response_type": "code",
        "client_id": oauth_client_id,
        "redirect_uri": oauth_redirect_uri,
        "scope": "openid profile email offline_access",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
    }
    authorize_url = f"{oauth_issuer}/oauth/authorize?{urlencode(authorize_params)}"

    try:
        session.get(
            authorize_url,
            headers=NAVIGATE_HEADERS,
            allow_redirects=True,
            verify=False,
            timeout=30,
        )
    except Exception:
        return None

    headers = dict(COMMON_HEADERS)
    headers["referer"] = f"{oauth_issuer}/log-in"
    headers["oai-device-id"] = device_id
    headers.update(generate_datadog_trace())

    sentinel_email = build_sentinel_token(session, device_id, flow="authorize_continue")
    if not sentinel_email:
        return None
    headers["openai-sentinel-token"] = sentinel_email

    try:
        resp = session.post(
            f"{oauth_issuer}/api/accounts/authorize/continue",
            json={"username": {"kind": "email", "value": email}},
            headers=headers,
            verify=False,
            timeout=30,
        )
    except Exception:
        return None

    if resp.status_code != 200:
        return None

    headers["referer"] = f"{oauth_issuer}/log-in/password"
    headers.update(generate_datadog_trace())

    sentinel_pwd = build_sentinel_token(session, device_id, flow="password_verify")
    if not sentinel_pwd:
        return None
    headers["openai-sentinel-token"] = sentinel_pwd

    try:
        resp = session.post(
            f"{oauth_issuer}/api/accounts/password/verify",
            json={"password": password},
            headers=headers,
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
    except Exception:
        return None

    if resp.status_code != 200:
        return None

    continue_url = None
    page_type = ""
    try:
        data = resp.json()
        continue_url = str(data.get("continue_url") or "")
        page_type = str(((data.get("page") or {}).get("type")) or "")
    except Exception:
        pass

    if not continue_url:
        return None

    if page_type == "email_otp_verification" or "email-verification" in continue_url:
        if not cf_token:
            return None

        mail_session = create_session(proxy=proxy)
        tried_codes = set()
        start_time = time.time()

        h_val = dict(COMMON_HEADERS)
        h_val["referer"] = f"{oauth_issuer}/email-verification"
        h_val["oai-device-id"] = device_id
        h_val.update(generate_datadog_trace())

        code = None
        while time.time() - start_time < 120:
            if email_provider == "duckmail":
                all_emails = fetch_emails_duckmail(mail_session, duckmail_api_base, cf_token)
            elif email_provider == "freemail":
                all_emails = fetch_emails_freemail(mail_session, freemail_api_base, cf_token, email, limit=20)
            else:
                all_emails = fetch_emails(mail_session, worker_domain, cf_token)
            if not all_emails:
                time.sleep(2)
                continue

            all_codes = []
            for e_item in all_emails:
                if not isinstance(e_item, dict):
                    continue
                if email_provider == "duckmail":
                    msg_id = e_item.get("id") or e_item.get("@id")
                    if msg_id:
                        detail = fetch_email_detail_duckmail(mail_session, duckmail_api_base, cf_token, str(msg_id))
                        if detail:
                            content = detail.get("text") or detail.get("html") or ""
                            c = extract_verification_code(content)
                            if c and c not in tried_codes:
                                all_codes.append(c)
                elif email_provider == "freemail":
                    msg_id = e_item.get("id")
                    subject_code = extract_verification_code(str(e_item.get("subject") or ""))
                    if subject_code and subject_code not in tried_codes:
                        all_codes.append(subject_code)
                        continue
                    if msg_id:
                        detail = fetch_email_detail_freemail(mail_session, freemail_api_base, cf_token, str(msg_id))
                        if detail:
                            content = str(detail.get("content") or "")
                            html_content = str(detail.get("html_content") or "")
                            c = extract_verification_code(content) or extract_verification_code(html_content)
                            if c and c not in tried_codes:
                                all_codes.append(c)
                else:
                    c = extract_verification_code(str(e_item.get("raw") or ""))
                    if c and c not in tried_codes:
                        all_codes.append(c)

            if not all_codes:
                time.sleep(2)
                continue

            for try_code in all_codes:
                tried_codes.add(try_code)
                resp_val = session.post(
                    f"{oauth_issuer}/api/accounts/email-otp/validate",
                    json={"code": try_code},
                    headers=h_val,
                    verify=False,
                    timeout=30,
                )
                if resp_val.status_code == 200:
                    code = try_code
                    try:
                        data = resp_val.json()
                        continue_url = str(data.get("continue_url") or "")
                        page_type = str(((data.get("page") or {}).get("type")) or "")
                    except Exception:
                        pass
                    break

            if code:
                break
            time.sleep(2)

        if not code:
            return None

        if "about-you" in continue_url:
            h_about = dict(NAVIGATE_HEADERS)
            h_about["referer"] = f"{oauth_issuer}/email-verification"
            try:
                resp_about = session.get(
                    f"{oauth_issuer}/about-you",
                    headers=h_about,
                    verify=False,
                    timeout=30,
                    allow_redirects=True,
                )
            except Exception:
                return None

            if "consent" in str(resp_about.url) or "organization" in str(resp_about.url):
                continue_url = str(resp_about.url)
            else:
                first_name, last_name = generate_random_name()
                birthdate = generate_random_birthday()

                h_create = dict(COMMON_HEADERS)
                h_create["referer"] = f"{oauth_issuer}/about-you"
                h_create["oai-device-id"] = device_id
                h_create.update(generate_datadog_trace())

                resp_create = session.post(
                    f"{oauth_issuer}/api/accounts/create_account",
                    json={"name": f"{first_name} {last_name}", "birthdate": birthdate},
                    headers=h_create,
                    verify=False,
                    timeout=30,
                )

                if resp_create.status_code == 200:
                    try:
                        data = resp_create.json()
                        continue_url = str(data.get("continue_url") or "")
                    except Exception:
                        pass
                elif resp_create.status_code == 400 and "already_exists" in resp_create.text:
                    continue_url = f"{oauth_issuer}/sign-in-with-chatgpt/codex/consent"

        if "consent" in page_type:
            continue_url = f"{oauth_issuer}/sign-in-with-chatgpt/codex/consent"

        if not continue_url or "email-verification" in continue_url:
            return None

    if continue_url.startswith("/"):
        consent_url = f"{oauth_issuer}{continue_url}"
    else:
        consent_url = continue_url

    def _extract_code_from_url(url: str) -> Optional[str]:
        if not url or "code=" not in url:
            return None
        try:
            return parse_qs(urlparse(url).query).get("code", [None])[0]
        except Exception:
            return None

    def _decode_auth_session(session_obj: requests.Session) -> Optional[Dict[str, Any]]:
        for c in session_obj.cookies:
            if c.name == "oai-client-auth-session":
                val = c.value
                first_part = val.split(".")[0] if "." in val else val
                pad = 4 - len(first_part) % 4
                if pad != 4:
                    first_part += "=" * pad
                try:
                    raw = base64.urlsafe_b64decode(first_part)
                    d = json.loads(raw.decode("utf-8"))
                    return d if isinstance(d, dict) else None
                except Exception:
                    pass
        return None

    def _follow_and_extract_code(session_obj: requests.Session, url: str, max_depth: int = 10) -> Optional[str]:
        if max_depth <= 0:
            return None
        try:
            r = session_obj.get(
                url,
                headers=NAVIGATE_HEADERS,
                verify=False,
                timeout=15,
                allow_redirects=False,
            )
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                code = _extract_code_from_url(loc)
                if code:
                    return code
                if loc.startswith("/"):
                    loc = f"{oauth_issuer}{loc}"
                return _follow_and_extract_code(session_obj, loc, max_depth - 1)
            if r.status_code == 200:
                return _extract_code_from_url(str(r.url))
        except requests.exceptions.ConnectionError as e:
            m = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
            if m:
                return _extract_code_from_url(m.group(1))
        except Exception:
            pass
        return None

    auth_code = None

    try:
        resp_consent = session.get(
            consent_url,
            headers=NAVIGATE_HEADERS,
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
        if resp_consent.status_code in (301, 302, 303, 307, 308):
            loc = resp_consent.headers.get("Location", "")
            auth_code = _extract_code_from_url(loc)
            if not auth_code:
                auth_code = _follow_and_extract_code(session, loc)
    except requests.exceptions.ConnectionError as e:
        m = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
        if m:
            auth_code = _extract_code_from_url(m.group(1))
    except Exception:
        pass

    if not auth_code:
        session_data = _decode_auth_session(session)
        workspace_id = None
        if session_data:
            workspaces = session_data.get("workspaces", [])
            if isinstance(workspaces, list) and workspaces:
                workspace_id = (workspaces[0] or {}).get("id")

        if workspace_id:
            h_consent = dict(COMMON_HEADERS)
            h_consent["referer"] = consent_url
            h_consent["oai-device-id"] = device_id
            h_consent.update(generate_datadog_trace())

            try:
                resp_ws = session.post(
                    f"{oauth_issuer}/api/accounts/workspace/select",
                    json={"workspace_id": workspace_id},
                    headers=h_consent,
                    verify=False,
                    timeout=30,
                    allow_redirects=False,
                )
                if resp_ws.status_code in (301, 302, 303, 307, 308):
                    loc = resp_ws.headers.get("Location", "")
                    auth_code = _extract_code_from_url(loc)
                    if not auth_code:
                        auth_code = _follow_and_extract_code(session, loc)
                elif resp_ws.status_code == 200:
                    ws_data = resp_ws.json()
                    ws_next = str(ws_data.get("continue_url") or "")
                    ws_page = str(((ws_data.get("page") or {}).get("type")) or "")

                    if "organization" in ws_next or "organization" in ws_page:
                        org_url = ws_next if ws_next.startswith("http") else f"{oauth_issuer}{ws_next}"

                        org_id = None
                        project_id = None
                        ws_orgs = (ws_data.get("data") or {}).get("orgs", []) if isinstance(ws_data, dict) else []
                        if ws_orgs:
                            org_id = (ws_orgs[0] or {}).get("id")
                            projects = (ws_orgs[0] or {}).get("projects", [])
                            if projects:
                                project_id = (projects[0] or {}).get("id")

                        if org_id:
                            body = {"org_id": org_id}
                            if project_id:
                                body["project_id"] = project_id

                            h_org = dict(COMMON_HEADERS)
                            h_org["referer"] = org_url
                            h_org["oai-device-id"] = device_id
                            h_org.update(generate_datadog_trace())

                            resp_org = session.post(
                                f"{oauth_issuer}/api/accounts/organization/select",
                                json=body,
                                headers=h_org,
                                verify=False,
                                timeout=30,
                                allow_redirects=False,
                            )
                            if resp_org.status_code in (301, 302, 303, 307, 308):
                                loc = resp_org.headers.get("Location", "")
                                auth_code = _extract_code_from_url(loc)
                                if not auth_code:
                                    auth_code = _follow_and_extract_code(session, loc)
                            elif resp_org.status_code == 200:
                                org_data = resp_org.json()
                                org_next = str(org_data.get("continue_url") or "")
                                if org_next:
                                    full_next = org_next if org_next.startswith("http") else f"{oauth_issuer}{org_next}"
                                    auth_code = _follow_and_extract_code(session, full_next)
                        else:
                            auth_code = _follow_and_extract_code(session, org_url)
                    else:
                        if ws_next:
                            full_next = ws_next if ws_next.startswith("http") else f"{oauth_issuer}{ws_next}"
                            auth_code = _follow_and_extract_code(session, full_next)
            except Exception:
                pass

    if not auth_code:
        try:
            resp_fallback = session.get(
                consent_url,
                headers=NAVIGATE_HEADERS,
                verify=False,
                timeout=30,
                allow_redirects=True,
            )
            auth_code = _extract_code_from_url(str(resp_fallback.url))
            if not auth_code and resp_fallback.history:
                for hist in resp_fallback.history:
                    loc = hist.headers.get("Location", "")
                    auth_code = _extract_code_from_url(loc)
                    if auth_code:
                        break
        except requests.exceptions.ConnectionError as e:
            m = re.search(r'(https?://localhost[^\s\'"]+)', str(e))
            if m:
                auth_code = _extract_code_from_url(m.group(1))
        except Exception:
            pass

    if not auth_code:
        return None

    return codex_exchange_code(
        auth_code,
        code_verifier,
        oauth_issuer=oauth_issuer,
        oauth_client_id=oauth_client_id,
        oauth_redirect_uri=oauth_redirect_uri,
        proxy=proxy,
    )


def decode_jwt_payload(token: str) -> Dict[str, Any]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        decoded = base64.urlsafe_b64decode(payload)
        data = json.loads(decoded)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


class RegisterRuntime:
    def __init__(self, conf: Dict[str, Any], target_tokens: int, logger: logging.Logger):
        self.conf = conf
        self.target_tokens = target_tokens
        self.logger = logger

        self.file_lock = threading.Lock()
        self.counter_lock = threading.Lock()
        self.token_success_count = 0
        self.stop_event = threading.Event()

        run_workers = int(pick_conf(conf, "run", "workers", default=1) or 1)
        self.concurrent_workers = max(1, run_workers)
        self.proxy = str(pick_conf(conf, "run", "proxy", default="") or "")

        self.worker_domain = str(pick_conf(conf, "email", "worker_domain", default="email.tuxixilax.cfd") or "")
        old_domain = str(pick_conf(conf, "email", "email_domain", default="tuxixilax.cfd") or "tuxixilax.cfd")
        domains = pick_conf(conf, "email", "email_domains", default=None)
        parsed_domains: List[str] = []
        if isinstance(domains, list):
            parsed_domains = [str(x).strip() for x in domains if str(x).strip()]
        if not parsed_domains:
            parsed_domains = [old_domain]
        self.email_domains = parsed_domains
        self.admin_password = str(pick_conf(conf, "email", "admin_password", default="") or "")

        self.email_provider = str(pick_conf(conf, "email", "provider", default="cloudflare") or "cloudflare").lower()
        self.duckmail_api_base = str(
            pick_conf(
                conf,
                "email",
                "duckmail_api_base",
                default=conf.get("duckmail_api_base", "https://api.duckmail.sbs"),
            )
            or "https://api.duckmail.sbs"
        )
        self.duckmail_bearer = str(
            pick_conf(conf, "email", "duckmail_bearer", default=conf.get("duckmail_bearer", "")) or ""
        )
        self.freemail_api_base = str(
            pick_conf(
                conf,
                "email",
                "freemail_api_base",
                default=conf.get("freemail_api_base", "https://mail.10010086.cn"),
            )
            or "https://mail.10010086.cn"
        )
        self.freemail_bearer = str(
            pick_conf(conf, "email", "freemail_bearer", default=conf.get("freemail_bearer", "")) or ""
        )

        self.oauth_issuer = str(pick_conf(conf, "oauth", "issuer", default="https://auth.openai.com") or "https://auth.openai.com")
        self.oauth_client_id = str(
            pick_conf(conf, "oauth", "client_id", default="app_EMoamEEZ73f0CkXaXp7hrann") or "app_EMoamEEZ73f0CkXaXp7hrann"
        )
        self.oauth_redirect_uri = str(
            pick_conf(conf, "oauth", "redirect_uri", default="http://localhost:1455/auth/callback")
            or "http://localhost:1455/auth/callback"
        )
        self.oauth_retry_attempts = int(pick_conf(conf, "oauth", "retry_attempts", default=3) or 3)
        self.oauth_retry_backoff_base = float(pick_conf(conf, "oauth", "retry_backoff_base", default=2.0) or 2.0)
        self.oauth_retry_backoff_max = float(pick_conf(conf, "oauth", "retry_backoff_max", default=15.0) or 15.0)

        upload_base = str(pick_conf(conf, "upload", "cli_proxy_api_base", "base_url", default="") or "").strip()
        if not upload_base:
            upload_base = str(pick_conf(conf, "clean", "base_url", default="") or "").strip()
        self.cli_proxy_api_base = upload_base.rstrip("/")

        upload_token = str(pick_conf(conf, "upload", "token", "cpa_password", default="") or "").strip()
        if not upload_token:
            upload_token = str(pick_conf(conf, "clean", "token", "cpa_password", default="") or "").strip()
        self.upload_api_token = upload_token

        self.upload_url = f"{self.cli_proxy_api_base}/v0/management/auth-files" if self.cli_proxy_api_base else ""

        output_cfg = conf.get("output")
        if not isinstance(output_cfg, dict):
            output_cfg = {}

        save_local_raw = output_cfg.get("save_local", True)
        if isinstance(save_local_raw, bool):
            self.save_local = save_local_raw
        else:
            self.save_local = str(save_local_raw).strip().lower() in ("1", "true", "yes", "on")

        self.run_dir = os.getcwd()
        if self.save_local:
            self.fixed_out_dir = os.path.join(self.run_dir, "output_fixed")
            self.tokens_parent_dir = os.path.join(self.run_dir, "output_tokens")
            os.makedirs(self.fixed_out_dir, exist_ok=True)
            os.makedirs(self.tokens_parent_dir, exist_ok=True)
            self.tokens_out_dir = self._ensure_unique_dir(self.tokens_parent_dir, f"{target_tokens}个账号")

            self.accounts_file = self._resolve_output_path(str(output_cfg.get("accounts_file", "accounts.txt")))
            self.csv_file = self._resolve_output_path(str(output_cfg.get("csv_file", "registered_accounts.csv")))
            self.ak_file = self._resolve_output_path(str(output_cfg.get("ak_file", "ak.txt")))
            self.rk_file = self._resolve_output_path(str(output_cfg.get("rk_file", "rk.txt")))
        else:
            self.fixed_out_dir = ""
            self.tokens_parent_dir = ""
            self.tokens_out_dir = ""
            self.accounts_file = ""
            self.csv_file = ""
            self.ak_file = ""
            self.rk_file = ""

    def _resolve_output_path(self, value: str) -> str:
        if os.path.isabs(value):
            return value
        return os.path.join(self.fixed_out_dir, value)

    def _ensure_unique_dir(self, parent_dir: str, base_name: str) -> str:
        os.makedirs(parent_dir, exist_ok=True)

        candidates = [os.path.join(parent_dir, base_name)] + [
            os.path.join(parent_dir, f"{base_name}-{idx}") for idx in range(1, 1000000)
        ]
        for candidate in candidates:
            try:
                os.makedirs(candidate)
                return candidate
            except FileExistsError:
                continue
        raise RuntimeError(f"无法创建唯一目录: {parent_dir}/{base_name}")

    def get_token_success_count(self) -> int:
        with self.counter_lock:
            return self.token_success_count

    def claim_token_slot(self) -> tuple[bool, int]:
        with self.counter_lock:
            if self.token_success_count >= self.target_tokens:
                return False, self.token_success_count
            self.token_success_count += 1
            if self.token_success_count >= self.target_tokens:
                self.stop_event.set()
            return True, self.token_success_count

    def release_token_slot(self) -> None:
        with self.counter_lock:
            if self.token_success_count > 0:
                self.token_success_count -= 1
            if self.token_success_count < self.target_tokens:
                self.stop_event.clear()

    def save_token_json(self, email: str, access_token: str, refresh_token: str = "", id_token: str = "") -> bool:
        try:
            payload = decode_jwt_payload(access_token)
            auth_info = payload.get("https://api.openai.com/auth", {})
            account_id = auth_info.get("chatgpt_account_id", "") if isinstance(auth_info, dict) else ""

            exp_timestamp = payload.get("exp", 0)
            expired_str = ""
            if exp_timestamp:
                exp_dt = dt.datetime.fromtimestamp(exp_timestamp, tz=dt.timezone(dt.timedelta(hours=8)))
                expired_str = exp_dt.strftime("%Y-%m-%dT%H:%M:%S+08:00")

            now = dt.datetime.now(tz=dt.timezone(dt.timedelta(hours=8)))
            token_data = {
                "type": "codex",
                "email": email,
                "expired": expired_str,
                "id_token": id_token or "",
                "account_id": account_id,
                "access_token": access_token,
                "last_refresh": now.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
                "refresh_token": refresh_token or "",
            }

            if self.save_local:
                filename = os.path.join(self.tokens_out_dir, f"{email}.json")
                ensure_parent_dir(filename)
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(token_data, f, ensure_ascii=False)

                if self.upload_url and self.upload_api_token:
                    self.upload_token_json(filename)
            else:
                if self.upload_url and self.upload_api_token:
                    self.upload_token_data(f"{email}.json", token_data)

            return True
        except Exception as e:
            self.logger.warning("保存 Token JSON 失败: %s", e)
            return False

    def upload_token_json(self, filename: str) -> None:
        if not self.upload_url or not self.upload_api_token:
            return
        try:
            s = create_session(proxy=self.proxy)
            with open(filename, "rb") as f:
                files = {"file": (os.path.basename(filename), f, "application/json")}
                headers = {"Authorization": f"Bearer {self.upload_api_token}"}
                resp = s.post(self.upload_url, files=files, headers=headers, verify=False, timeout=30)
                if resp.status_code != 200:
                    self.logger.warning("上传 token 失败: %s %s", resp.status_code, resp.text[:200])
        except Exception as e:
            self.logger.warning("上传 token 异常: %s", e)

    def upload_token_data(self, filename: str, token_data: Dict[str, Any]) -> None:
        if not self.upload_url or not self.upload_api_token:
            return
        try:
            s = create_session(proxy=self.proxy)
            content = json.dumps(token_data, ensure_ascii=False).encode("utf-8")
            files = {"file": (filename, content, "application/json")}
            headers = {"Authorization": f"Bearer {self.upload_api_token}"}
            resp = s.post(self.upload_url, files=files, headers=headers, verify=False, timeout=30)
            if resp.status_code != 200:
                self.logger.warning("上传 token 失败: %s %s", resp.status_code, resp.text[:200])
        except Exception as e:
            self.logger.warning("上传 token 异常: %s", e)

    def save_tokens(self, email: str, tokens: Dict[str, Any]) -> bool:
        access_token = str(tokens.get("access_token") or "")
        refresh_token = str(tokens.get("refresh_token") or "")
        id_token = str(tokens.get("id_token") or "")

        if self.save_local:
            try:
                with self.file_lock:
                    if access_token:
                        ensure_parent_dir(self.ak_file)
                        with open(self.ak_file, "a", encoding="utf-8") as f:
                            f.write(f"{access_token}\n")
                    if refresh_token:
                        ensure_parent_dir(self.rk_file)
                        with open(self.rk_file, "a", encoding="utf-8") as f:
                            f.write(f"{refresh_token}\n")
            except Exception as e:
                self.logger.warning("AK/RK 保存失败: %s", e)
                return False

        if access_token:
            return self.save_token_json(email, access_token, refresh_token, id_token)
        return False

    def save_account(self, email: str, password: str) -> None:
        if not self.save_local:
            return

        with self.file_lock:
            ensure_parent_dir(self.accounts_file)
            ensure_parent_dir(self.csv_file)

            with open(self.accounts_file, "a", encoding="utf-8") as f:
                f.write(f"{email}:{password}\n")

            file_exists = os.path.exists(self.csv_file)
            with open(self.csv_file, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                if not file_exists:
                    writer.writerow(["email", "password", "timestamp"])
                writer.writerow([email, password, time.strftime("%Y-%m-%d %H:%M:%S")])

    def collect_token_emails(self) -> set[str]:
        emails = set()
        if not os.path.isdir(self.tokens_out_dir):
            return emails
        for name in os.listdir(self.tokens_out_dir):
            if not name.endswith(".json"):
                continue
            path = os.path.join(self.tokens_out_dir, name)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                email = data.get("email") or name[:-5]
                if email:
                    emails.add(str(email))
            except Exception:
                continue
        return emails

    def reconcile_account_outputs_from_tokens(self) -> int:
        if not self.save_local:
            return 0

        token_emails = self.collect_token_emails()

        pwd_map: Dict[str, str] = {}
        if os.path.exists(self.accounts_file):
            try:
                with open(self.accounts_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or ":" not in line:
                            continue
                        email, pwd = line.split(":", 1)
                        pwd_map[email] = pwd
            except Exception:
                pass

        ordered_emails = sorted(token_emails)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        with self.file_lock:
            ensure_parent_dir(self.accounts_file)
            ensure_parent_dir(self.csv_file)

            with open(self.accounts_file, "w", encoding="utf-8") as f:
                for email in ordered_emails:
                    f.write(f"{email}:{pwd_map.get(email, '')}\n")

            with open(self.csv_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["email", "password", "timestamp"])
                for email in ordered_emails:
                    writer.writerow([email, pwd_map.get(email, ""), timestamp])

        return len(ordered_emails)

    def oauth_login_with_retry(self, email: str, password: str, cf_token: str) -> Optional[Dict[str, Any]]:
        attempts = max(1, self.oauth_retry_attempts)
        for attempt in range(1, attempts + 1):
            if self.stop_event.is_set() and self.get_token_success_count() >= self.target_tokens:
                return None

            self.logger.info("OAuth 尝试 %s/%s: %s", attempt, attempts, email)
            tokens = perform_codex_oauth_login_http(
                email=email,
                password=password,
                cf_token=cf_token,
                worker_domain=self.worker_domain,
                oauth_issuer=self.oauth_issuer,
                oauth_client_id=self.oauth_client_id,
                oauth_redirect_uri=self.oauth_redirect_uri,
                proxy=self.proxy,
                email_provider=self.email_provider,
                duckmail_api_base=self.duckmail_api_base,
                freemail_api_base=self.freemail_api_base,
            )
            if tokens:
                return tokens
            if attempt < attempts:
                backoff = min(self.oauth_retry_backoff_max, self.oauth_retry_backoff_base ** (attempt - 1))
                jitter = random.uniform(0.2, 0.8)
                time.sleep(backoff + jitter)
        return None


def register_one(runtime: RegisterRuntime, worker_id: int = 0) -> tuple[Optional[str], Optional[bool], float, float]:
    if runtime.stop_event.is_set() and runtime.get_token_success_count() >= runtime.target_tokens:
        return None, None, 0.0, 0.0

    t_start = time.time()
    session = create_session(proxy=runtime.proxy)

    if runtime.email_provider == "duckmail":
        email, cf_token = create_temp_email_duckmail(
            session,
            duckmail_api_base=runtime.duckmail_api_base,
            duckmail_bearer=runtime.duckmail_bearer,
            logger=runtime.logger,
        )
    elif runtime.email_provider == "freemail":
        email, cf_token = create_temp_email_freemail(
            session,
            freemail_api_base=runtime.freemail_api_base,
            freemail_bearer=runtime.freemail_bearer,
            logger=runtime.logger,
        )
    else:
        email, cf_token = create_temp_email(
            session,
            worker_domain=runtime.worker_domain,
            email_domains=runtime.email_domains,
            admin_password=runtime.admin_password,
            logger=runtime.logger,
        )
    if not email or not cf_token:
        return None, False, 0.0, time.time() - t_start

    password = generate_random_password()
    registrar = ProtocolRegistrar(proxy=runtime.proxy, logger=runtime.logger)
    reg_ok = registrar.register(
        email=email,
        worker_domain=runtime.worker_domain,
        cf_token=cf_token,
        password=password,
        client_id=runtime.oauth_client_id,
        redirect_uri=runtime.oauth_redirect_uri,
        email_provider=runtime.email_provider,
        duckmail_api_base=runtime.duckmail_api_base,
        freemail_api_base=runtime.freemail_api_base,
    )
    t_reg = time.time() - t_start
    if not reg_ok:
        runtime.logger.warning("注册流程失败: %s", email)
        return email, False, t_reg, time.time() - t_start

    tokens = runtime.oauth_login_with_retry(email=email, password=password, cf_token=cf_token)
    t_total = time.time() - t_start
    if not tokens:
        return email, False, t_reg, t_total

    claimed, current = runtime.claim_token_slot()
    if not claimed:
        return email, None, t_reg, t_total

    saved = runtime.save_tokens(email, tokens)
    if not saved:
        runtime.release_token_slot()
        return email, False, t_reg, t_total

    runtime.save_account(email, password)
    runtime.logger.info(
        "注册+OAuth 成功: %s | 注册 %.1fs + OAuth %.1fs = %.1fs | token %s/%s",
        email,
        t_reg,
        t_total - t_reg,
        t_total,
        current,
        runtime.target_tokens,
    )
    return email, True, t_reg, t_total


def run_batch_register(conf: Dict[str, Any], target_tokens: int, logger: logging.Logger) -> tuple[int, int, int]:
    if target_tokens <= 0:
        return 0, 0, 0

    email_provider = str(pick_conf(conf, "email", "provider", default="cloudflare") or "cloudflare").lower()
    if email_provider == "duckmail":
        duckmail_bearer = str(
            pick_conf(conf, "email", "duckmail_bearer", default=conf.get("duckmail_bearer", "")) or ""
        ).strip()
        if not duckmail_bearer:
            logger.error("duckmail_bearer 未配置，无法创建 DuckMail 临时邮箱。")
            return 0, 0, 0
    elif email_provider == "freemail":
        freemail_bearer = str(
            pick_conf(conf, "email", "freemail_bearer", default=conf.get("freemail_bearer", "")) or ""
        ).strip()
        if not freemail_bearer:
            logger.error("freemail_bearer 未配置，无法创建 Freemail 临时邮箱。")
            return 0, 0, 0
    else:
        if not pick_conf(conf, "email", "admin_password", default=""):
            logger.error("email.admin_password 未配置，无法创建临时邮箱。")
            return 0, 0, 0

    runtime = RegisterRuntime(conf=conf, target_tokens=target_tokens, logger=logger)
    workers = runtime.concurrent_workers

    logger.info(
        "开始补号: 目标 token=%s, 并发=%s, 邮箱提供者=%s",
        target_tokens,
        workers,
        runtime.email_provider,
    )
    if runtime.email_provider == "duckmail":
        logger.info("DuckMail API: %s", runtime.duckmail_api_base)
    elif runtime.email_provider == "freemail":
        logger.info("Freemail API: %s", runtime.freemail_api_base)
    else:
        logger.info("Worker域名=%s, 邮箱后缀=%s", runtime.worker_domain, ",".join(runtime.email_domains))

    ok = 0
    fail = 0
    skip = 0
    attempts = 0
    reg_times: List[float] = []
    total_times: List[float] = []
    lock = threading.Lock()
    batch_start = time.time()

    if workers == 1:
        while runtime.get_token_success_count() < target_tokens:
            attempts += 1
            email, success, t_reg, t_total = register_one(runtime, worker_id=1)
            if success is True:
                ok += 1
                reg_times.append(t_reg)
                total_times.append(t_total)
            elif success is False:
                fail += 1
            else:
                skip += 1
            logger.info(
                "补号进度: token %s/%s | OK=%s FAIL=%s SKIP=%s | 用时 %.1fs",
                runtime.get_token_success_count(),
                target_tokens,
                ok,
                fail,
                skip,
                time.time() - batch_start,
            )
            if runtime.get_token_success_count() >= target_tokens:
                break
            time.sleep(random.randint(2, 6))
    else:
        def worker_task(task_index: int, worker_id: int):
            if task_index > 1:
                jitter = random.uniform(0.5, 2.0) * worker_id
                time.sleep(jitter)
            if runtime.stop_event.is_set() and runtime.get_token_success_count() >= target_tokens:
                return task_index, None, None, 0.0, 0.0
            email, success, t_reg, t_total = register_one(runtime, worker_id=worker_id)
            return task_index, email, success, t_reg, t_total

        executor = ThreadPoolExecutor(max_workers=workers)
        futures = {}
        next_task_index = 1

        def submit_one() -> bool:
            nonlocal next_task_index
            remaining = target_tokens - runtime.get_token_success_count()
            if remaining <= 0:
                return False
            if len(futures) >= remaining:
                return False

            wid = ((next_task_index - 1) % workers) + 1
            fut = executor.submit(worker_task, next_task_index, wid)
            futures[fut] = next_task_index
            next_task_index += 1
            return True

        try:
            for _ in range(min(workers, target_tokens)):
                if not submit_one():
                    break

            while futures:
                if runtime.get_token_success_count() >= target_tokens:
                    runtime.stop_event.set()
                    break

                done_set, _ = wait(list(futures.keys()), return_when=FIRST_COMPLETED, timeout=1.0)
                if not done_set:
                    continue

                for fut in done_set:
                    _ = futures.pop(fut, None)
                    attempts += 1
                    try:
                        _, _, success, t_reg, t_total = fut.result()
                    except Exception:
                        success, t_reg, t_total = False, 0.0, 0.0

                    with lock:
                        if success is True:
                            ok += 1
                            reg_times.append(t_reg)
                            total_times.append(t_total)
                        elif success is False:
                            fail += 1
                        else:
                            skip += 1

                        logger.info(
                            "补号进度: token %s/%s | OK=%s FAIL=%s SKIP=%s | 用时 %.1fs",
                            runtime.get_token_success_count(),
                            target_tokens,
                            ok,
                            fail,
                            skip,
                            time.time() - batch_start,
                        )

                    if runtime.get_token_success_count() < target_tokens:
                        submit_one()
        finally:
            runtime.stop_event.set()
            for f in list(futures.keys()):
                f.cancel()
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                executor.shutdown(wait=False)

    synced = runtime.reconcile_account_outputs_from_tokens()
    elapsed = time.time() - batch_start
    avg_reg = (sum(reg_times) / len(reg_times)) if reg_times else 0
    avg_total = (sum(total_times) / len(total_times)) if total_times else 0
    logger.info(
        "补号完成: token=%s/%s, fail=%s, skip=%s, attempts=%s, elapsed=%.1fs, avg(注册)=%.1fs, avg(总)=%.1fs, 收敛账号=%s",
        runtime.get_token_success_count(),
        target_tokens,
        fail,
        skip,
        attempts,
        elapsed,
        avg_reg,
        avg_total,
        synced,
    )
    return runtime.get_token_success_count(), fail, synced


def fetch_auth_files(base_url: str, token: str, timeout: int) -> List[Dict[str, Any]]:
    resp = requests.get(f"{base_url}/v0/management/auth-files", headers=mgmt_headers(token), timeout=timeout)
    resp.raise_for_status()
    raw = resp.json()
    data = raw if isinstance(raw, dict) else {}
    files = data.get("files", [])
    return files if isinstance(files, list) else []


def build_probe_payload(auth_index: str, user_agent: str, chatgpt_account_id: Optional[str] = None) -> Dict[str, Any]:
    call_header = {
        "Authorization": "Bearer $TOKEN$",
        "Content-Type": "application/json",
        "User-Agent": user_agent or DEFAULT_MGMT_UA,
    }
    if chatgpt_account_id:
        call_header["Chatgpt-Account-Id"] = chatgpt_account_id
    return {
        "authIndex": auth_index,
        "method": "GET",
        "url": "https://chatgpt.com/backend-api/wham/usage",
        "header": call_header,
    }


async def probe_account_async(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    base_url: str,
    token: str,
    item: Dict[str, Any],
    user_agent: str,
    timeout: int,
    retries: int,
    min_weekly_remaining_percent: float,
) -> Dict[str, Any]:
    auth_index = item.get("auth_index")
    name = item.get("name") or item.get("id")
    account = item.get("account") or item.get("email") or ""
    result = {
        "name": name,
        "account": account,
        "auth_index": auth_index,
        "type": get_item_type(item),
        "provider": item.get("provider"),
        "status_code": None,
        "invalid_401": False,
        "weekly_remaining_percent": None,
        "low_weekly_quota": False,
        "error": None,
    }
    if not auth_index:
        result["error"] = "missing auth_index"
        return result

    chatgpt_account_id = extract_chatgpt_account_id(item)
    payload = build_probe_payload(str(auth_index), user_agent, chatgpt_account_id)

    for attempt in range(retries + 1):
        try:
            async with semaphore:
                async with session.post(
                    f"{base_url}/v0/management/api-call",
                    headers={**mgmt_headers(token), "Content-Type": "application/json"},
                    json=payload,
                    timeout=timeout,
                ) as resp:
                    text = await resp.text()
                    if resp.status >= 400:
                        raise RuntimeError(f"management api-call http {resp.status}: {text[:200]}")
                    data = safe_json_text(text)
                    sc = data.get("status_code")
                    result["status_code"] = sc
                    result["invalid_401"] = sc == 401
                    remaining = extract_weekly_remaining_percent(data)
                    result["weekly_remaining_percent"] = remaining
                    if (
                        sc == 200
                        and remaining is not None
                        and min_weekly_remaining_percent >= 0
                        and remaining < min_weekly_remaining_percent
                    ):
                        result["low_weekly_quota"] = True
                    if sc is None:
                        result["error"] = "missing status_code in api-call response"
                    return result
        except Exception as e:
            result["error"] = str(e)
            if attempt >= retries:
                return result
    return result


async def delete_account_async(
    session: aiohttp.ClientSession,
    semaphore: asyncio.Semaphore,
    base_url: str,
    token: str,
    name: str,
    timeout: int,
) -> Dict[str, Any]:
    if not name:
        return {"name": None, "deleted": False, "error": "missing name"}
    encoded_name = quote(name, safe="")
    url = f"{base_url}/v0/management/auth-files?name={encoded_name}"
    try:
        async with semaphore:
            async with session.delete(url, headers=mgmt_headers(token), timeout=timeout) as resp:
                text = await resp.text()
                data = safe_json_text(text)
                ok = resp.status == 200 and data.get("status") == "ok"
                return {
                    "name": name,
                    "deleted": ok,
                    "status_code": resp.status,
                    "error": None if ok else f"delete failed, response={text[:200]}",
                }
    except Exception as e:
        return {"name": name, "deleted": False, "error": str(e)}


async def run_probe_async(
    base_url: str,
    token: str,
    target_type: str,
    workers: int,
    timeout: int,
    retries: int,
    user_agent: str,
    min_weekly_remaining_percent: float,
    logger: Optional[logging.Logger] = None,
) -> tuple[List[Dict[str, Any]], int, int]:
    files = fetch_auth_files(base_url, token, timeout)
    candidates: List[Dict[str, Any]] = []
    for f in files:
        if str(get_item_type(f)).lower() != target_type.lower():
            continue
        candidates.append(f)

    if not candidates:
        return [], len(files), 0

    connector = aiohttp.TCPConnector(limit=max(1, workers), limit_per_host=max(1, workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    semaphore = asyncio.Semaphore(max(1, workers))

    probe_results = []
    total_candidates = len(candidates)
    checked = 0
    invalid_count = 0
    low_quota_count = 0

    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
        tasks = [
            asyncio.create_task(
                probe_account_async(
                    session=session,
                    semaphore=semaphore,
                    base_url=base_url,
                    token=token,
                    item=item,
                    user_agent=user_agent,
                    timeout=timeout,
                    retries=retries,
                    min_weekly_remaining_percent=min_weekly_remaining_percent,
                )
            )
            for item in candidates
        ]
        for task in asyncio.as_completed(tasks):
            result = await task
            probe_results.append(result)
            checked += 1
            if result.get("invalid_401"):
                invalid_count += 1
            if result.get("low_weekly_quota"):
                low_quota_count += 1

            if logger and (checked % 50 == 0 or checked == total_candidates):
                logger.info(
                    "探测进度: 已检查=%s/%s, 命中401=%s, 周剩余<%.1f%%=%s",
                    checked,
                    total_candidates,
                    invalid_count,
                    min_weekly_remaining_percent,
                    low_quota_count,
                )

    to_delete = [r for r in probe_results if r.get("invalid_401") or r.get("low_weekly_quota")]
    return to_delete, len(files), len(candidates)


async def run_delete_async(
    base_url: str,
    token: str,
    names_to_delete: List[str],
    delete_workers: int,
    timeout: int,
) -> tuple[int, int]:
    if not names_to_delete:
        return 0, 0

    connector = aiohttp.TCPConnector(limit=max(1, delete_workers), limit_per_host=max(1, delete_workers))
    client_timeout = aiohttp.ClientTimeout(total=max(1, timeout))
    semaphore = asyncio.Semaphore(max(1, delete_workers))

    delete_results = []
    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout, trust_env=True) as session:
        tasks = [
            asyncio.create_task(
                delete_account_async(
                    session=session,
                    semaphore=semaphore,
                    base_url=base_url,
                    token=token,
                    name=name,
                    timeout=timeout,
                )
            )
            for name in names_to_delete
        ]
        for task in asyncio.as_completed(tasks):
            delete_results.append(await task)

    success = [r for r in delete_results if r.get("deleted")]
    failed = [r for r in delete_results if not r.get("deleted")]
    return len(success), len(failed)


async def run_clean_401_async(
    *,
    base_url: str,
    token: str,
    target_type: str,
    workers: int,
    delete_workers: int,
    timeout: int,
    retries: int,
    user_agent: str,
    min_weekly_remaining_percent: float,
    logger: logging.Logger,
) -> tuple[int, int, int, int]:
    to_delete, total_files, codex_files = await run_probe_async(
        base_url=base_url,
        token=token,
        target_type=target_type,
        workers=workers,
        timeout=timeout,
        retries=retries,
        user_agent=user_agent,
        min_weekly_remaining_percent=min_weekly_remaining_percent,
        logger=logger,
    )
    invalid_401 = [r for r in to_delete if r.get("invalid_401")]
    low_quota = [r for r in to_delete if r.get("low_weekly_quota")]
    names = list(dict.fromkeys(str(r.get("name")) for r in to_delete if r.get("name")))
    logger.info(
        "探测完成: 总账号=%s, codex账号=%s, 401失效=%s, 周剩余<%.1f%%=%s, 待删除=%s",
        total_files,
        codex_files,
        len(invalid_401),
        min_weekly_remaining_percent,
        len(low_quota),
        len(names),
    )

    deleted_ok, deleted_fail = await run_delete_async(
        base_url=base_url,
        token=token,
        names_to_delete=names,
        delete_workers=delete_workers,
        timeout=timeout,
    )
    logger.info("删除完成: 成功=%s, 失败=%s", deleted_ok, deleted_fail)
    return len(invalid_401), len(low_quota), deleted_ok, deleted_fail


def run_clean_401(conf: Dict[str, Any], logger: logging.Logger) -> tuple[int, int, int, int]:
    if aiohttp is None:
        raise RuntimeError("未安装 aiohttp，请先安装: pip install aiohttp")

    base_url = str(pick_conf(conf, "clean", "base_url", default="") or "").rstrip("/")
    token = str(pick_conf(conf, "clean", "token", "cpa_password", default="") or "").strip()
    target_type = str(pick_conf(conf, "clean", "target_type", default="codex") or "codex")
    workers = int(pick_conf(conf, "clean", "workers", default=20) or 20)
    delete_workers = int(pick_conf(conf, "clean", "delete_workers", default=40) or 40)
    timeout = int(pick_conf(conf, "clean", "timeout", default=10) or 10)
    retries = int(pick_conf(conf, "clean", "retries", default=1) or 1)
    user_agent = str(pick_conf(conf, "clean", "user_agent", default=DEFAULT_MGMT_UA) or DEFAULT_MGMT_UA)
    min_weekly_remaining_percent = float(
        pick_conf(conf, "clean", "min_weekly_remaining_percent", "weekly_remaining_min_percent", default=10) or 10
    )
    if min_weekly_remaining_percent < 0:
        min_weekly_remaining_percent = 0.0
    if min_weekly_remaining_percent > 100:
        min_weekly_remaining_percent = 100.0

    if not base_url or not token:
        raise RuntimeError("clean 配置缺少 base_url 或 token/cpa_password")

    logger.info(
        "开始清理账号: base_url=%s target_type=%s (401 + 周剩余<%.1f%%)",
        base_url,
        target_type,
        min_weekly_remaining_percent,
    )
    return asyncio.run(
        run_clean_401_async(
            base_url=base_url,
            token=token,
            target_type=target_type,
            workers=workers,
            delete_workers=delete_workers,
            timeout=timeout,
            retries=retries,
            user_agent=user_agent,
            min_weekly_remaining_percent=min_weekly_remaining_percent,
            logger=logger,
        )
    )


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_cfg = script_dir / "config.json"
    default_log_dir = script_dir / "logs"

    parser = argparse.ArgumentParser(description="账号池自动维护（三合一：清理+补号+收敛）")
    parser.add_argument("--config", default=str(default_cfg), help="统一配置文件路径")
    parser.add_argument(
        "--min-candidates",
        type=int,
        default=None,
        help="候选账号最小阈值（默认读取 maintainer.min_candidates / 顶层 min_candidates，最终默认 100）",
    )
    parser.add_argument("--timeout", type=int, default=15, help="统计 candidates 时接口超时秒数")
    parser.add_argument("--log-dir", default=str(default_log_dir), help="日志目录")
    return parser.parse_args()


def main() -> int:
    requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

    args = parse_args()
    config_path = Path(args.config).resolve()
    logger, log_path = setup_logger(Path(args.log_dir).resolve())
    logger.info("=== 账号池自动维护开始（二合一）===")
    logger.info("配置文件: %s", config_path)
    logger.info("日志文件: %s", log_path)

    if not config_path.exists():
        logger.error("配置文件不存在: %s", config_path)
        return 2

    conf = load_json(config_path)

    base_url = str(pick_conf(conf, "clean", "base_url", default="") or "").rstrip("/")
    token = str(pick_conf(conf, "clean", "token", "cpa_password", default="") or "").strip()
    target_type = str(pick_conf(conf, "clean", "target_type", default="codex") or "codex")

    cfg_min_candidates = pick_conf(conf, "maintainer", "min_candidates", default=None)
    if cfg_min_candidates is None:
        cfg_min_candidates = conf.get("min_candidates")

    if args.min_candidates is not None:
        min_candidates = int(args.min_candidates)
    elif cfg_min_candidates is not None:
        min_candidates = int(cfg_min_candidates)
    else:
        min_candidates = 100

    if min_candidates < 0:
        logger.error("min_candidates 不能小于 0（当前值=%s）", min_candidates)
        return 2
    if not base_url or not token:
        logger.error("缺少 clean.base_url 或 clean.token/cpa_password")
        return 2

    try:
        probed_401, probed_low_quota, deleted_ok, deleted_fail = run_clean_401(conf, logger)
        logger.info(
            "清理阶段汇总: 401命中=%s, 周剩余不足命中=%s, 删除成功=%s, 删除失败=%s",
            probed_401,
            probed_low_quota,
            deleted_ok,
            deleted_fail,
        )
    except Exception as e:
        logger.error("清理账号失败: %s", e)
        logger.info("=== 账号池自动维护结束（失败）===")
        return 3

    try:
        total_after_clean, candidates_after_clean = get_candidates_count(
            base_url=base_url,
            token=token,
            target_type=target_type,
            timeout=args.timeout,
        )
    except Exception as e:
        logger.error("删除后统计失败: %s", e)
        logger.info("=== 账号池自动维护结束（失败）===")
        return 4

    logger.info(
        "清理后统计: 总账号=%s, candidates=%s, 阈值=%s",
        total_after_clean,
        candidates_after_clean,
        min_candidates,
    )

    if candidates_after_clean >= min_candidates:
        logger.info("当前 candidates 已达标，无需补号。")
        logger.info("=== 账号池自动维护结束（成功）===")
        return 0

    gap = min_candidates - candidates_after_clean
    logger.info("当前 candidates 未达标，缺口=%s，开始补号。", gap)

    try:
        filled, failed, synced = run_batch_register(conf=conf, target_tokens=gap, logger=logger)
        logger.info("补号阶段汇总: 成功token=%s, 失败=%s, 收敛账号=%s", filled, failed, synced)
    except Exception as e:
        logger.error("补号阶段失败: %s", e)
        logger.info("=== 账号池自动维护结束（失败）===")
        return 5

    try:
        total_final, candidates_final = get_candidates_count(
            base_url=base_url,
            token=token,
            target_type=target_type,
            timeout=args.timeout,
        )
    except Exception as e:
        logger.error("补号后统计失败: %s", e)
        logger.info("=== 账号池自动维护结束（失败）===")
        return 6

    logger.info(
        "补号后统计: 总账号=%s, codex账号=%s, codex目标=%s",
        total_final,
        candidates_final,
        min_candidates,
    )
    if candidates_final < min_candidates:
        logger.warning("最终 codex账号数 仍低于阈值，请检查邮箱/OAuth/上传链路。")
    logger.info("=== 账号池自动维护结束（成功）===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
