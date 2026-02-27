#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

STOP_REQUESTED = False
CHILD_PROC: Optional[subprocess.Popen[str]] = None


def now_str() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def safe_print(message: str) -> None:
    text = str(message)
    try:
        print(text, flush=True)
        return
    except UnicodeEncodeError:
        pass

    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    data = (text + "\n").encode(encoding, errors="replace")
    try:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except Exception:
        fallback = (text + "\n").encode("ascii", errors="replace").decode("ascii", errors="ignore")
        print(fallback, flush=True)


def log(message: str) -> None:
    safe_print(f"{now_str()} | [daemon] {message}")


def handle_stop_signal(signum: int, _frame) -> None:
    global STOP_REQUESTED, CHILD_PROC
    STOP_REQUESTED = True
    log(f"收到停止信号: {signum}")
    if CHILD_PROC is not None and CHILD_PROC.poll() is None:
        try:
            CHILD_PROC.terminate()
        except Exception as exc:
            log(f"停止子进程失败: {exc}")


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_cfg = script_dir / "config.json"

    parser = argparse.ArgumentParser(description="自动补号守护运行器（每轮执行清理+补号）")
    parser.add_argument("--config", default=str(default_cfg), help="统一配置文件路径")
    parser.add_argument("--target-active", type=int, required=True, help="维持活跃账号目标值")
    parser.add_argument("--interval-seconds", type=int, default=60, help="巡检间隔秒数，默认 60")
    parser.add_argument("--timeout", type=int, default=15, help="读取统计接口超时秒数")
    return parser.parse_args()


def main() -> int:
    global CHILD_PROC

    args = parse_args()
    if args.target_active <= 0:
        safe_print("target-active 必须大于 0")
        return 2
    if args.interval_seconds < 5:
        safe_print("interval-seconds 不能小于 5，已自动设置为 5")
        args.interval_seconds = 5
    if args.timeout <= 0:
        safe_print("timeout 必须大于 0")
        return 2

    script_dir = Path(__file__).resolve().parent
    config_path = Path(args.config).resolve()
    maintainer = (script_dir / "auto_pool_maintainer.py").resolve()
    if not config_path.exists():
        safe_print(f"配置文件不存在: {config_path}")
        return 2
    if not maintainer.exists():
        safe_print(f"维护脚本不存在: {maintainer}")
        return 2

    signal.signal(signal.SIGINT, handle_stop_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_stop_signal)

    log(
        f"守护任务启动: target_active={args.target_active}, interval={args.interval_seconds}s, "
        f"config={config_path}"
    )

    round_no = 0
    while not STOP_REQUESTED:
        round_no += 1
        log(f"第 {round_no} 轮开始")
        cmd = [
            sys.executable,
            str(maintainer),
            "--config",
            str(config_path),
            "--min-candidates",
            str(int(args.target_active)),
            "--timeout",
            str(int(args.timeout)),
        ]
        try:
            CHILD_PROC = subprocess.Popen(
                cmd,
                cwd=str(script_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
        except Exception as exc:
            log(f"启动维护脚本失败: {exc}")
            CHILD_PROC = None
            break

        if CHILD_PROC.stdout is not None:
            for raw in CHILD_PROC.stdout:
                line = raw.rstrip("\r\n")
                if line:
                    safe_print(line)
                if STOP_REQUESTED:
                    break
            try:
                CHILD_PROC.stdout.close()
            except Exception:
                pass

        if STOP_REQUESTED and CHILD_PROC.poll() is None:
            try:
                CHILD_PROC.terminate()
            except Exception:
                pass

        exit_code = CHILD_PROC.wait()
        CHILD_PROC = None
        log(f"第 {round_no} 轮结束，退出码={exit_code}")

        if STOP_REQUESTED:
            break

        log(f"等待 {args.interval_seconds}s 后进入下一轮")
        for _ in range(args.interval_seconds):
            if STOP_REQUESTED:
                break
            time.sleep(1)

    log("守护任务已停止")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
