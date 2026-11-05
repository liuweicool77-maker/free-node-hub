"""云端真实代理探测。

做法：在构建机上起一个真实的 Mihomo 内核，把候选节点装进一个临时 provider，
再通过内核自带的 RESTful API 逐个做 **真实 HTTP 代理请求**
（GET /proxies/<name>/delay?url=<204 探测点>）。

这比 TCP 握手可靠得多——TCP 能连上但代理不通的节点非常常见。
但它只能证明"从构建机可达"，**不能**代替本机可用性判断，
所以产物里只保留探测通过的节点，并在 stats 中标注探测来源。
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from common import LOG

PROBE_URL = "http://www.gstatic.com/generate_204"
PROBE_GROUP = "PROBE"
SECRET = "fnh-probe"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _api(port: int, path: str, timeout: float = 10.0):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers={"Authorization": f"Bearer {SECRET}"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


class Prober:
    def __init__(self, mihomo: str, workdir: str | None = None):
        # 必须绝对路径：下面会用 cwd=临时目录启动子进程，相对路径会解析到错误位置
        self.mihomo = os.path.abspath(mihomo)
        self._tmp = workdir or tempfile.mkdtemp(prefix="fnh-probe-")
        self._own_tmp = workdir is None
        self.proc: subprocess.Popen | None = None
        self.port = _free_port()

    def start(self, proxies: list[dict], start_timeout: float = 20.0) -> None:
        os.makedirs(self._tmp, exist_ok=True)

        # 直接把候选节点内联进配置，不用 file provider：
        # 实测在 CI 的 Linux 内核上 file provider 一个节点都没注册上（只看到内置 PASS-RULE），
        # 而内联 proxies 与 -t 校验走的是同一条已被验证的路径，行为确定。
        names = [p["name"] for p in proxies]
        cfg = {
            "mixed-port": _free_port(),
            "mode": "rule",
            "log-level": "info",
            "ipv6": False,
            "external-controller": f"127.0.0.1:{self.port}",
            "secret": SECRET,
            "unified-delay": True,
            "proxies": proxies,
            "proxy-groups": [{"name": PROBE_GROUP, "type": "select", "proxies": names}],
            "rules": [f"MATCH,{PROBE_GROUP}"],
            "profile": {"store-selected": False},
        }
        cfg_path = os.path.join(self._tmp, "probe-config.yaml")
        with open(cfg_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=1)

        log_path = os.path.join(self._tmp, "core.log")
        self.log_path = log_path
        log_file = open(log_path, "w", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen(
            [self.mihomo, "-d", self._tmp, "-f", cfg_path],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            cwd=self._tmp,
        )

        deadline = time.time() + start_timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("Mihomo 探测内核提前退出，见 core.log")
            try:
                _api(self.port, "/version", timeout=2)
                return
            except Exception:
                time.sleep(0.4)
        raise RuntimeError("Mihomo 探测内核启动超时")

    def proxy_names(self) -> list[str]:
        data = _api(self.port, "/proxies")
        skip = {
            "DIRECT", "REJECT", "REJECT-DROP", "PASS", "PASS-RULE", "COMPATIBLE",
            "GLOBAL", PROBE_GROUP,
        }
        return [n for n in data.get("proxies", {}) if n not in skip]

    def wait_ready(self, expected: int, timeout: float = 60.0) -> list[str]:
        """等 provider 把节点真正注册进内核。

        内核的 /version 会在节点全部装载之前就可用，直接读 /proxies 可能只拿到
        一两条，导致后面"探测了 1 个节点"。这里轮询到节点数达标或超时。
        """
        deadline = time.time() + timeout
        best: list[str] = []
        while time.time() < deadline:
            names = self.proxy_names()
            if len(names) >= expected:
                return names
            if len(names) > len(best):
                best = names
            time.sleep(1.0)
        LOG.warning(
            "探测内核只注册了 %d/%d 个节点（超时 %.0fs），已注册样本: %s",
            len(best), expected, timeout, ", ".join(best[:5]) or "(空)",
        )
        return best

    def log_tail(self, lines: int = 40) -> str:
        """把探测内核的日志尾部取出来，用于失败诊断。"""
        try:
            with open(self.log_path, encoding="utf-8", errors="replace") as f:
                tail = f.readlines()[-lines:]
            from common import scrub
            return scrub("".join(tail)).strip()
        except Exception:
            return "(无内核日志)"

    def _delay(self, name: str, timeout_ms: int) -> int | None:
        q = urllib.parse.urlencode({"timeout": timeout_ms, "url": PROBE_URL})
        path = f"/proxies/{urllib.parse.quote(name, safe='')}/delay?{q}"
        try:
            d = _api(self.port, path, timeout=timeout_ms / 1000 + 5)
            v = d.get("delay")
            return int(v) if isinstance(v, int) and v > 0 else None
        except Exception:
            return None

    def run(self, names: list[str], timeout_ms: int = 5000, workers: int = 16) -> dict[str, int]:
        LOG.info("真实代理探测：%d 个节点，并发 %d，单点超时 %dms", len(names), workers, timeout_ms)
        results: dict[str, int] = {}
        done = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for name, delay in zip(names, pool.map(lambda n: self._delay(n, timeout_ms), names)):
                done += 1
                if delay:
                    results[name] = delay
                if done % 100 == 0:
                    LOG.info("  已探测 %d/%d，通过 %d", done, len(names), len(results))
        LOG.info("探测完成：通过 %d / %d", len(results), len(names))
        return results

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self._own_tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()
        return False
