"""地区判定。

规则（对应需求 3.9）：
  * **只看 GeoIP 结果**，绝不从节点名/国旗 emoji 推断地区。实测证据：
    nodesradar 里名为 "Netherlands 001" 的 82.38.31.176，GeoIP 归属 GB。
  * 域名先 DNS 解析再查库；解析失败或库中无记录 → "UNKNOWN"。
  * 解析结果带 TTL 缓存，减少每轮重复 DNS。
"""

from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import json
import os
import socket
import time

from common import LOG

UNKNOWN = "UNKNOWN"

# ISO 3166-1 alpha-2（只作为"是不是真实国家码"的白名单，
# 防止 GeoIP 库把 GOOGLE / CLOUDFLARE 之类的运营商标签当成国家）
ISO2 = set("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT
MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW
SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG
UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
""".split())

CACHE_TTL = 7 * 24 * 3600


class GeoResolver:
    def __init__(self, mmdb_path: str, cache_path: str | None = None):
        import maxminddb

        self._fh = None
        try:
            self._db = maxminddb.open_database(mmdb_path)
        except (FileNotFoundError, OSError):
            # Windows 上 C 扩展对含非 ASCII 字符的绝对路径会失败，改用文件对象绕过
            self._fh = open(mmdb_path, "rb")
            self._db = maxminddb.open_database(self._fh)
        self._cache_path = cache_path
        self._cache: dict[str, dict] = {}
        if cache_path and os.path.exists(cache_path):
            try:
                with open(cache_path, encoding="utf-8") as f:
                    self._cache = json.load(f)
            except Exception:
                self._cache = {}

    def close(self) -> None:
        try:
            self._db.close()
        except Exception:
            pass
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:
                pass

    def save_cache(self) -> None:
        if not self._cache_path:
            return
        os.makedirs(os.path.dirname(self._cache_path) or ".", exist_ok=True)
        tmp = self._cache_path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(self._cache, f, ensure_ascii=False, indent=1, sort_keys=True)
        os.replace(tmp, self._cache_path)

    # ------------------------------------------------------------ 单点查询

    def _lookup_cc(self, ip: str) -> str | None:
        try:
            rec = self._db.get(ip)
        except Exception:
            return None
        if not rec:
            return None
        for key in ("country", "registered_country"):
            iso = ((rec.get(key) or {}).get("iso_code") or "").upper()
            if iso in ISO2:
                return iso
        return None

    @staticmethod
    def _resolve(host: str, timeout: float = 3.0) -> str | None:
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            for info in infos:
                addr = info[4][0]
                if ipaddress.ip_address(addr).is_global:
                    return addr
            return infos[0][4][0] if infos else None
        except Exception:
            return None
        finally:
            socket.setdefaulttimeout(old)

    def country(self, host: str) -> str:
        entry = self._cache.get(host)
        now = time.time()
        if entry and now - entry.get("ts", 0) < CACHE_TTL and entry.get("cc"):
            return entry["cc"]

        ip = self._resolve(host)
        if not ip:
            self._cache[host] = {"ip": None, "cc": UNKNOWN, "ts": now}
            return UNKNOWN
        cc = self._lookup_cc(ip) or UNKNOWN
        self._cache[host] = {"ip": ip, "cc": cc, "ts": now}
        return cc

    def country_of_ip(self, ip: str) -> str:
        return self._lookup_cc(ip) or UNKNOWN

    # ------------------------------------------------------------ 批量

    def classify(self, hosts: list[str], workers: int = 32) -> dict[str, str]:
        """并发判定一批 server 的地区，返回 {host: cc}。"""
        uniq = sorted({h for h in hosts if h})
        out: dict[str, str] = {}

        def work(h: str) -> tuple[str, str]:
            try:
                return h, self.country(h)
            except Exception:
                return h, UNKNOWN

        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            for h, cc in pool.map(work, uniq):
                out[h] = cc

        live = sum(1 for v in out.values() if v != UNKNOWN)
        LOG.info("地区判定：%d 个地址，%d 个已定位，%d 个 Unknown", len(uniq), live, len(uniq) - live)
        return out
