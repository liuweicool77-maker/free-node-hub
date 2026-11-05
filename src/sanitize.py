"""节点定义清洗与校验。

设计原则（对应需求 3.5 / 3.6 / 3.7）：
  * **白名单**而非黑名单：只保留明确列出的字段，其余一律丢弃。
    这样上游新增任何"能改变客户端行为"的字段（dialer-proxy / interface-name /
    routing-mark / script / 自定义 plugin 等）都不会被带进我们的产物。
  * 永不输出 skip-cert-verify，也不因为节点"跳过校验才能用"而放宽 TLS。
  * 校验失败抛 Reject(原因码)，由调用方统计，方便定位是哪个源在退化。

本模块不发起任何网络请求，纯函数，便于单测。
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# ---------------------------------------------------------------- 允许的协议

TYPE_FIELDS: dict[str, set[str]] = {
    "ss": {"cipher", "password", "plugin", "plugin-opts"},
    "ssr": {"cipher", "password", "obfs", "protocol", "obfs-param", "protocol-param"},
    "vmess": {
        "uuid", "alterId", "cipher", "tls", "servername", "network",
        "ws-opts", "grpc-opts", "h2-opts", "http-opts", "reality-opts",
        "client-fingerprint", "alpn", "packet-encoding", "global-padding",
    },
    "vless": {
        "uuid", "flow", "tls", "servername", "network", "ws-opts", "grpc-opts",
        "reality-opts", "client-fingerprint", "alpn", "packet-encoding", "encryption",
    },
    "trojan": {
        "password", "sni", "alpn", "network", "ws-opts", "grpc-opts",
        "client-fingerprint",
    },
    "hysteria2": {"password", "obfs", "obfs-password", "sni", "alpn", "up", "down", "ports"},
    "hysteria": {"auth-str", "obfs", "sni", "alpn", "up", "down", "protocol", "ports"},
    "http": {"username", "password", "tls", "sni"},
    "socks5": {"username", "password", "tls", "sni"},
}

# 永远不进入产物的字段（即使将来被误加进白名单）
NEVER_ALLOW = {
    "skip-cert-verify", "dialer-proxy", "interface-name", "routing-mark",
    "smux", "name", "type", "server", "port",
}

TLS_TYPES = {"trojan", "hysteria2", "hysteria"}
SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "rc4-md5", "chacha20-ietf", "xchacha20", "none",
}
VMESS_CIPHERS = {"auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"}
FINGERPRINTS = {
    "chrome", "firefox", "safari", "ios", "android", "edge",
    "360", "qq", "random",
}
ALPN_ALLOWED = {"h2", "http/1.1", "h3"}
NETWORKS = {"tcp", "ws", "grpc", "h2", "http"}
# Xray / sing-box 把 TCP 传输层叫 "raw"，语义等价，做规范化而不是丢弃
NETWORK_ALIASES = {"raw": "tcp", "": "tcp", "none": "tcp"}

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_BAD_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class Reject(Exception):
    """校验不通过。reason 是稳定短码，用于统计。"""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def unsupported_types(proxies: list[dict]) -> dict[str, int]:
    """发布前的最后一道协议检查：产物里不允许出现 allowlist 之外的协议。"""
    bad: dict[str, int] = {}
    for p in proxies:
        t = str(p.get("type", ""))
        if t not in TYPE_FIELDS:
            bad[t] = bad.get(t, 0) + 1
    return bad


# ---------------------------------------------------------------- 基础校验

def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "yes", "1"):
            return True
        if low in ("false", "no", "0"):
            return False
    return None


def _host(value: Any) -> str | None:
    """返回规范化主机名/字面量 IP；非法返回 None。"""
    if not isinstance(value, str):
        return None
    host = value.strip().strip("[]")
    if not host or len(host) > 253 or _BAD_CHARS.search(host):
        return None
    if " " in host or "/" in host:
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(host):
        return None
    if "." not in host:  # 单标签域名在公网不可解析，视为无效
        return None
    return host.lower().rstrip(".")


def is_public_ip(host: str) -> bool | None:
    """host 是 IP 时返回是否可用于公网；是域名返回 None。"""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


# ---------------------------------------------------------------- 各段校验

def _clean_alpn(value: Any) -> list[str] | None:
    if not isinstance(value, list):
        return None
    out = [str(x).strip().lower() for x in value if isinstance(x, str)]
    out = [x for x in out if x in ALPN_ALLOWED]
    return out or None


def _clean_ws_opts(value: Any) -> dict | None:
    if not isinstance(value, dict):
        return None
    opts: dict[str, Any] = {}
    path = value.get("path")
    if isinstance(path, str) and path.startswith("/") and len(path) <= 256:
        opts["path"] = path
    elif path is None:
        opts["path"] = "/"
    else:
        return None
    headers = value.get("headers")
    if isinstance(headers, dict):
        clean_headers = {}
        for k, v in headers.items():
            if not isinstance(k, str) or not isinstance(v, str):
                continue
            if _BAD_CHARS.search(k) or _BAD_CHARS.search(v):
                continue
            if len(k) > 64 or len(v) > 256:
                continue
            if k.lower() == "host":
                clean_headers["Host"] = v
        if clean_headers:
            opts["headers"] = clean_headers
    # early-data 只接受有限整数
    ed = _as_int(value.get("max-early-data"))
    if ed is not None and 0 < ed <= 65535:
        opts["max-early-data"] = ed
    return opts


def _clean_grpc_opts(value: Any) -> dict | None:
    if not isinstance(value, dict):
        return None
    name = value.get("grpc-service-name")
    if not isinstance(name, str) or not name.strip() or len(name) > 128:
        return None
    return {"grpc-service-name": name.strip()}


def _clean_reality(value: Any) -> dict | None:
    if not isinstance(value, dict):
        return None
    pk = value.get("public-key")
    if not isinstance(pk, str) or not pk.strip() or len(pk) > 256:
        return None
    out = {"public-key": pk.strip()}
    sid = value.get("short-id")
    if isinstance(sid, str) and re.fullmatch(r"[0-9a-fA-F]{0,16}", sid):
        out["short-id"] = sid
    return out


# ---------------------------------------------------------------- 主入口

def sanitize(raw: Any) -> tuple[dict, dict]:
    """把一条上游节点定义清洗成可安全写入产物的定义。

    返回 (clean, meta)。clean 不含 name（名称由发布阶段统一生成），
    meta 含 type/server/port 供去重与地理判定使用。
    校验失败抛 Reject。
    """
    if not isinstance(raw, dict):
        raise Reject("not_a_mapping")

    ptype = raw.get("type")
    if not isinstance(ptype, str) or ptype.strip().lower() not in TYPE_FIELDS:
        raise Reject("unsupported_type", str(ptype))
    ptype = ptype.strip().lower()

    server = _host(raw.get("server"))
    if not server:
        raise Reject("bad_server")
    public = is_public_ip(server)
    if public is False:
        raise Reject("private_or_reserved_ip")

    port = _as_int(raw.get("port"))
    if port is None or not (1 <= port <= 65535):
        raise Reject("bad_port")

    allowed = TYPE_FIELDS[ptype] - NEVER_ALLOW
    clean: dict[str, Any] = {"type": ptype, "server": server, "port": port}

    for key in allowed:
        if key not in raw:
            continue
        value = raw[key]
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue  # 空字符串一律当缺失，避免 sni:'' 之类破坏握手
        if key in ("tls", "udp"):
            b = _as_bool(value)
            if b is not None:
                clean[key] = b
            continue
        if key == "alpn":
            v = _clean_alpn(value)
            if v:
                clean[key] = v
            continue
        if key == "ws-opts":
            v = _clean_ws_opts(value)
            if v:
                clean[key] = v
            continue
        if key == "grpc-opts":
            v = _clean_grpc_opts(value)
            if v:
                clean[key] = v
            continue
        if key == "reality-opts":
            v = _clean_reality(value)
            if v:
                clean[key] = v
            continue
        if key in ("h2-opts", "http-opts", "plugin-opts"):
            if isinstance(value, dict):
                clean[key] = value
            continue
        if key == "client-fingerprint":
            cf = str(value).strip().lower()
            if cf in FINGERPRINTS:
                clean[key] = cf
            continue
        if key == "alterId":
            ai = _as_int(value)
            if ai is not None and 0 <= ai <= 65535:
                clean["alterId"] = ai
            continue
        if key == "flow":
            if value in ("xtls-rprx-vision", "xtls-rprx-vision-udp443"):
                clean["flow"] = value
            continue
        if isinstance(value, (str, int, float, bool)):
            clean[key] = value
        elif isinstance(value, list):
            clean[key] = [x for x in value if isinstance(x, (str, int, float))]

    _validate_common(clean, raw)
    _validate_by_type(clean)
    _validate_tls(clean, server)

    meta = {"type": ptype, "server": server, "port": port}
    return clean, meta


def _validate_common(clean: dict, raw: dict) -> None:
    # 协议名 / 密码类字段必须是可打印短字符串
    for key in ("password", "uuid", "auth-str", "obfs-password", "username", "cipher"):
        if key not in clean:
            continue
        if not isinstance(clean[key], str):
            clean[key] = str(clean[key])
        value = clean[key]
        if _BAD_CHARS.search(value) or len(value) > 512:
            raise Reject("bad_auth_field", key)

    network = clean.get("network")
    if network is not None:
        net = str(network).strip().lower()
        net = NETWORK_ALIASES.get(net, net)
        if net not in NETWORKS:
            raise Reject("bad_network", net[:24])
        if net == "tcp":
            clean.pop("network", None)
            for k in ("ws-opts", "grpc-opts", "h2-opts", "http-opts"):
                clean.pop(k, None)
        else:
            clean["network"] = net
            if net == "ws" and "ws-opts" not in clean:
                clean["ws-opts"] = {"path": "/"}
            if net == "grpc" and "grpc-opts" not in clean:
                raise Reject("grpc_without_service_name")
            if net == "h2" and "h2-opts" not in clean:
                raise Reject("h2_without_opts")
            if net == "http" and "http-opts" not in clean:
                raise Reject("http_without_opts")


def _validate_by_type(clean: dict) -> None:
    ptype = clean["type"]

    if ptype in ("vmess", "vless"):
        uuid = clean.get("uuid")
        if not isinstance(uuid, str) or not _UUID_RE.match(uuid):
            raise Reject("bad_uuid")
        if ptype == "vmess":
            cipher = str(clean.get("cipher", "auto")).strip().lower()
            if cipher not in VMESS_CIPHERS:
                raise Reject("bad_vmess_cipher", cipher)
            clean["cipher"] = cipher
            # 兼容上游 sni 写法：vmess 用 servername
            if "servername" not in clean and "sni" in clean:
                clean["servername"] = clean.pop("sni")

    elif ptype == "trojan":
        if not clean.get("password"):
            raise Reject("trojan_without_password")

    elif ptype == "ss":
        cipher = str(clean.get("cipher", "")).strip().lower()
        if cipher not in SS_CIPHERS:
            raise Reject("bad_ss_cipher", cipher)
        clean["cipher"] = cipher
        if not clean.get("password"):
            raise Reject("ss_without_password")

    elif ptype == "ssr":
        for key in ("cipher", "password", "obfs", "protocol"):
            if not clean.get(key):
                raise Reject("ssr_missing_field", key)

    elif ptype == "hysteria2":
        if not clean.get("password"):
            raise Reject("hysteria2_without_password")
        if "obfs" in clean and clean["obfs"] not in ("salamander",):
            clean.pop("obfs", None)
            clean.pop("obfs-password", None)

    elif ptype == "hysteria":
        if not clean.get("auth-str"):
            raise Reject("hysteria_without_auth")
        for key in ("up", "down"):
            if not clean.get(key):
                raise Reject("hysteria_missing_bandwidth", key)
        clean.setdefault("protocol", "udp")

    elif ptype in ("http", "socks5"):
        if clean.get("tls") is not True:
            # 明文 HTTP/SOCKS 代理会让链路内容对节点运营者可见，直接不收
            raise Reject("plaintext_proxy")

    # reality 必须配合 tls 与指纹
    if "reality-opts" in clean:
        clean["tls"] = True
        clean.setdefault("client-fingerprint", "chrome")


def _validate_tls(clean: dict, server: str) -> None:
    """TLS 参数合法性。绝不通过关闭证书校验来迁就不良节点。

    SNI 不可用时：若 server 是域名，直接去掉 sni 让内核回落到用域名做 SNI
    （这是正常行为，不会降低安全性）；若 server 是 IP，则证书几乎必然不匹配，
    直接剔除该节点。
    """
    ptype = clean["type"]
    needs_tls = ptype in TLS_TYPES or clean.get("tls") is True
    key = "sni" if ptype in ("trojan", "hysteria2", "hysteria", "http", "socks5") else "servername"

    raw_sni = clean.pop("sni", None)
    raw_ser = clean.pop("servername", None)
    candidate = raw_sni if isinstance(raw_sni, str) and raw_sni.strip() else raw_ser

    if isinstance(candidate, str) and candidate.strip():
        host = _host(candidate)
        if host:
            clean[key] = host
            return
        if needs_tls and is_public_ip(server) is not None:
            raise Reject("bad_sni", candidate[:32])

    if needs_tls and is_public_ip(server) is not None:
        raise Reject("tls_ip_without_sni")
