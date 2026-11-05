"""FreeNode Hub 构建流水线。

    抓取 → 解析 → 清洗校验 → 去重 → 地理判定 → 配额裁剪 → 命名
         → 内核校验 → 真实探测 → 发布门禁 → 落盘

退出码：
    0  成功（产物已更新，或与上一版一致）
    2  发布门禁拦截（节点数异常下降 / 低于下限），保留旧版本
    3  内核校验失败，保留旧版本
    1  致命错误
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import time

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import LOG, fetch, fingerprint, write_json  # noqa: E402
from geo import UNKNOWN, GeoResolver  # noqa: E402
from sanitize import Reject, sanitize  # noqa: E402

EXIT_OK, EXIT_FATAL, EXIT_GATE, EXIT_INVALID = 0, 1, 2, 3

YAML_HEADER = (
    "# FreeNode Hub — 公开免费节点聚合产物\n"
    "# 由 GitHub Actions 自动生成，请勿手工编辑。\n"
    "# 仅包含顶层 proxies 字段；不含规则/DNS/TUN/脚本等任何可改变客户端行为的配置。\n"
    "# 上游来源见 dist/stats.json 与仓库 README。\n"
)


# ------------------------------------------------------------------ 抓取与解析

def load_sources(path: str) -> tuple[list[dict], dict]:
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    sources = [s for s in (doc.get("sources") or []) if s.get("enabled", True)]
    limits = doc.get("limits") or {}
    return sources, limits


def parse_proxies(payload: bytes) -> list[dict]:
    """只取 proxies。任何额外字段被彻底忽略——不合并、不执行。"""
    text = payload.decode("utf-8", "replace")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ValueError(f"YAML 解析失败: {str(e)[:200]}") from None
    if not isinstance(doc, dict):
        raise ValueError("订阅根节点不是映射（可能是 base64/URI 列表格式，本系统不采集）")
    proxies = doc.get("proxies")
    if not isinstance(proxies, list):
        raise ValueError("订阅中不存在 proxies 列表")
    return [p for p in proxies if isinstance(p, dict)]


# ------------------------------------------------------------------ 身份与命名

def identity(clean: dict) -> dict:
    """去重 / 命名的内部指纹输入：协议 + 端点 + 认证参数 + 传输层特征。"""
    keys = (
        "type", "server", "port", "uuid", "password", "username", "auth-str",
        "cipher", "network", "sni", "servername", "plugin",
    )
    base = {k: clean[k] for k in keys if k in clean}
    if "ws-opts" in clean:
        base["ws-path"] = clean["ws-opts"].get("path")
        base["ws-host"] = (clean["ws-opts"].get("headers") or {}).get("Host")
    if "grpc-opts" in clean:
        base["grpc"] = clean["grpc-opts"].get("grpc-service-name")
    return base


def make_name(cc: str, src: str, fp: str, used: set[str]) -> str:
    """名称 = FREE-<地区>-<来源>-<指纹前6位>，因此同一节点跨轮次名字稳定。"""
    for width in (6, 8, 10, 12):
        candidate = f"FREE-{cc}-{src}-{fp[:width]}"
        if candidate not in used:
            used.add(candidate)
            return candidate
    candidate = f"FREE-{cc}-{src}-{fp}"
    used.add(candidate)
    return candidate


# ------------------------------------------------------------------ 发布

def read_previous_total(path: str) -> int:
    if not os.path.exists(path):
        return 0
    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        return len(doc.get("proxies") or [])
    except Exception:
        return 0


def dump_proxies(path: str, proxies: list[dict]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    body = yaml.safe_dump(
        {"proxies": proxies},
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=1000,
        indent=2,
    )
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(YAML_HEADER)
        f.write(body)
    os.replace(tmp, path)


def build_summary(stats: dict) -> str:
    c = stats["counts"]
    lines = [
        "## FreeNode Hub 构建报告",
        "",
        f"- 生成时间：{stats['generated_at']}",
        f"- 发布节点数：**{c['published']}**（上一版 {stats['gate']['previous_total']}，门槛 {stats['gate']['threshold']}）",
        f"- 抓取 {c['raw']} → 清洗通过 {c['sanitized']} → 去重移除 {c['duplicates_removed']} "
        f"→ 配额后 {c['after_cap']} → 探测存活 {c['probed_alive']}",
        f"- 判定结果：`{stats['gate']['decision']}`",
        "",
        "### 各来源",
        "",
        "| 源 | 状态 | HTTP | 原始 | 采用 | 说明 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for s in stats["sources"]:
        lines.append(
            f"| {s['id']} ({s['name']}) | {'OK' if s['ok'] else 'FAIL'} | {s.get('http_status') or '-'} "
            f"| {s['raw_nodes']} | {s['kept_nodes']} | {s.get('error') or ''} |"
        )
    lines += ["", "### 地区分布", "", "| 地区 | 节点数 |", "| --- | --- |"]
    for cc, n in sorted(stats["by_region"].items(), key=lambda kv: -kv[1]):
        lines.append(f"| {cc} | {n} |")
    if stats["rejected_reasons"]:
        lines += ["", "### 剔除原因", "", "| 原因 | 次数 |", "| --- | --- |"]
        for r, n in sorted(stats["rejected_reasons"].items(), key=lambda kv: -kv[1]):
            lines.append(f"| `{r}` | {n} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default="config/sources.yaml")
    ap.add_argument("--out", default="dist/free-proxies.yaml")
    ap.add_argument("--stats", default="dist/stats.json")
    ap.add_argument("--summary", default="")
    ap.add_argument("--mmdb", default="Country.mmdb")
    ap.add_argument("--mihomo", default="")
    ap.add_argument("--geo-cache", default=".cache/geo.json")
    ap.add_argument("--no-probe", action="store_true")
    ap.add_argument("--probe-limit", type=int, default=600)
    ap.add_argument("--probe-workers", type=int, default=16)
    ap.add_argument("--probe-timeout", type=int, default=5000)
    ap.add_argument("--use-env-proxy", action="store_true", help="抓取时使用系统代理环境变量")
    ap.add_argument("--cache-dir", default=".cache/raw", help="源缓存目录，在线抓取失败时回退")
    ap.add_argument("--cache-max-age-h", type=float, default=48.0, help="缓存最大可用时长（小时）")
    ap.add_argument("--force", action="store_true", help="忽略数量下降门禁强制发布（仅排障）")
    args = ap.parse_args()

    sources, limits = load_sources(args.sources)
    total_max = int(limits.get("total_max", 600))
    min_publish = int(limits.get("min_publish", 20))
    min_ratio = float(limits.get("min_ratio_vs_previous", 0.5))
    LOG.info("来源 %d 个，总量上限 %d", len(sources), total_max)

    stats: dict = {
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool": "FreeNodeHub/1.0",
        "sources": [],
        "counts": {},
        "rejected_reasons": {},
        "by_region": {},
        "by_protocol": {},
        "probe": {"enabled": not args.no_probe},
        "gate": {},
        "validation": {},
    }
    reasons: dict[str, int] = stats["rejected_reasons"]

    # ---------------- 1. 抓取 + 清洗
    kept_by_source: dict[str, list[dict]] = {}
    raw_total = 0
    cache_dir = args.cache_dir
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)

    for src in sources:
        sid = src["id"]
        LOG.info("抓取 %s → %s", sid, src["url"])
        data, err, status = fetch(
            src["url"], timeout=60, max_bytes=8_000_000, retries=3,
            use_env_proxy=args.use_env_proxy,
        )
        entry = {
            "id": sid, "name": src.get("name", sid), "url": src["url"],
            "license": src.get("license", "unknown"),
            "ok": False, "http_status": status, "bytes": 0,
            "raw_nodes": 0, "kept_nodes": 0, "error": None, "from_cache": False,
        }

        cache_path = os.path.join(cache_dir, f"{sid}.yaml") if cache_dir else ""
        if data is None and cache_path and os.path.exists(cache_path):
            age_h = (time.time() - os.path.getmtime(cache_path)) / 3600
            if age_h <= args.cache_max_age_h:
                with open(cache_path, "rb") as f:
                    data = f.read()
                entry["from_cache"] = True
                entry["cache_age_h"] = round(age_h, 1)
                LOG.warning("  %s 在线抓取失败（%s），回退到 %.1f 小时前的缓存", sid, err, age_h)

        if data is None:
            entry["error"] = err
            LOG.warning("  %s 抓取失败：%s", sid, err)
            stats["sources"].append(entry)
            kept_by_source[sid] = []
            continue

        if not entry["from_cache"] and cache_path:
            try:
                with open(cache_path, "wb") as f:
                    f.write(data)
            except Exception as e:  # 缓存写失败不影响主流程
                LOG.warning("  %s 缓存写入失败：%s", sid, e)

        entry["bytes"] = len(data)
        try:
            raw_nodes = parse_proxies(data)
        except ValueError as e:
            entry["error"] = str(e)
            LOG.warning("  %s 解析失败：%s", sid, e)
            stats["sources"].append(entry)
            kept_by_source[sid] = []
            continue

        entry["raw_nodes"] = len(raw_nodes)
        raw_total += len(raw_nodes)

        clean_list: list[dict] = []
        src_reasons: dict[str, int] = {}
        for raw in raw_nodes:
            try:
                clean, _meta = sanitize(raw)
            except Reject as r:
                src_reasons[r.reason] = src_reasons.get(r.reason, 0) + 1
                reasons[r.reason] = reasons.get(r.reason, 0) + 1
                continue
            clean_list.append(clean)

        # 源内去重
        seen: set[str] = set()
        uniq: list[dict] = []
        for c in clean_list:
            fp = fingerprint(identity(c))
            if fp in seen:
                continue
            seen.add(fp)
            uniq.append(c)

        cap = int(src.get("max_nodes", total_max))
        if len(uniq) > cap:
            LOG.info("  %s 超出单源配额，%d → %d", sid, len(uniq), cap)
            uniq = uniq[:cap]

        kept_by_source[sid] = uniq
        entry["ok"] = True
        entry["kept_nodes"] = len(uniq)
        if src_reasons:
            entry["rejected"] = dict(sorted(src_reasons.items(), key=lambda kv: -kv[1])[:6])
        LOG.info("  %s：原始 %d，清洗后 %d，去重后 %d，配额后 %d",
                 sid, len(raw_nodes), len(clean_list), len(seen), len(uniq))
        stats["sources"].append(entry)

    sanitized_total = sum(len(v) for v in kept_by_source.values())
    if sanitized_total == 0:
        LOG.error("所有来源均无有效节点，拒绝发布")
        stats["counts"] = {"raw": raw_total, "sanitized": 0, "duplicates_removed": 0,
                           "after_cap": 0, "probed_alive": 0, "published": 0}
        stats["gate"] = {"previous_total": read_previous_total(args.out),
                         "threshold": min_publish, "decision": "blocked_no_nodes"}
        write_json(args.stats, stats)
        return EXIT_GATE

    # ---------------- 2. 跨源去重
    seen_fp: set[str] = set()
    merged: list[tuple[str, dict]] = []
    dup = 0
    for src in sources:
        for c in kept_by_source.get(src["id"], []):
            fp = fingerprint(identity(c))
            if fp in seen_fp:
                dup += 1
                continue
            seen_fp.add(fp)
            merged.append((src["id"], c))
    LOG.info("跨源去重：移除 %d，剩余 %d", dup, len(merged))

    # ---------------- 3. 地区判定（GeoIP，绝不看节点名）
    resolver = GeoResolver(args.mmdb, args.geo_cache)
    try:
        cc_map = resolver.classify([c["server"] for _, c in merged])
    finally:
        resolver.save_cache()

    # ---------------- 4. 全局配额（按源轮转，保持来源多样性）
    if len(merged) > total_max:
        buckets: dict[str, list[tuple[str, dict]]] = {}
        for sid, c in merged:
            buckets.setdefault(sid, []).append((sid, c))
        picked: list[tuple[str, dict]] = []
        idx = 0
        while len(picked) < total_max and any(len(v) > idx for v in buckets.values()):
            for sid, items in buckets.items():
                if len(picked) >= total_max:
                    break
                if len(items) > idx:
                    picked.append(items[idx])
            idx += 1
        merged = picked
        LOG.info("全局配额裁剪至 %d", len(merged))

    # ---------------- 5. 命名
    used_names: set[str] = set()
    named: list[dict] = []
    for sid, c in merged:
        cc = cc_map.get(c["server"], UNKNOWN)
        fp = fingerprint(identity(c))
        proxy = {"name": make_name(cc, sid, fp, used_names)}
        proxy.update(c)
        named.append(proxy)

    # ---------------- 6. 内核校验
    vok, vmsg = (True, "skipped: 未提供内核路径")
    if args.mihomo:
        from validate import validate_proxies
        vok, vmsg = validate_proxies(args.mihomo, named)
        LOG.info("内核校验：%s", "通过" if vok else "失败")
        if not vok:
            LOG.error(vmsg)
    stats["validation"] = {"ok": vok, "message": vmsg[-1500:]}
    if not vok:
        stats["counts"] = {"raw": raw_total, "sanitized": sanitized_total, "duplicates_removed": dup,
                           "after_cap": len(named), "probed_alive": 0, "published": 0}
        stats["gate"] = {"previous_total": read_previous_total(args.out),
                         "threshold": min_publish, "decision": "blocked_invalid_config"}
        write_json(args.stats, stats)
        return EXIT_INVALID

    # ---------------- 7. 真实代理探测
    alive = named
    if not args.no_probe and args.mihomo:
        from probe import Prober
        candidates = named[: args.probe_limit]
        try:
            with Prober(args.mihomo) as p:
                p.start(candidates)
                names = p.proxy_names()
                delays = p.run(names, timeout_ms=args.probe_timeout, workers=args.probe_workers)
        except Exception as e:  # 探测设施故障不应阻断发布，但要如实记录
            LOG.warning("探测失败（降级为不探测）：%s", e)
            stats["probe"] = {"enabled": True, "error": str(e), "tested": 0, "alive": None}
        else:
            alive = [n for n in candidates if n["name"] in delays]
            ds = sorted(delays.values())
            stats["probe"] = {
                "enabled": True, "tested": len(names), "alive": len(alive),
                "median_delay_ms": ds[len(ds) // 2] if ds else None,
                "min_delay_ms": ds[0] if ds else None,
                "max_delay_ms": ds[-1] if ds else None,
            }

    # ---------------- 8. 发布门禁
    prev_total = read_previous_total(args.out)
    threshold = max(min_publish, int(prev_total * min_ratio))
    decision = "publish"
    if args.force:
        LOG.warning("--force 已启用，跳过数量门禁")
    elif len(alive) < threshold:
        decision = "blocked_count_drop"
        LOG.error("节点数 %d 低于门槛 %d（上一版 %d），保留旧版本", len(alive), threshold, prev_total)

    stats["counts"] = {
        "raw": raw_total, "sanitized": sanitized_total, "duplicates_removed": dup,
        "after_cap": len(named), "probed_alive": len(alive),
        "published": 0 if decision != "publish" else len(alive),
    }
    stats["gate"] = {"previous_total": prev_total, "threshold": threshold, "decision": decision}
    stats["by_region"] = {}
    stats["by_protocol"] = {}
    for p in alive:
        cc = p["name"].split("-")[1]
        stats["by_region"][cc] = stats["by_region"].get(cc, 0) + 1
        stats["by_protocol"][p["type"]] = stats["by_protocol"].get(p["type"], 0) + 1

    if decision != "publish":
        write_json(args.stats, stats)
        if args.summary:
            with open(args.summary, "w", encoding="utf-8") as f:
                f.write(build_summary(stats))
        return EXIT_GATE

    # ---------------- 9. 落盘
    dump_proxies(args.out, alive)
    write_json(args.stats, stats)
    if args.summary:
        with open(args.summary, "w", encoding="utf-8") as f:
            f.write(build_summary(stats))
    LOG.info("已发布 %d 个节点 → %s", len(alive), args.out)
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        LOG.exception("致命错误：%s", exc)
        sys.exit(EXIT_FATAL)
