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
from sanitize import Reject, sanitize, unsupported_types  # noqa: E402

EXIT_OK, EXIT_FATAL, EXIT_GATE, EXIT_INVALID = 0, 1, 2, 3

YAML_HEADER = (
    "# FreeNode Hub — 公开免费节点聚合产物\n"
    "# 由 GitHub Actions 自动生成，请勿手工编辑。\n"
    "# 仅包含顶层 proxies 字段；不含规则/DNS/TUN/脚本等任何可改变客户端行为的配置。\n"
    "# 上游来源见 dist/stats.json 与仓库 README。\n"
)


# ------------------------------------------------------------------ 抓取与解析

def load_sources(path: str) -> tuple[list[dict], list[dict], dict]:
    """返回 (可再分发的来源, 因许可原因被排除的来源, limits)。

    默认 **不** 假定未声明许可的来源可以公开再分发：必须在 sources.yaml 里
    显式写 redistribute: true 才会进入公开产物。
    """
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    enabled = [s for s in (doc.get("sources") or []) if s.get("enabled", True)]
    usable = [s for s in enabled if s.get("redistribute", False)]
    excluded = [s for s in enabled if not s.get("redistribute", False)]
    limits = doc.get("limits") or {}
    return usable, excluded, limits


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
    """去重 / 命名的内部指纹输入：协议 + 端点 + 认证参数 + 传输层特征。

    这里漏掉任何一项都会把"两个实际不同的节点"误判成重复，
    所以传输层与认证相关的可选参数也要纳入。
    """
    keys = (
        "type", "server", "port", "uuid", "password", "username", "auth-str",
        "cipher", "network", "sni", "servername", "plugin",
        "obfs", "obfs-password", "flow", "protocol",
    )
    base = {k: clean[k] for k in keys if k in clean}
    if "ws-opts" in clean:
        base["ws-path"] = clean["ws-opts"].get("path")
        base["ws-host"] = (clean["ws-opts"].get("headers") or {}).get("Host")
    if "grpc-opts" in clean:
        base["grpc"] = clean["grpc-opts"].get("grpc-service-name")
    if "reality-opts" in clean:
        base["reality-pk"] = clean["reality-opts"].get("public-key")
        base["reality-sid"] = clean["reality-opts"].get("short-id")
    if "plugin-opts" in clean:
        po = clean["plugin-opts"]
        if isinstance(po, dict):
            base["plugin-opts"] = json.dumps(po, sort_keys=True, ensure_ascii=False)
    return base


def decide_publish(
    *,
    alive_count: int,
    prev_total: int,
    min_publish: int,
    min_ratio: float,
    validation_ok: bool,
    probe_required: bool,
    probe_error: str | None,
    force: bool,
) -> tuple[str, str]:
    """发布门禁（纯函数，便于单测）。

    返回 (decision, human_reason)。decision == "publish" 才允许落盘。

    优先级刻意这样排：
      1) 配置本身不合法 → 一律不发布（--force 也不越过）
      2) 本轮要求探测但探测设施故障 → 一律不发布，避免把未验证节点当已验证发布
      3) 低于绝对下限 → 一律不发布（--force 也不越过空订阅保护）
      4) 相对上一版骤降 → 只有 --force 能越过
    """
    threshold = max(min_publish, int(prev_total * min_ratio))

    if not validation_ok:
        return "blocked_invalid_config", "生成的配置未通过内核校验"
    if probe_required and probe_error:
        return "blocked_probe_failed", f"真实探测设施故障，拒绝发布未验证节点：{probe_error}"
    if alive_count < min_publish:
        return "blocked_below_minimum", f"节点数 {alive_count} 低于绝对下限 {min_publish}"
    if alive_count < threshold:
        if force:
            return "publish", f"--force 越过数量下降门禁（{alive_count} < {threshold}）"
        return "blocked_count_drop", f"节点数 {alive_count} 低于门槛 {threshold}（上一版 {prev_total}）"
    return "publish", f"节点数 {alive_count} ≥ 门槛 {threshold}"


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
    ]

    probe = stats.get("probe") or {}
    if probe.get("error"):
        lines.append(f"- ⚠️ 真实探测失败并降级（本轮为未经验证的节点）：`{probe['error']}`")
    elif probe.get("alive") is not None:
        lines.append(
            f"- 真实探测：测试 {probe.get('tested')}，存活 {probe.get('alive')}，"
            f"中位延迟 {probe.get('median_delay_ms')} ms"
        )
    else:
        lines.append("- 真实探测：已跳过")

    lines += [
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

    # 相对路径会在切换工作目录后失效（探测会用 cwd=临时目录启动内核），统一转绝对路径
    if args.mihomo:
        args.mihomo = os.path.abspath(args.mihomo)
        if not os.path.exists(args.mihomo):
            LOG.error("内核路径不存在：%s", args.mihomo)
            return EXIT_FATAL
    # MMDB 不做 abspath：Windows 下 maxminddb 对含中文的绝对路径会打开失败，相对路径正常

    sources, excluded_sources, limits = load_sources(args.sources)
    total_max = int(limits.get("total_max", 600))
    min_publish = int(limits.get("min_publish", 20))
    min_ratio = float(limits.get("min_ratio_vs_previous", 0.5))
    if excluded_sources:
        for s in excluded_sources:
            LOG.warning(
                "来源 %s 许可为 %s，未声明可再分发，已排除出公开产物",
                s.get("id"), s.get("license", "unknown"),
            )
    if not sources:
        LOG.error("没有任何允许再分发的来源，拒绝执行")
        return EXIT_FATAL
    LOG.info("可发布来源 %d 个，总量上限 %d", len(sources), total_max)

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
    # 规则：只要本轮"要求探测"，探测设施出任何问题都必须中止发布，
    # 绝不允许把未经验证的节点当作已验证节点推上线。
    probe_required = not args.no_probe and bool(args.mihomo)
    probe_error: str | None = None
    alive = named

    if probe_required:
        from probe import Prober
        candidates = named[: args.probe_limit]
        prober = None
        try:
            prober = Prober(args.mihomo)
            prober.start(candidates)
            names = prober.wait_ready(expected=len(candidates))
            loaded_ratio = len(names) / max(1, len(candidates))
            if loaded_ratio < 0.9:
                raise RuntimeError(
                    f"探测内核只注册了 {len(names)}/{len(candidates)} 个节点（{loaded_ratio:.0%}），"
                    "低于 90% 视为内核启动/加载异常"
                )
            delays = prober.run(names, timeout_ms=args.probe_timeout, workers=args.probe_workers)
            if not isinstance(delays, dict):
                raise RuntimeError("探测 API 返回非预期结构")
        except Exception as e:  # noqa: BLE001 - 任何探测异常都算设施故障
            probe_error = f"{type(e).__name__}: {e}"
            LOG.error("探测设施故障，本轮不发布：%s", e)
            tail = prober.log_tail(30) if prober else "(无)"
            print("----- 探测内核日志尾部 -----")
            print(tail)
            print("---------------------------")
            stats["probe"] = {
                "enabled": True, "error": probe_error, "tested": 0, "alive": None,
                "core_log_tail": tail[-3000:],
            }
        else:
            alive = [n for n in candidates if n["name"] in delays]
            ds = sorted(delays.values())
            stats["probe"] = {
                "enabled": True, "tested": len(names), "alive": len(alive),
                "loaded_ratio": round(loaded_ratio, 3),
                "median_delay_ms": ds[len(ds) // 2] if ds else None,
                "min_delay_ms": ds[0] if ds else None,
                "max_delay_ms": ds[-1] if ds else None,
            }
            LOG.info("探测完成：%d/%d 存活", len(alive), len(names))
        finally:
            if prober:
                prober.stop()
    else:
        stats["probe"] = {"enabled": False, "note": "本轮显式跳过探测（--no-probe）"}

    # 协议白名单复核：产物里不允许出现当前内核不支持的协议
    bad_types = unsupported_types(alive)
    if bad_types:
        LOG.error("产物中出现不支持的协议：%s", bad_types)
        probe_error = probe_error or f"unsupported_protocol: {bad_types}"

    # ---------------- 8. 发布门禁
    prev_total = read_previous_total(args.out)
    threshold = max(min_publish, int(prev_total * min_ratio))
    decision, reason = decide_publish(
        alive_count=len(alive),
        prev_total=prev_total,
        min_publish=min_publish,
        min_ratio=min_ratio,
        validation_ok=vok,
        probe_required=probe_required,
        probe_error=probe_error,
        force=args.force,
    )
    (LOG.warning if decision == "publish" else LOG.error)("发布门禁：%s — %s", decision, reason)

    stats["counts"] = {
        "raw": raw_total, "sanitized": sanitized_total, "duplicates_removed": dup,
        "after_cap": len(named), "probed_alive": len(alive),
        "published": 0 if decision != "publish" else len(alive),
    }
    stats["gate"] = {"previous_total": prev_total, "threshold": threshold,
                     "decision": decision, "reason": reason}
    stats["sources_excluded_by_license"] = [
        {"id": s.get("id"), "license": s.get("license", "unknown")} for s in excluded_sources
    ]
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
