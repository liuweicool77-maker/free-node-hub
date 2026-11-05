#!/usr/bin/env bash
# 准备构建依赖：Mihomo 内核 + 国家 GeoIP 库。
# 只从官方/知名源下载，下载后校验可执行性，不做任何自动更新。
set -euo pipefail

BIN_DIR="${1:-bin}"
mkdir -p "$BIN_DIR"

MIHOMO_VERSION="${MIHOMO_VERSION:-}"   # 留空=取最新 release
echo "== 准备 Mihomo 内核 =="
if [ -z "$MIHOMO_VERSION" ]; then
  MIHOMO_VERSION=$(curl -fsSL --retry 3 --max-time 60 \
    -H "Authorization: Bearer ${GITHUB_TOKEN:-}" \
    https://api.github.com/repos/MetaCubeX/mihomo/releases/latest \
    | python -c "import json,sys; print(json.load(sys.stdin)['tag_name'].lstrip('v'))")
fi
echo "版本: $MIHOMO_VERSION"

ASSET="mihomo-linux-amd64-compatible-v${MIHOMO_VERSION}.gz"
URL="https://github.com/MetaCubeX/mihomo/releases/download/v${MIHOMO_VERSION}/${ASSET}"
echo "下载: $URL"
curl -fsSL --retry 3 --retry-delay 5 --max-time 300 -o "${BIN_DIR}/mihomo.gz" "$URL"
gunzip -f "${BIN_DIR}/mihomo.gz"
chmod +x "${BIN_DIR}/mihomo"
"${BIN_DIR}/mihomo" -v

echo "== 准备 Country.mmdb =="
curl -fsSL --retry 3 --retry-delay 5 --max-time 300 \
  -o Country.mmdb \
  https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb
ls -l Country.mmdb
