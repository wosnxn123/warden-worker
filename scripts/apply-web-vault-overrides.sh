#!/usr/bin/env bash
set -euo pipefail

WEB_VAULT_DIR="${1:-public/web-vault}"
WEB_VAULT_DIR="${WEB_VAULT_DIR%/}"

SRC_CSS="public/css/vaultwarden.css"
DST_CSS="${WEB_VAULT_DIR}/css/vaultwarden.css"

if [[ ! -f "${SRC_CSS}" ]]; then
  echo "❌ Missing source CSS: ${SRC_CSS}" >&2
  exit 1
fi

if [[ ! -d "${WEB_VAULT_DIR}" ]]; then
  echo "❌ Missing web vault directory: ${WEB_VAULT_DIR}" >&2
  echo "   (Expected bw_web_builds to extract into a 'web-vault' folder.)" >&2
  exit 1
fi

mkdir -p "$(dirname "${DST_CSS}")"
cp "${SRC_CSS}" "${DST_CSS}"

echo "✅ Installed override CSS: ${DST_CSS}"
