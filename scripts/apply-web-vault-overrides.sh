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

# Keep behavior consistent with backend src/handlers/config.rs:
# - Defaults to true if not set
# - Only "false" disables it
disable_user_registration="${DISABLE_USER_REGISTRATION:-}"
disable_user_registration="$(printf '%s' "${disable_user_registration}" | tr '[:upper:]' '[:lower:]')"

if [[ -z "${disable_user_registration}" || "${disable_user_registration}" != "false" ]]; then
  cat >> "${DST_CSS}" <<'EOF'

/* Build-time option: hide signup/register UI when DISABLE_USER_REGISTRATION != "false" */
app-root a[routerlink="/signup"],
app-login form div + div + div + div + hr,
app-login form div + div + div + div + hr + p {
  display: none !important;
}
EOF
fi

echo "✅ Installed override CSS: ${DST_CSS}"
