#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
用法：
  ./numasec-headful.sh <目标目录> [numasec 其他参数]

示例：
  ./numasec-headful.sh "/opt/target-test01"
  ./numasec-headful.sh "/opt/target-test01" -s ses_xxx
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

if [[ "${EUID}" -eq 0 ]]; then
  echo "请在 Kali 图形桌面的普通用户终端中运行本脚本，不要直接以 root 运行。" >&2
  exit 1
fi

TARGET_DIR="$1"
shift

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"
PACKAGES_DIR="$REPO_ROOT/packages/numasec"
ENTRYPOINT="$PACKAGES_DIR/src/index.ts"

if [[ ! -d "$PACKAGES_DIR" || ! -f "$ENTRYPOINT" ]]; then
  echo "未找到 numasec 仓库结构，请把脚本放在 numasec 仓库根目录中使用。" >&2
  exit 1
fi

if [[ ! -d "$TARGET_DIR" ]]; then
  echo "目标目录不存在：$TARGET_DIR" >&2
  exit 1
fi

if ! command -v bun >/dev/null 2>&1; then
  echo "未找到 bun，请先确保当前用户环境可以直接执行 bun。" >&2
  exit 1
fi

if ! command -v xhost >/dev/null 2>&1; then
  echo "未找到 xhost，请先安装对应的 X11 工具。" >&2
  exit 1
fi

DISPLAY_VALUE="${DISPLAY:-:0}"
XAUTHORITY_VALUE="${XAUTHORITY:-$HOME/.Xauthority}"
XDG_RUNTIME_DIR_VALUE="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
DBUS_SESSION_BUS_ADDRESS_VALUE="${DBUS_SESSION_BUS_ADDRESS:-unix:path=${XDG_RUNTIME_DIR_VALUE}/bus}"
BUN_BIN="$(command -v bun)"

if [[ ! -f "$XAUTHORITY_VALUE" ]]; then
  echo "未找到 XAUTHORITY 文件：$XAUTHORITY_VALUE" >&2
  exit 1
fi

xhost +SI:localuser:root >/dev/null

echo "已授权 root 访问当前图形会话，正在以有头模式启动 numasec..."

exec sudo -E env \
  DISPLAY="$DISPLAY_VALUE" \
  XAUTHORITY="$XAUTHORITY_VALUE" \
  XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR_VALUE" \
  DBUS_SESSION_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS_VALUE" \
  NUMASEC_BROWSER_MODE=auto \
  "$BUN_BIN" run --cwd "$PACKAGES_DIR" --conditions=browser src/index.ts "$TARGET_DIR" "$@"
