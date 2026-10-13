#!/usr/bin/env bash
# 构建 msg-client-rust
#
# 流程：
#   [1/2] cargo build --release
#   [2/2] 复制二进制到 dist/msg-client-rust
#
# 重要约定：
#   · 本脚本**只更新 dist/ 中的二进制可执行文件**；
#   · **不会**复制、创建、删除或覆盖 dist/ 中的任何运行状态，包括但不限于：
#       etemsg.db / etemsg.db-wal / etemsg.db-shm / etemsg.encrypted
#       tui_stderr.log / received_files/ 等；
#   · 运行时状态的初始化由部署/使用环节负责（使用 dist 目录中原有文件即可）。
set -euo pipefail
cd "$(dirname "$0")"

# 自动定位 cargo（未加入 PATH 时补充常见安装位置，保证脚本可直接运行）
if ! command -v cargo >/dev/null 2>&1; then
    for d in "$HOME/.cargo/bin" /root/.cargo/bin /usr/local/cargo/bin; do
        if [ -x "$d/cargo" ]; then
            export PATH="$PATH:$d"
            break
        fi
    done
fi
if ! command -v cargo >/dev/null 2>&1; then
    echo "[错误] 未找到 cargo。请先安装 Rust 工具链，或把 cargo 加入 PATH。" >&2
    exit 1
fi

echo "=== [1/2] cargo build --release ==="
cargo build --release

echo
echo "=== [2/2] 复制二进制到 dist/ ==="
mkdir -p dist
cp -f target/release/msg-client-rust dist/msg-client-rust
chmod +x dist/msg-client-rust
ls -lh dist/msg-client-rust

echo
echo "提示：dist/ 中的数据库、标记、日志、received_files/ 等运行状态未被改动。"
