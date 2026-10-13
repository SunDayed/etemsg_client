# msg-client-rust

[English](README.md)

`etemsg` 端到端加密聊天系统的 Rust 终端 TUI 客户端。它负责管理本地身份、加密 1v1 消息与文件，并使用 OpenMLS 进行群组加密。服务端只转发密文和不透明 MLS 对象。

## 功能

- RSA-4096 身份与挑战-应答登录。
- 1v1 文本消息端到端加密：AES-256-GCM、RSA-OAEP 密钥封装、消息签名。
- 1v1 流式、可断点续传的加密文件传输。
- MLS（RFC 9420）群组：建群、申请、审批、消息同步、改名、退群、踢人、转让、解散。
- 多服务器支持，每台服务器独立身份、联系人与本地数据。
- SQLCipher 加密本地数据库。
- 基于 ratatui + crossterm 的纯键盘 TUI。
- REST 证书 SPKI 指纹固定（TOFU）与 WebSocket 自动重连。

## 构建

环境要求：Rust 1.91+ 与 Cargo。

```bash
cd client

# 推荐：构建并更新 dist/msg-client-rust
./build.sh

# 或直接构建
cargo build --release --offline
```

Release 二进制位于 `target/release/msg-client-rust`；`./build.sh` 会把它复制到 `dist/msg-client-rust`。

运行测试：

```bash
cargo test --release --offline
```
