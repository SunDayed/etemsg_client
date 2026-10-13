# msg-client-rust — 端到端加密聊天客户端

`msg-client-rust` 是一个使用 Rust 编写的终端 TUI 即时通讯客户端，配合 `etemsg` Go 服务端使用。客户端负责生成和管理身份密钥、对 1v1 消息做端到端加密、对文件做分块流式加密，并通过 OpenMLS 管理群组端到端加密状态；服务端只保存和转发密文/不透明 MLS 对象。

> 本 README 基于当前源码生成。项目根目录的 `README.md` 描述了完整的协议与交互；根目录 `ASSESSMENT.md` 记录了当前安全、性能与功能评估。

---

## 1. 核心特性

| 能力 | 实现 |
|---|---|
| 身份 | RSA-4096，本地私钥只存 SQLCipher，用户 ID = `sha512(SPKI-DER).hex()[:10]` |
| 1v1 文本 | 每条消息随机 AES-256-GCM 密钥；密钥用接收方 RSA-4096 OAEP-SHA256 封装 |
| 消息认证 | RSA-PKCS1v15-SHA256 签名，服务端与接收方都验签 |
| 文件传输 | AES-256-GCM 流式分块（1 MiB/块），文件名单独加密，SHA-256 明文校验，支持断点续传 |
| 群组 | OpenMLS / RFC 9420，服务端只转发 Commit、Welcome 和群消息密文 |
| 实时连接 | WSS；自动重连与 30s 应用层心跳 |
| 离线消息 | 登录后调用 `/get_offline_msg` 拉取并逐条验签解密 |
| 多服务器 | 可添加多台服务器，每台服务器独立身份、联系人和会话 |
| 本地存储 | SQLCipher（`bundled-sqlcipher`），按 `server_id` 隔离数据 |
| TUI | ratatui + crossterm，纯键盘交互，不依赖鼠标 |
| 证书策略 | REST 使用 SPKI SHA-256 TOFU 固定；WSS 当前不校验证书（见安全限制） |

---

## 2. 技术栈

- Rust 2021，`rust-version = "1.91"`（`Cargo.toml`）
- UI：`ratatui 0.30` + `crossterm 0.29`
- 加密：`rsa 0.9`、`aes-gcm 0.10`、`sha2`、`md-5`
- 群组：`openmls 0.9` + `openmls_rust_crypto`
- 存储：`rusqlite 0.37`，启用 `bundled-sqlcipher`
- 网络：`rustls 0.23` + `ring`，自实现 HTTP/1.1；`tungstenite` 负责 WebSocket

---

## 3. 目录结构

```text
client/
├── Cargo.toml / Cargo.lock
├── build.sh                    构建并只更新 dist/msg-client-rust
├── dist/                       运行时目录（构建脚本不覆盖运行状态）
└── src/
    ├── main.rs                 CLI、主密钥解锁、诊断模式、bootstrap
    ├── core.rs                 登录、WS 收发、加解密、文件收发、重连
    ├── ui.rs                   TUI 布局、会话树、弹窗、按键
    ├── store.rs                SQLCipher 表结构与读写
    ├── crypto.rs               RSA/AES/签名/ID/流式文件加解密
    ├── log.rs                  写文件日志，避免污染 TUI
    ├── group_cli.rs            无界面群组子命令
    ├── net/
    │   ├── tls.rs              rustls + SPKI TOFU 校验器
    │   ├── http.rs             手写 HTTPS/1.1 客户端
    │   └── ws.rs               WebSocket 客户端
    └── group/
        ├── adapter.rs          MLS 状态机封装
        ├── service.rs          群组业务流程编排
        ├── runtime.rs          群组后台线程
        ├── net_transport.rs    带签群组 REST 实现
        ├── storage.rs          群组本地表读写
        └── state.rs            群角色/状态数据类型
```

---

## 4. 构建

```bash
cd client

# 方式一：脚本构建，并更新 dist/msg-client-rust
./build.sh

# 方式二：直接构建
cargo build --release --offline
# 产物：target/release/msg-client-rust
```

`build.sh` 的原则是**只更新 `dist/` 中的可执行文件**，不会复制、删除或覆盖 `etemsg.db`、`etemsg.db-wal`、`etemsg.db-shm`、日志和 `received_files/` 等运行状态。

运行测试：

```bash
cargo test --release --offline
```

---

## 5. 运行与配置

```bash
# 默认：使用可执行文件旁的 etemsg.db；首次运行提示设置主密钥
dist/msg-client-rust

# 指定数据库
dist/msg-client-rust --db /path/to/etemsg.db

# 直接提供主密钥（注意：会出现在进程列表中）
dist/msg-client-rust --key 'your-strong-master-key'
```

路径与主密钥解析顺序：

- 数据库：`--db` → `MSG_CLIENT_DB` → 可执行文件同级 `etemsg.db` → 当前目录 `etemsg.db`
- 主密钥：`--key` → `MSG_CLIENT_KEY` → 交互式输入

首次运行会要求设置本地数据库主密钥。该主密钥是 SQLCipher 的唯一保护；库内包含全部聊天明文、MLS 私钥和 RSA 私钥，请使用强随机口令或操作系统密钥环保存。

---

## 6. TUI 快捷键

| 按键 | 功能 |
|---|---|
| `F1` | 服务器配置：添加、删除、重命名、连接 |
| `F2` | 添加联系人（可粘贴整句自动提取 ID） |
| `F3` | 选择文件发送（仅单聊；群聊不支持文件） |
| `F4` | 帮助 |
| `F5` | 创建群组（群名和昵称必填） |
| `F6` | 申请加入群组（群 ID、说明、昵称必填） |
| `F7` | 通知中心：群审批、群主转让、好友申请 |
| `F8` | 手动同步群组 |
| `F9` | 查看群成员；群主可移除成员 |
| `r` | 重命名当前服务器/联系人/群组（群组改名仅群主） |
| `d` | 删除联系人；选中群组时为退出群组 |
| `t` | 群主转让（选中群组时） |
| `D` | 解散群组（仅群主） |
| `Enter` | 打开会话/发送/确认 |
| `Tab` | 会话树与输入框切换焦点 |
| `Ctrl+J` 或 `Shift+Enter` | 输入框换行 |
| `Ctrl+Alt+M` / `Alt+M` | 退出程序（会先执行 WAL checkpoint） |
| `Ctrl+C` / `Ctrl+Q` | 刻意忽略，避免误退 |

---

## 7. 诊断与群组 CLI

产品形态是 TUI，以下命令用于无界面排障或自动化验证：

```bash
dist/msg-client-rust --selftest <db> <key>
dist/msg-client-rust --nettest  <db> <key>
dist/msg-client-rust --wstest   <db> <key>
dist/msg-client-rust --keytest

# 无界面群组操作
dist/msg-client-rust --db <db> --key <key> --group-list
dist/msg-client-rust --db <db> --key <key> --group-create "群名" "我的昵称"
dist/msg-client-rust --db <db> --key <key> --group-request <gid> "说明" "我的昵称"
dist/msg-client-rust --db <db> --key <key> --group-sync <gid>
```

完整的子命令列表见根目录 `README.md`，或运行 `dist/msg-client-rust --help`。

---

## 8. 安全模型

- **传输层**：REST 使用自签证书 + SPKI SHA-256 TOFU；WSS 当前不校验服务端证书。
- **身份层**：RSA-4096 私钥只在本地加密库中；注册和添加联系人时客户端会校验 `public_key_id(pub) == user_id`。
- **1v1 消息**：AES-256-GCM 加密，RSA-OAEP 封装消息密钥，RSA-PKCS1v15-SHA256 签名。
- **文件**：分块 AES-256-GCM，`AAD = file_id|size`，块 IV 由随机 base_iv 派生，SHA-256 校验明文件完整性。
- **群组**：MLS 状态和成员变更由成员客户端执行，服务端不解析、不生成、不解密 MLS 对象。
- **本地**：SQLCipher 主密钥只在运行时提供，不硬编码；退出前 checkpoint，保证单独备份 `etemsg.db` 时不丢 WAL 数据。

### 当前安全注意事项

1. `--key` 会暴露在进程列表中，优先使用交互式输入或 `MSG_CLIENT_KEY`，并保护环境变量。
2. WSS 不校验证书，攻击者若劫持网络可看到连接元数据并伪造实时控制帧；应用层消息签名能保护消息来源与内容。
3. 主密钥强度决定本地历史消息、RSA 私钥和 MLS 状态的安全。
4. 在部分系统上，数据库、日志和接收到的明文文件权限可能依赖 umask，建议部署时限制为当前用户可读。

---

## 9. 测试

```bash
cargo test --release --offline
```

当前源码的客户端测试覆盖 SQLCipher、协议摘要、文件加解密、UI 按键、群组加入/退出/改名/转让/踢人等关键路径；文档生成时共 82 个测试通过。

---

## 10. 已知边界

- 群组文件发送/接收未实现，文件功能仅支持 1v1。
- WSS 不做证书固定，REST 才做 SPKI TOFU。
- 建群、申请、审批、改名、踢人、退群、转让、解散等群操作已放到后台线程执行，UI 不再等待网络/MLS 往返；结果通过 Toast/通知中心异步返回。
- 不支持多设备；一个用户在一个服务器上只有一个身份和一条 WS 连接。
- 服务端和客户端都没有自动数据库迁移；升级前应确认 schema 兼容性。
- KeyPackage 不是一次性；服务端的群通知是 opaque 转发，成员权威来自 MLS 棘轮树。
- 群主发起转让并退出后，如果继任者既不接受也不拒绝，群会进入 owner 空缺的"死状态"（不能加群/审批；消息收发不受影响），当前没有自动超时或回退机制。

---

## 11. 相关文档

- 项目根目录：`../README.md`
- 项目评估：`../ASSESSMENT.md`
- 服务端文档：`../server/README.md`
