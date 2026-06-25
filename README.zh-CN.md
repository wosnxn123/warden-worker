# Warden：基于 Cloudflare Workers 的 Bitwarden 兼容服务器

[![Powered by Cloudflare](https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white)](https://www.cloudflare.com/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> [!NOTE]
> 📖 English documentation: [README.md](README.md) / 英文文档见 [README.md](README.md)

本项目是一个可部署到 Cloudflare Workers 的自托管 Bitwarden 兼容服务器。利用 Cloudflare 的免费套餐，你可以获得一个完全免费、无服务器、低维护的密码管理后端。

> 本文档为中文版。英文文档见 [README.md](README.md)。

## 目录

- [简介](#简介)
- [功能特性](#功能特性)
- [部署指南](#部署指南)
- [配置项](#配置项)
  - [基础配置](#基础配置)
  - [邮件服务](#邮件服务)
  - [附件存储](#附件存储)
  - [双因素认证（2FA）](#双因素认证2fa)
  - [SSO 单点登录](#sso-单点登录)
  - [微软 Graph 集成](#微软-graph-集成)
  - [Admin 管理面板](#admin-管理面板)
  - [Key Connector](#key-connector)
  - [SCIM 目录同步](#scim-目录同步)
- [组织与共享](#组织与共享)
- [紧急访问](#紧急访问)
- [本地开发](#本地开发)
- [数据库操作](#数据库操作)
- [常见问题](#常见问题)

## 简介

虽然 [Vaultwarden](https://github.com/dani-garcia/vaultwarden) 提供了优秀的自托管方案，但仍需管理服务器或 VPS。Warden 通过 Cloudflare Workers 生态解决了这个问题：将服务部署到 Worker，使用 D1 数据库存储，即可拥有完全免费、无服务器、低维护的 Bitwarden 服务器。

- **后端**：Rust + Axum，编译为 WASM 运行于 Cloudflare Workers
- **存储**：Cloudflare D1（数据库）、R2/KV/OneDrive（文件）
- **实时同步**：Durable Objects + WebSocket + 移动端推送
- **兼容性**：兼容官方 Bitwarden 客户端（浏览器扩展、Android、iOS、桌面端）

## 功能特性

本项目已实现 **全部** Bitwarden 功能：

### 核心密码库
- 密码项（Cipher）的增删改查、软删除（回收站）、归档
- 文件夹管理
- 文件附件（支持 KV / R2 / OneDrive 三种存储后端）
- Bitwarden Send（通过链接分享加密文本或文件）
- 导入 / 导出
- 回收站自动清理（定时任务）
- TOTP 验证码生成

### 双因素认证（2FA）
- **Authenticator（TOTP）**：基于时间的一次性密码
- **Email**：邮箱验证码
- **Yubikey**：YubiKey 硬件密钥（调用 Yubico 验证服务器）
- **Duo**：Duo Security 推送/OTP
- **WebAuthn（Passkey）**：通行密钥（纯 Rust 实现，WASM 兼容）
- **恢复码**：2FA 紧急恢复
- **受保护操作 OTP**：敏感操作可用 OTP 替代主密码

### 组织与共享
- 创建组织、邀请/接受/确认成员（密钥交换）
- 集合（Collection）管理及用户权限分配
- 密码项共享至组织
- 组织批量导入
- 组织策略（Policies）
- 事件日志（审计追踪）

### 单点登录（SSO）
- OIDC 协议单点登录
- 多租户支持（多个微软 E3 组织可选）
- Key Connector（SSO 用户免主密码解锁）

### 目录同步
- SCIM 2.0 协议（RFC 7643/7644）
- 从 Entra ID / Okta / OneLogin 等自动配置用户和组

### 紧急访问
- 邀请 → 接受 → 确认 → 发起 → 批准/拒绝 → 查看 / 接管（+ 重置密码）

### 其他
- 设备管理与会话撤销
- 设备登录（Auth Requests）
- 实时同步（WebSocket + 移动推送）
- Admin 管理面板
- 微软 Graph 集成（Exchange 邮件 + OneDrive 存储）
- 内置速率限制

## 部署指南

### 前置条件

- Rust 工具链（见 `rust-toolchain.toml`，当前 1.91.1）
- Node.js 与 Wrangler CLI
- Cloudflare 账户

### CLI 部署

1. 安装依赖并登录：
   ```bash
   npm install -g wrangler
   wrangler login
   ```

2. 创建 D1 数据库：
   ```bash
   wrangler d1 create vault1
   ```
   将返回的 `database_id` 填入 `wrangler.toml`。

3. 应用数据库迁移：
   ```bash
   wrangler d1 migrations apply vault1 --remote
   ```

4. 设置必需的密钥：
   ```bash
   wrangler secret put JWT_SECRET
   wrangler secret put JWT_REFRESH_SECRET
   ```

5. 部署：
   ```bash
   wrangler deploy
   ```

### GitHub Actions 部署

参见 [部署文档](docs/deployment.md)。在工作流中配置 `D1_DATABASE_ID`、`JWT_SECRET`、`JWT_REFRESH_SECRET` 等 Secrets 即可自动构建部署。

### 前端（Web Vault）

前端使用 [bw_web_builds](https://github.com/dani-garcia/bw_web_builds)（Vaultwarden 的 Web Vault 构建），通过 Cloudflare Workers Static Assets 打包部署。

```bash
# 下载前端资源
mkdir -p public/web-vault
# 从 GitHub Release 下载并解压到 public/web-vault/

# 应用 UI 覆盖样式
mkdir -p public/web-vault/css/
cp public/css/vaultwarden.css public/web-vault/css/

# 本地或部署
wrangler dev --persist
```

可通过 GitHub Actions 变量 `BW_WEB_VERSION`（生产）或 `BW_WEB_VERSION_DEV`（开发）指定版本。

## 配置项

所有配置通过 `wrangler.toml` 的 `[vars]` 或 Cloudflare Dashboard 设置。密钥通过 `wrangler secret put` 设置。

### 基础配置

| 变量 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `JWT_SECRET` | secret | 必填 | JWT 访问令牌签名密钥 |
| `JWT_REFRESH_SECRET` | secret | 必填 | JWT 刷新令牌签名密钥 |
| `BASE_URL` | var | 自动 | 覆盖文件上传/下载 URL 的基础地址（如 `https://vault.example.com`） |
| `PASSWORD_ITERATIONS` | var | `600000` | 服务端 PBKDF2 迭代次数（最小 600000） |
| `TRASH_AUTO_DELETE_DAYS` | var | `30` | 回收站保留天数（0 或负数禁用） |
| `IMPORT_BATCH_SIZE` | var | `30` | 导入/删除批处理大小（0 禁用批处理） |
| `DISABLE_USER_REGISTRATION` | var | `true` | 控制客户端是否显示注册按钮（不影响服务端行为） |
| `AUTHENTICATOR_DISABLE_TIME_DRIFT` | var | `false` | 设为 `true` 禁用 TOTP ±1 时间步漂移 |
| `ALLOWED_EMAILS` | secret | 无 | 允许注册的邮箱白名单（逗号分隔 glob 模式，不设则开放注册） |

### 邮件服务

Workers 无法直接发 SMTP，邮件通过 HTTP API 发送。通过 `MAIL_PROVIDER` 选择：

| 值 | 说明 | 所需配置 |
|----|------|----------|
| `resend` | 使用 Resend 服务 | `RESEND_API_KEY`（secret）、`MAIL_FROM`（var） |
| `webhook` | 自定义 HTTP 中继 | `MAIL_WEBHOOK_URL`（var）、`MAIL_FROM`（var，可选） |
| `msgraph` | 通过 Exchange Online 发送 | 见[微软 Graph 集成](#微软-graph-集成) |
| 不设 | 禁用（相关功能静默失效） | 无 |

邮件功能用于：Email 2FA、紧急访问邀请通知、密码提示、**注册邮箱验证**。

### 注册邮箱验证

默认情况下，Warden 要求用户注册后必须验证邮箱才能登录。如需关闭，设置 `REQUIRE_EMAIL_VERIFICATION=false`。

开启时的流程：
1. 用户注册 → 系统发送一封含唯一验证链接的邮件。
2. 用户点击链接 → `POST /api/accounts/verify-email` 将 `email_verified` 置为 1。
3. 此时方可登录。

如果验证邮件丢失，可调用 `POST /identity/accounts/register/send-verification-email`（登录前，body `{email}`）或 `POST /api/accounts/send-verification-email`（登录后）重新发送。验证 token 有效期 24 小时。

### 附件存储

支持三种存储后端，优先级：**OneDrive > R2 > KV**。

| 特性 | KV | R2 | OneDrive |
|------|----|----|----------|
| 单文件上限 | 25 MB | 100 MB | 250 MB |
| 需要信用卡 | 否 | 是 | 否（用 E3 订阅） |
| 流式 I/O | 是 | 是 | 是 |

| 变量 | 说明 |
|------|------|
| `ATTACHMENT_MAX_BYTES` | 单个附件最大字节数 |
| `ATTACHMENT_TOTAL_LIMIT_KB` | 每用户附件存储总量上限（KB） |
| `ATTACHMENT_TTL_SECS` | 附件上传/下载 URL 有效期（秒，默认 300，最小 60） |

### 双因素认证（2FA）

#### Yubikey

调用 Yubico 验证服务器（HMAC 签名请求，响应签名校验）：
- `YUBICO_CLIENT_ID`（var）
- `YUBICO_SECRET_KEY`（secret）

未配置时，Yubikey 端点返回错误。

#### Duo

使用 Duo Auth API（HMAC-SHA1 签名请求）：
- `DUO_IKEY`（var）
- `DUO_SKEY`（secret）
- `DUO_HOST`（var，如 `api-1234.duosecurity.com`）
- `DUO_AKEY`（secret，可选）

#### WebAuthn（Passkey）

通行密钥注册与登录断言验证完全在 WASM 沙箱内运行，使用纯 Rust 加密（`p256` ECDSA-P256 + `ciborium` CBOR + `sha2`）。无需外部配置。

#### Email 2FA

6 位数字验证码，通过已配置的邮件服务发送。无需额外配置（仅需 `MAIL_PROVIDER`）。

#### 恢复码

启用任何 2FA 后自动生成。用户可通过 `/api/two-factor/recover`（无需认证）使用恢复码绕过 2FA。

### SSO 单点登录

通过 OIDC 协议实现单点登录。SSO 认证用户身份，保险库仍用主密码解锁（除非启用 Key Connector）。

| 变量 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `SSO_ENABLED` | var | `false` | 设为 `true` 启用 |
| `SSO_AUTHORITY` | var | 必填 | IdP 签发者 URL（如 `https://login.microsoftonline.com/{tenant}/v2.0`） |
| `SSO_CLIENT_ID` | var | 必填 | OAuth 客户端 ID |
| `SSO_CLIENT_SECRET` | secret | 必填 | OAuth 客户端密钥 |
| `SSO_SCOPES` | var | `openid email profile` | OIDC scopes |
| `SSO_CALLBACK_URL` | var | 自动 | 回调 URL，默认 `{BASE_URL}/identity/connect/oidc-signin` |
| `SSO_SIGNUPS_MATCH_EMAIL` | var | `true` | 仅允许 SSO 登录已存在的账户 |
| `SSO_ALLOW_UNVERIFIED_EMAIL` | var | `false` | 允许未验证的邮箱 |

回调 URL 必须在 IdP 注册为重定向 URI。

#### 多租户 SSO（多个微软 E3 组织）

如果有多个 E3/M365 租户，配置 `SSO_TENANTS` 为 JSON 数组，让用户选择组织：

```json
[
  {
    "id": "contoso",
    "name": "Contoso (E3)",
    "authority": "https://login.microsoftonline.com/tenant-a/v2.0",
    "client_id": "...",
    "description": "Contoso Ltd"
  },
  {
    "id": "fabrikam",
    "name": "Fabrikam (E3)",
    "authority": "https://login.microsoftonline.com/tenant-b/v2.0",
    "client_id": "...",
    "description": "Fabrikam Inc"
  }
]
```

客户端调用 `GET /identity/connect/sso-tenants` 获取可选组织列表，然后在 `/identity/connect/authorize` 传递 `domain_hint=<id>`。未设置时使用单租户 `SSO_AUTHORITY`/`SSO_CLIENT_ID`。

### 微软 Graph 集成

利用 E3/M365 订阅，启用 Exchange Online 邮件和 OneDrive 附件存储。

在 Azure AD 创建应用注册，授予应用权限 `Mail.Send` 和 `Files.ReadWrite.All`（管理员同意）。

| 变量 | 类型 | 说明 |
|------|------|------|
| `MSGRAPH_TENANT_ID` | var | 租户 GUID |
| `MSGRAPH_CLIENT_ID` | var | 应用客户端 ID |
| `MSGRAPH_CLIENT_SECRET` | secret | 应用密钥 |
| `MSGRAPH_USER` | var | 拥有 OneDrive 存储的服务账号 UPN |
| `MSGRAPH_MAIL_USER` | var | 发件人 UPN（默认同 `MSGRAPH_USER`） |
| `MSGRAPH_BASE_PATH` | var | OneDrive 文件夹（默认 `/warden-attachments`） |

启用后：
- `MAIL_PROVIDER=msgraph` 通过 Exchange Online 发邮件
- OneDrive 作为附件存储后端（优先级最高）

Token 使用 Cloudflare Cache API 缓存。

### Admin 管理面板

内置管理面板位于 `/admin`，由 `ADMIN_TOKEN` secret 保护。未配置时返回 404（禁用）。

功能：
- 使用 Admin Token 登录（Cookie 会话）
- 仪表板：用户/密码项/文件夹/Send/组织/附件数量统计
- 用户列表：邮箱验证、删除操作
- 服务器配置概览：SSO 租户、推送、邮件、存储后端、2FA 提供商

```bash
wrangler secret put ADMIN_TOKEN
```

### Key Connector

允许 SSO 用户无需主密码即可获取用户密钥。Worker 自身充当 Key Connector。

| 变量 | 说明 |
|------|------|
| `KEY_CONNECTOR_ENABLED` | 设为 `true` 启用 |
| `KEY_CONNECTOR_URL` | Worker 自身的 `/api/key-connector` 基础 URL |

### SCIM 目录同步

支持从身份提供商（Entra ID / Okta / OneLogin 等）自动配置用户和组到组织。遵循 RFC 7643/7644：

| 端点 | 方法 | 说明 |
|------|------|------|
| `/scim/v2/{org_id}/Users` | GET / POST | 列表 / 创建用户 |
| `/scim/v2/{org_id}/Users/{id}` | GET / PUT / PATCH / DELETE | 管理单个用户 |
| `/scim/v2/{org_id}/Groups` | GET / POST | 列表 / 创建组 |
| `/scim/v2/{org_id}/Groups/{id}` | DELETE | 删除组 |

认证：`Authorization: Bearer {org_id}:{api_key}`。每个组织的 API key 以 SHA-256 哈希存储。

为组织生成 API key：

```sql
INSERT INTO organization_api_keys (org_id, api_key_hash, created_at, updated_at)
VALUES ('<组织UUID>', '<key的SHA-256十六进制>', datetime('now'), datetime('now'));
```

映射关系：
- SCIM User → `users_organizations` 成员关系（创建=邀请、active=已确认、inactive=已邀请、delete=移除）
- SCIM Group → `groups` 表

## 组织与共享

组织允许团队共享密码项。

- **创建组织**：`POST /api/organizations`（需提供加密的组织密钥和密钥对）
- **邀请成员**：`POST /api/organizations/{id}/users/invite`
- **接受邀请**：`POST /api/organizations/{id}/users/{id}/accept`
- **确认成员**：`POST /api/organizations/{id}/users/{id}/confirm`（密钥交换：用成员公钥加密组织密钥）
- **集合管理**：创建/更新/删除集合，分配用户访问权限（只读/隐藏密码/管理）
- **密码项共享**：`PUT /api/ciphers/{id}/share` 将个人密码项迁入组织并分配集合
- **组织导入**：`POST /api/organizations/{id}/import` 批量导入密码项和集合
- **组织策略**：`PUT /api/organizations/{id}/policies/{type}`

角色：Owner（0）、Admin（1）、User（2）、Manager（3）。

## 紧急访问

允许指定信任联系人，在等待期后查看或接管你的密码库。

完整流程：
1. **邀请**：`POST /api/emergency-access/invite`
2. **接受**：`POST /api/emergency-access/{id}/accept`
3. **确认**（密钥交换）：`POST /api/emergency-access/{id}/confirm`
4. **发起**（联系人发起）：`POST /api/emergency-access/{id}/initiate`
5. **批准/拒绝**（账户所有者）：`POST /api/emergency-access/{id}/approve` 或 `/reject`
6. **查看**（View 类型）：`POST /api/emergency-access/{id}/view`
7. **接管**（Takeover 类型）：`POST /api/emergency-access/{id}/takeover` → `/password`（重置密码）

类型：View（0，仅查看）、Takeover（1，接管账户）。

## 本地开发

```bash
# 快速启动（仅 API）
wrangler dev --persist

# 完整启动（含 Web Vault）
# 1. 下载前端资源（见部署指南）
# 2. 启动
wrangler dev --persist
# 3. 访问 http://localhost:8787
```

检查本地 SQLite：
```bash
ls .wrangler/state/v3/d1/
sqlite3 .wrangler/state/v3/d1/miniflare-D1DatabaseObject/*.sqlite
```

## 数据库操作

- **备份与恢复**：见 [数据库备份文档](docs/db-backup-recovery.md)
- **D1 Time Travel**：见备份文档中的时间点恢复
- **导入备份到本地**：`wrangler d1 execute vault1 --file=backup.sql`

### 数据库迁移

当前共 18 个迁移文件（`migrations/0001` ~ `0018`）：

| 迁移 | 说明 |
|------|------|
| 0001-0013 | 原始表结构（用户、密码项、附件、2FA、设备、Send 等） |
| 0014 | 紧急访问 |
| 0015 | 组织与共享 |
| 0016 | 事件日志 |
| 0017 | SSO 认证 |
| 0018 | 组织 API 密钥（SCIM） |

## 常见问题

### 注册时提示"已注册"但之前没注册过？

已修复。现在注册重复邮箱会返回明确的 `"Email {email} is already registered"` 错误，客户端会正确显示。如果遇到其他报错，检查：
- `ALLOWED_EMAILS` 是否配置（未配置则开放注册）
- 速率限制是否触发

### SSO 登录后还需要主密码吗？

默认是的。SSO 仅认证身份，保险库仍需主密码解锁。如需 SSO 用户免主密码，启用 [Key Connector](#key-connector)。

### 如何启用 Admin 面板？

```bash
wrangler secret put ADMIN_TOKEN
```

设置后访问 `https://你的域名/admin`。

### 如何使用微软 E3 的 OneDrive 存储附件？

配置 `MSGRAPH_*` 系列变量（见[微软 Graph 集成](#微软-graph-集成)）。配置后 OneDrive 自动作为优先存储后端。

### 如何配置多组织 SSO？

设置 `SSO_TENANTS` 为 JSON 数组（见[多租户 SSO](#多租户-sso多个微软-e3-组织)）。每个组织需在各自 Azure AD 注册应用。

### Web Vault 版本？

默认使用 `bw_web_builds v2026.4.1`。可通过 `BW_WEB_VERSION` 变量指定其他版本。

### 支持哪些 Bitwarden 客户端？

- 浏览器扩展：Chrome、Firefox、Safari 等
- Android App（官方）
- iOS App（官方）
- 桌面端（Windows / macOS / Linux）

## 许可证

本项目基于 MIT 许可证。详见 [LICENSE](LICENSE)。
