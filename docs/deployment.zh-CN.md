# 部署指南

> [!NOTE]
> 📖 English documentation: [deployment.md](deployment.md) / 英文文档见 [deployment.md](deployment.md)

本页介绍两种部署方式，请根据你的工作流和基础设施选择。

## 目录

- [CLI 部署](#cli-部署)
- [GitHub Actions CI/CD 部署](#github-actions-cicd-部署)

## CLI 部署

1. **克隆仓库：**

   ```bash
   git clone https://github.com/your-username/warden-worker.git
   cd warden-worker
   ```

2. **创建 D1 数据库：**

   ```bash
   wrangler d1 create warden-db
   ```

3. **（可选）为附件启用 R2 存储桶：**

   Warden 默认使用 KV 存储附件。如果你想使用 R2 作为存储后端：

   ```bash
   # 创建生产环境存储桶
   wrangler r2 bucket create warden-attachments
   ```

   然后在 `wrangler.toml` 中取消注释 R2 存储桶配置部分以启用 R2 绑定。

   > [!NOTE]
   > 附件是可选功能。如果同时移除 KV 和 R2 绑定，附件功能将被禁用，但其他功能不受影响。
   >
   > 你也可以使用微软 OneDrive 作为存储后端（需配置 `MSGRAPH_*` 环境变量），优先级高于 R2 和 KV。

4. **配置数据库 ID：**

   创建 D1 数据库时，Wrangler 会输出 `database_id`。为避免将此密钥提交到仓库，本项目使用环境变量配置数据库 ID。

   **方式一（推荐）：使用 `.env` 文件：**

   在项目根目录创建 `.env` 文件，添加以下内容（替换为你的实际 `database_id`）：

   ```
   D1_DATABASE_ID="your-database-id-goes-here"
   ```

   确保将 `.env` 文件添加到 `.gitignore` 以防提交到 git。

   **方式二：在 shell 中设置环境变量：**

   ```bash
   export D1_DATABASE_ID="your-database-id-goes-here"
   wrangler deploy
   ```

5. **下载前端（Web Vault）：**

   ```bash
   # 默认固定版本（可通过导出 BW_WEB_VERSION 覆盖）
   BW_WEB_VERSION="${BW_WEB_VERSION:-v2026.4.1}"
   if [ "${BW_WEB_VERSION}" = "latest" ]; then
     BW_WEB_VERSION="$(curl -s https://api.github.com/repos/dani-garcia/bw_web_builds/releases/latest | jq -r .tag_name)"
   fi

   # 下载并解压
   wget "https://github.com/dani-garcia/bw_web_builds/releases/download/${BW_WEB_VERSION}/bw_web_${BW_WEB_VERSION}.tar.gz"
   tar -xzf "bw_web_${BW_WEB_VERSION}.tar.gz" -C public/
   rm "bw_web_${BW_WEB_VERSION}.tar.gz"

   # 删除大型 source map 以满足 Cloudflare 静态资源单文件大小限制
   find public/web-vault -type f -name '*.map' -delete
   ```

   **可选：** 应用轻量级 UI 覆盖以生成 `public/web-vault/css/vaultwarden.css`：

   ```bash
   mkdir -p public/web-vault/css/ && cp public/css/vaultwarden.css public/web-vault/css/
   ```

6. **设置数据库并部署 Worker：**

   ```bash
   # 首次部署前仅运行一次
   wrangler d1 execute vault1 --file sql/schema.sql --remote
   # 应用迁移
   wrangler d1 migrations apply vault1 --remote

   # （可选）向 D1 种子化全局等效域名
   # 默认下载 Vaultwarden 的 global_domains.json
   bash scripts/seed-global-domains.sh --db vault1 --remote
   
   wrangler deploy
   ```

   这将部署 Worker 并设置必要的数据库表。

7. **设置环境变量（Secret）：**

   - `ALLOWED_EMAILS` your-email@example.com（支持 glob 模式如 `*@example.com`，逗号分隔；不设则开放注册）
   - `JWT_SECRET` 一段长随机字符串
   - `JWT_REFRESH_SECRET` 一段长随机字符串

   **可选移动端推送中继设置：**
   - `PUSH_ENABLED=true`、`PUSH_RELAY_URI`、`PUSH_IDENTITY_URI`（文本变量）
   - `PUSH_INSTALLATION_ID`、`PUSH_INSTALLATION_KEY`（密钥变量）
   - 详见 [移动推送通知](../README.zh-CN.md#实时同步与推送通知)

   **可选高级功能设置（详见 [README](../README.zh-CN.md)）：**

   | 功能 | 变量 | 说明 |
   |------|------|------|
   | Admin 面板 | `ADMIN_TOKEN`（secret） | 启用 `/admin` 管理面板 |
   | SSO 单点登录 | `SSO_ENABLED`、`SSO_AUTHORITY`、`SSO_CLIENT_ID`（var）、`SSO_CLIENT_SECRET`（secret） | OIDC 单点登录；多租户用 `SSO_TENANTS`（JSON 数组） |
   | Key Connector | `KEY_CONNECTOR_ENABLED`、`KEY_CONNECTOR_URL`（var） | SSO 用户免主密码解锁 |
   | 微软 Graph | `MSGRAPH_TENANT_ID`、`MSGRAPH_CLIENT_ID`、`MSGRAPH_USER`（var）、`MSGRAPH_CLIENT_SECRET`（secret） | Exchange 邮件 + OneDrive 存储；设 `MAIL_PROVIDER=msgraph` 启用邮件 |
   | 邮件（Resend） | `MAIL_PROVIDER=resend`、`RESEND_API_KEY`（secret）、`MAIL_FROM`（var） | 使用 Resend 发邮件 |
   | 邮件（Webhook） | `MAIL_PROVIDER=webhook`、`MAIL_WEBHOOK_URL`（var） | 自定义 HTTP 中继发邮件 |
   | Yubikey 2FA | `YUBICO_CLIENT_ID`（var）、`YUBICO_SECRET_KEY`（secret） | YubiKey 硬件密钥 |
   | Duo 2FA | `DUO_IKEY`、`DUO_HOST`（var）、`DUO_SKEY`（secret） | Duo Security |
   | WebAuthn | 无需配置 | 纯 Rust 实现，WASM 兼容 |
   | SCIM 目录同步 | 数据库配置组织 API key | 见 [README](../README.zh-CN.md#scim-目录同步) |

8. **配置 Bitwarden 客户端：**

   在 Bitwarden 客户端中，进入自托管登录页面，输入你部署的 Worker URL。

   > [!NOTE]
   > 默认禁用 `*.workers.dev` 域名（可能抛出 1101 错误）。强烈建议使用自定义域名，详见 [配置自定义域名](../README.zh-CN.md)。

## GitHub Actions CI/CD 部署

本项目包含 GitHub Actions 工作流用于自动部署。这是生产环境的推荐方式，可确保一致的构建和部署。

### 必需的 Secrets

在你的 GitHub 仓库中添加以下密钥（`Settings > Secrets and variables > Actions`）：

| Secret | 必需 | 说明 |
|--------|------|------|
| `CLOUDFLARE_API_TOKEN` | 是 | Cloudflare API 令牌 |
| `CLOUDFLARE_ACCOUNT_ID` | 是 | Cloudflare 账户 ID |
| `D1_DATABASE_ID` | 是 | 生产环境 D1 数据库 ID |
| `D1_DATABASE_ID_DEV` | 否 | 开发环境 D1 数据库 ID（仅在 `dev` 分支使用 Deploy Dev 工作流时需要） |

#### 如何获取 Cloudflare 账户 ID

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 选择你的账户
3. 账户 ID 显示在 Overview 页面右侧栏，或 URL 中：`https://dash.cloudflare.com/<account-id>`

#### 如何获取 Cloudflare API 令牌

`CLOUDFLARE_API_TOKEN` 需要以下权限：
- **Edit Cloudflare Workers**：部署 Worker 所需
- **Edit D1**：数据库迁移和备份所需
- **Edit KV**：附件存储所需（如果使用 KV）

1. 访问 [https://dash.cloudflare.com/profile/api-tokens](https://dash.cloudflare.com/profile/api-tokens)
2. 点击 **Create Token**
3. 使用 **Edit Cloudflare Workers** 模板
4. 在 `Permissions` 下添加 **Account** → **D1**
5. 选择 `Account Resources` 和 `Zone Resources`
6. 点击 **Continue to Summary**，然后 **Create Token**

### 可选变量

#### Web Vault 前端版本

可通过 GitHub Actions 变量固定/覆盖 Web Vault（bw_web_builds）版本：

| 变量 | 适用环境 | 默认值 | 示例 | 说明 |
|------|----------|--------|------|------|
| `BW_WEB_VERSION` | 生产（`main/uat/release*`） | `v2026.4.1` | `v2026.4.1` | 设为 `latest` 跟踪上游最新版本 |
| `BW_WEB_VERSION_DEV` | 开发（`dev`） | `v2026.4.1` | `v2026.4.1` | 设为 `latest` 跟踪上游最新版本 |

#### 全局等效域名

Bitwarden 客户端使用 `globalEquivalentDomains` 在已知域名组之间进行 URI 匹配。

为避免将大型 JSON 文件打包进 Worker，数据集可存储在 D1 中并在部署时种子化。

| 变量 | 适用环境 | 默认值 | 示例 | 说明 |
|------|----------|--------|------|------|
| `SEED_GLOBAL_DOMAINS` | 生产 + 开发 | `true` | `false` | 设为 `false` 跳过种子化（API 返回空列表） |
| `GLOBAL_DOMAINS_URL` | 生产 | （空） | raw GitHub URL | 可选：固定特定 Vaultwarden tag/commit |
| `GLOBAL_DOMAINS_URL_DEV` | 开发 | （空） | raw GitHub URL | 同生产，用于 dev 工作流 |

如果跳过种子化，`/api/settings/domains` 和 `/api/sync` 将返回 `globalEquivalentDomains: []`。

### 使用步骤

1. **Fork 或克隆仓库**到你的 GitHub 账户

2. **配置必需的密钥**（仓库设置中）

3. **（可选）为附件启用 R2 存储桶：**

   Warden 默认使用 KV 存储附件。如果你想使用 R2：

   1. **在 Cloudflare Dashboard 中创建 R2 存储桶：**
      - 进入 **Storage & databases** → **R2** → **Create bucket**
      - 创建生产存储桶（如 `warden-attachments`）

   2. **将存储桶名称添加为 GitHub Action secret：**
      - `R2_NAME` → 生产存储桶名称

   当这些 secret 存在时，工作流会自动将 `ATTACHMENTS_BUCKET` 绑定附加到 `wrangler.toml`，无需在 Cloudflare 控制台手动绑定。

4. **从 GitHub Actions 标签页手动触发 `Build` Action**

5. **在仓库的 Actions 标签页监控部署**

6. **在 Cloudflare Dashboard 中设置环境变量（secret）：**
   - `ALLOWED_EMAILS` your-email@example.com（支持 glob 模式如 `*@example.com`，逗号分隔；不设则开放注册）
   - `JWT_SECRET` 一段长随机字符串
   - `JWT_REFRESH_SECRET` 一段长随机字符串
   - 可选移动端推送设置：
     `PUSH_ENABLED=true`、`PUSH_RELAY_URI`、`PUSH_IDENTITY_URI`、`PUSH_INSTALLATION_ID`、`PUSH_INSTALLATION_KEY`
   - 可选高级功能（详见 [README](../README.zh-CN.md)）：
     `ADMIN_TOKEN`、`SSO_*`、`KEY_CONNECTOR_*`、`MSGRAPH_*`、`MAIL_*`、`YUBICO_*`、`DUO_*`

> [!IMPORTANT]
> 服务器没有这三个环境变量无法工作：`ALLOWED_EMAILS`（可选）、`JWT_SECRET`、`JWT_REFRESH_SECRET`。如果忘记设置，服务器会崩溃。

如果想在客户端前端显示"创建账户"按钮，可添加 `DISABLE_USER_REGISTRATION` 为 `text` 并设为 `false`。详见 [环境变量](../README.zh-CN.md#基础配置)。

默认禁用 `*.workers.dev` 域名（可能抛出 1101 错误）。强烈建议使用自定义域名，详见 [配置自定义域名](../README.zh-CN.md)。
