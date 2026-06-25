# 数据库备份、恢复与时间旅行

> [!NOTE]
> 📖 English documentation: [db-backup-recovery.md](db-backup-recovery.md) / 英文文档见 [db-backup-recovery.md](db-backup-recovery.md)

集中管理 D1 运维手册：备份自动化、恢复流程和时间点恢复。

## GitHub Actions 备份

> [!NOTE]
> 要使用此备份功能，你必须 fork 本仓库并提前配置所需的 Cloudflare 密钥，如 [CI/CD 部署](deployment.zh-CN.md#github-actions-cicd-部署) 中所述：`CLOUDFLARE_API_TOKEN`、`CLOUDFLARE_ACCOUNT_ID` 和 `D1_DATABASE_ID`（如果需要备份 `dev`，还需 `D1_DATABASE_ID_DEV`）。

本项目包含一个 GitHub Action 工作流，可自动导出 D1 数据库并将备份上传到一个或多个目标（S3 兼容存储和/或 WebDAV）。备份每天 04:00 UTC 运行（在清理任务之后 1 小时）。

> [!NOTE]
> - **首次运行需手动触发：** 你必须手动触发一次 Action（GitHub Actions → Backup D1 Database (S3/WebDAV) → Run workflow），之后定时备份才会自动运行。
> - **确保 S3 存储桶设为私有访问**，防止数据泄露并避免不必要的公网流量费用。
> - **⚠️ 关键：切勿使用与你的 Worker 相同的 Cloudflare 账户的 R2 做备份。** 如果你的 Cloudflare 账户被暂停或封禁，你将同时失去 Worker 和备份存储的访问权，导致完全数据丢失。始终使用独立的 Cloudflare 账户或不同的 S3 兼容存储提供商（AWS S3、Backblaze B2、MinIO 等）做备份，确保冗余和灾难恢复。
> - **目标是按需启用的：** 上传步骤仅在配置了相应密钥时运行。如果既不配置 S3 也不配置 WebDAV，工作流仍会导出/压缩/加密备份，但不会上传到任何地方。

### 备份目标密钥

在你的 GitHub 仓库中添加以下密钥（`Settings > Secrets and variables > Actions`）：

#### S3 兼容存储（可选）

| Secret | 必需 | 说明 |
|--------|------|------|
| `S3_ACCESS_KEY_ID` | 是（S3） | S3 访问密钥 ID |
| `S3_SECRET_ACCESS_KEY` | 是（S3） | S3 秘密访问密钥 |
| `S3_BUCKET` | 是（S3） | 存储备份的 S3 存储桶名称 |
| `S3_REGION` | 是（S3） | S3 区域（如 `us-east-1`）。不确定则用 `auto` |
| `S3_ENDPOINT` | 否 | 自定义 S3 端点 URL。不设则默认 AWS S3。S3 兼容服务（MinIO、Cloudflare R2、Backblaze B2 等）必需 |

#### WebDAV（可选）

| Secret | 必需 | 说明 |
|--------|------|------|
| `WEBDAV_URL` | 是（WebDAV） | WebDAV 端点 URL（如 Nextcloud：`https://example.com/remote.php/dav/files/<user>/`） |
| `WEBDAV_USER` | 是（WebDAV） | WebDAV 用户名 |
| `WEBDAV_PASSWORD` | 是（WebDAV） | WebDAV 密码 |
| `WEBDAV_VENDOR` | 否 | rclone 的 WebDAV 厂商（`nextcloud`、`owncloud` 或 `other`）。默认 `other` |
| `WEBDAV_BASE_PATH` | 否 | 远程备份基础路径。默认 `warden-worker` |

#### 通用（可选）

| Secret | 必需 | 说明 |
|--------|------|------|
| `BACKUP_ENCRYPTION_KEY` | 否 | 可选加密口令。设置后备份将用 AES-256 加密。**强烈推荐**，因为数据库包含未加密的用户元数据（邮箱、条目数量） |
| `BACKUP_RETENTION_DAYS` | 否 | 保留备份的天数。默认 30 |

> [!WARNING]
> **GitHub 会在仓库 60 天无活动后自动禁用定时工作流。** 如果你的 fork 在 60 天内默认分支没有提交，GitHub 将禁用备份工作流（及所有其他 cron 触发的工作流）。在此之前你会收到邮件通知。为防止此情况，定期[同步你的 fork](../README.zh-CN.md) 与上游（如果产生了提交），或从 Actions 标签页手动重新启用工作流。详见 [GitHub 文档：禁用和启用工作流](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/disable-and-enable-workflows)。

### 备份功能

- **自动每日备份：** 生产数据库每天 04:00 UTC 自动备份
- **手动触发：** 可从 GitHub Actions 标签页手动触发备份
- **环境选择：** 手动触发时可选择备份 `production` 或 `dev` 数据库
- **压缩：** 备份使用 gzip 压缩以节省存储空间
- **可选加密：** 如果设置了 `BACKUP_ENCRYPTION_KEY`，备份将用 AES-256-CBC 加密（PBKDF2 密钥派生，10 万次迭代）
- **自动清理：** 超过 30 天的旧备份自动删除
- **基于目标的上传：** 上传步骤仅在配置了目标密钥时运行
- **S3 兼容：** 兼容 AWS S3、Cloudflare R2、MinIO、Backblaze B2 及任何 S3 兼容存储
- **WebDAV：** 兼容大多数 WebDAV 服务器（包括 Nextcloud/ownCloud）

### 备份文件位置

备份按以下结构存储：

```
# 未加密备份
s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz

# 加密备份（设置了 BACKUP_ENCRYPTION_KEY 时）
s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc

# WebDAV 备份（WEBDAV_BASE_PATH 默认为 warden-worker）
<WEBDAV_BASE_PATH>/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz
<WEBDAV_BASE_PATH>/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc
```

### 解密备份

如果启用了加密，使用以下命令解密备份：

```bash
openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
  -in vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc \
  -out backup.sql.gz \
  -pass pass:"你的加密密钥"

# 然后解压
gunzip backup.sql.gz
```

### 恢复数据库到 Cloudflare D1

1. **从 S3 下载备份：**

   ```bash
   # 使用 AWS CLI
   aws s3 cp s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc ./
   
   # 或使用自定义端点（如 R2、MinIO）
   aws s3 cp s3://your-bucket/warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc ./ \
     --endpoint-url https://your-s3-endpoint.com
   ```

   或从 WebDAV 下载（使用 rclone）：

   ```bash
   rclone copy webdav:warden-worker/production/vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc ./
   ```

2. **解密备份（如果已加密）：**

   ```bash
   openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
     -in vault1_prod_YYYY-MM-DD_HH-MM-SS.sql.gz.enc \
     -out backup.sql.gz \
     -pass pass:"你的加密密钥"
   ```

3. **解压备份：**

   ```bash
   gunzip backup.sql.gz
   ```

4. **恢复到 Cloudflare D1：**

   首先使用 wrangler 查找数据库名称：

   ```bash
   wrangler d1 list
   ```

   这将显示数据库列表。查找 `name` 列（如生产环境 `warden-db`，开发环境 `warden-dev`）。

   然后恢复备份：

   ```bash
   # 将 DATABASE_NAME 替换为你的实际数据库名称（如 warden-db）
   
   # 首先，你可能想清空现有数据库（可选，谨慎使用！）
   # wrangler d1 execute DATABASE_NAME --remote --command "DELETE FROM ciphers; DELETE FROM folders; DELETE FROM users;"
   
   # 导入备份
   wrangler d1 execute DATABASE_NAME --remote --file=backup.sql
   ```

   > [!NOTE]
   > `--remote` 标志用于对生产 D1 数据库执行操作。不加此标志将针对本地开发数据库执行。

   > ⚠️ **故障排除：`no such table: main.users` 错误**
   > 
   > 如果导入时遇到此错误，是因为 `wrangler d1 export` 输出表的顺序可能不遵守外键依赖（如 `folders` 表在 `users` 表之前创建，但 `folders` 有引用 `users` 的外键）。
   > 
   > **解决方案：** 在 backup.sql 文件开头添加 `PRAGMA foreign_keys=OFF;` 以在导入时禁用外键检查：
   > 
   > ```bash
   > # 在备份文件前添加 PRAGMA 语句
   > echo -e "PRAGMA foreign_keys=OFF;\n$(cat backup.sql)" > backup.sql
   > 
   > # 然后照常导入
   > wrangler d1 execute DATABASE_NAME --remote --file=backup.sql
   > ```
   > 
   > 或者，手动重新排序备份文件中的 SQL 语句，确保父表（`users`）在子表（`folders`、`ciphers`）之前创建。

## D1 时间旅行（时间点恢复）

Cloudflare D1 提供内置的时间旅行功能，允许你在过去 30 天内的任何时间点恢复数据库。这在不需备份的情况下撤销意外的数据修改或删除非常有用。

使用时间旅行：

1. **检查当前恢复书签：**

   ```bash
   # 将 DATABASE_NAME 替换为你的实际数据库名称（如 warden-db）
   wrangler d1 time-travel info DATABASE_NAME
   ```

2. **恢复到特定时间戳：**

   ```bash
   # 恢复到特定时间点（ISO 8601 格式）
   wrangler d1 time-travel restore DATABASE_NAME --timestamp=2024-01-15T12:00:00Z
   
   # 或恢复到特定书签
   wrangler d1 time-travel restore DATABASE_NAME --bookmark=<bookmark_id>
   ```

> [!NOTE]
> 时间旅行在免费套餐中保留 30 天数据。详见 [Cloudflare D1 时间旅行文档](https://developers.cloudflare.com/d1/reference/time-travel/)。
