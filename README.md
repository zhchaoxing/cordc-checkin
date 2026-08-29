# cordc-checkin

CordCloud（SSPanel 机场）每日自动签到，跑在 GitHub Actions 上，无需服务器。
Automated daily check-in for CordCloud (SSPanel airport), running on GitHub
Actions — no server needed.

> 复刻并修复自 / Replicated & fixed from
> [`zhchaoxing/cordcloud-action`](https://github.com/zhchaoxing/cordcloud-action)
> （原项目 Fork 自 `yanglbme/cordcloud-action`）。

## 有什么不同 / What changed

- **修复被拦截**：带上真实浏览器 `User-Agent` 等请求头 —— 原版裸 `python-requests`
  UA 常被机场/Cloudflare 403 或返回 HTML，导致 `.json()` 直接崩。
  *Fix "blocked" failures*: sends real browser headers; the original bare
  `python-requests` UA is often 403'd / served an HTML challenge (which then
  breaks `.json()`).
- **修复控制流**：登录失败会**立即换下一个 host**，不再用未登录的 session 去签到。
  *Fix control flow*: on login failure it moves to the next host instead of
  calling check-in on an unauthenticated session.
- **更快更简单**：改成 **纯脚本 + 定时 workflow**，不再每次构建 Docker 镜像，
  也不依赖可能失效的上游 Action。
  *Simpler & faster*: plain script + scheduled workflow — no per-run Docker
  build, no dependency on a possibly-dead upstream action.
- 非 JSON 响应给出清晰报错；错误正确走 GitHub Actions 注解。
  Clear errors on non-JSON responses; proper GitHub Actions annotations.

## 怎么用 / Setup

1. **Fork / 使用这个仓库**（保持 private 也行，Actions 一样能跑）。
   Fork or use this repo (a private repo works fine too).
2. 到 **Settings → Secrets and variables → Actions → New repository secret**，
   添加：
   Add these repository secrets:

   | Secret | 必填 / Required | 说明 / Description |
   |--------|:---:|-------------------|
   | `CC_EMAIL`  | ✅ | 账号邮箱 / account email |
   | `CC_PASSWD` | ✅ | 账号密码 / account password |
   | `CC_SECRET` | ⬜ | 两步验证 TOTP 密钥（开了 2FA 才需要）/ 2-step TOTP secret |
   | `CC_HOST`   | ⬜ | 逗号分隔的域名，覆盖默认列表 / comma-separated hosts override |

3. 到 **Actions** 页启用 workflow。默认每天 **北京时间 09:00** 自动签到；
   也可在 Actions 页点 **Run workflow** 手动触发。
   Enable workflows in the **Actions** tab. Runs daily at **09:00 Asia/Shanghai**;
   you can also trigger it manually via **Run workflow**.

## 安全 / Security

- 所有凭据只存 **GitHub Secrets**，通过环境变量注入；**代码与日志里不含任何密码/密钥**。
  All credentials live only in **GitHub Secrets**, injected via env vars; no
  password/secret is ever written to code or logs.
- 本仓库是公开的（public）—— 请**不要**把邮箱/密码写进任何文件或提交里。
  This repo is public — **never** commit your email/password into any file.

## 本地测试 / Local test

```bash
pip install -r requirements.txt
export CC_EMAIL='you@example.com'
export CC_PASSWD='********'
# export CC_SECRET='XXXX...'   # 可选 / optional
python checkin.py
```

默认域名 / default hosts: `cordcloud.us, cordcloud.one, cordcloud.biz, c-cloud.xyz, cordc.net`
（用 `CC_HOST` 覆盖 / override with `CC_HOST`）。

## License

MIT
