#!/usr/bin/env python3
"""
CordCloud 每日签到 / CordCloud daily check-in.

复刻并修复自 https://github.com/zhchaoxing/cordcloud-action
Replicates & fixes https://github.com/zhchaoxing/cordcloud-action

所有凭据从环境变量读取（由 GitHub Actions Secrets 注入），脚本本身不含任何密码。
All credentials come from environment variables (injected from GitHub Secrets);
no secret is ever hard-coded here.

Env vars:
  CC_EMAIL   (required)  账号邮箱 / account email
  CC_PASSWD  (required)  账号密码 / account password
  CC_SECRET  (optional)  两步验证 TOTP 密钥 / 2-step TOTP secret
  CC_HOST    (optional)  逗号分隔的域名列表 / comma-separated hosts
"""
import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

import requests
import urllib3

try:
    import pyotp
except ImportError:  # pyotp only needed when a TOTP secret is set
    pyotp = None

urllib3.disable_warnings()

DEFAULT_HOSTS = "cordcloud.us,cordcloud.one,cordcloud.biz,cordc.net"
# A realistic browser UA — many panels / Cloudflare reject the default
# python-requests UA with a 403 or an HTML challenge page (which then breaks
# .json()). This header is the single most common reason check-in bots fail.
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "X-Requested-With": "XMLHttpRequest",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}


def _now() -> str:
    tz = timezone(timedelta(hours=8))  # Asia/Shanghai
    return datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")


def info(msg: str = "") -> None:
    print(f"[{_now()}] {msg}", flush=True)


def warning(msg: str = "") -> None:
    # GitHub Actions annotation + readable line
    print(f"::warning::[{_now()}] {msg}", flush=True)


def error(msg: str = "") -> None:
    print(f"::error::[{_now()}] {msg}", flush=True)


class CordCloud:
    def __init__(self, email: str, passwd: str, code: str = "", host: str = "cordcloud.us"):
        self.email = email
        self.passwd = passwd
        self.code = code
        self.host = host.replace("https://", "").replace("http://", "").strip("/ ")
        self.session = requests.session()
        self.session.headers.update(BROWSER_HEADERS)
        self.timeout = 15

    def _url(self, path: str) -> str:
        return f"https://{self.host}/{path}"

    def _post_json(self, path: str, data: dict | None = None) -> dict:
        r = self.session.post(self._url(path), data=data or {},
                              timeout=self.timeout, verify=False,
                              headers={"Referer": self._url("auth/login")})
        # Panels sometimes answer with an HTML challenge/error page instead of
        # JSON; surface that clearly instead of a bare JSONDecodeError.
        try:
            return r.json()
        except ValueError:
            raise RuntimeError(
                f"{path} 返回非 JSON (HTTP {r.status_code})，可能被 WAF/Cloudflare 拦截或域名已失效")

    def _csrf_token(self) -> str:
        # CordCloud/SSPanel now guards login with a session-bound CSRF token:
        # GET the login page first to obtain the PHPSESSID cookie plus a hidden
        # <input name="csrf_token" value="..."> that must be echoed on POST.
        # Skipping this is what makes a bare POST fail with
        # "CSRF Token 验证失败, 请尝试刷新页面或更换浏览器".
        r = self.session.get(self._url("auth/login"), timeout=self.timeout, verify=False)
        tag = re.search(r'<input[^>]*name=["\']csrf_token["\'][^>]*>', r.text, re.I)
        if tag:
            val = re.search(r'value=["\']([^"\']+)["\']', tag.group(0))
            if val:
                return val.group(1)
        return ""

    def _altcha_payload(self) -> str:
        # CordCloud protects login with ALTCHA — a self-hosted proof-of-work
        # captcha (not a human-interaction one). The browser widget auto-solves
        # it on load; we do the same: fetch the signed challenge, brute-force the
        # number n where SHA-256(salt + n) == challenge, then base64-encode the
        # solution as the `altcha` form field. Skipping it => login is rejected
        # with "系统无法接受您的验证结果". (This is legitimate: the PoW is meant
        # to be computed by the client.)
        r = self.session.get(self._url("auth/altcha/challenge"), timeout=self.timeout, verify=False)
        try:
            c = r.json()
        except ValueError:
            return ""  # ALTCHA not enabled on this host
        algo = c.get("algorithm", "SHA-256").replace("-", "").lower()
        salt, target = c["salt"], c["challenge"]
        maxnum = int(c.get("maxnumber", c.get("maxNumber", 1_000_000)))
        for n in range(maxnum + 1):
            if hashlib.new(algo, f"{salt}{n}".encode()).hexdigest() == target:
                solution = {
                    "algorithm": c["algorithm"],
                    "challenge": target,
                    "number": n,
                    "salt": salt,
                    "signature": c["signature"],
                }
                return base64.b64encode(json.dumps(solution).encode()).decode()
        return ""

    def login(self) -> dict:
        data = {
            "email": self.email,
            "passwd": self.passwd,
            "code": self.code,
            "csrf_token": self._csrf_token(),
        }
        altcha = self._altcha_payload()
        if altcha:
            data["altcha"] = altcha
        return self._post_json("auth/login", data)

    def check_in(self) -> dict:
        return self._post_json("user/checkin")

    def traffic(self) -> tuple:
        r = self.session.get(self._url("user"), timeout=self.timeout, verify=False)
        # When the panel omits charset in Content-Type, requests defaults to
        # latin-1 and mangles the Chinese labels — force a real decode so the
        # regexes below can match.
        r.encoding = r.apparent_encoding or "utf-8"
        html = r.text
        today = re.search(r'今日已用</span>.*?<code[^>]*>(.*?)</code>', html, re.S)
        past = re.search(r'过去已用</span>.*?<code[^>]*>(.*?)</code>', html, re.S)
        rest = re.search(r'剩余流量</span>.*?<code[^>]*>(.*?)</code>', html, re.S)
        if today and past and rest:
            return today.group(1).strip(), past.group(1).strip(), rest.group(1).strip()
        return ()


def _load_cookie() -> str:
    # Cookie string comes either inline (CC_COOKIE) or from a file (CC_COOKIE_FILE,
    # written by the one-time login helper and refreshed after each run).
    ck = os.environ.get("CC_COOKIE", "").strip()
    if ck:
        return ck
    path = os.environ.get("CC_COOKIE_FILE", "").strip()
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    return ""


def _save_cookie(cc: "CordCloud") -> None:
    path = os.environ.get("CC_COOKIE_FILE", "").strip()
    if not path:
        return
    pairs = "; ".join(f"{c.name}={c.value}" for c in cc.session.cookies)
    if pairs:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(pairs)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def run_cookie(cookie: str) -> int:
    # Reuse an existing logged-in session — no login, so no captcha / no
    # unfamiliar-device email. The session is IP-bound (SSPanel `key`/`ip`
    # cookies), so this must run from the same IP the cookie was created on.
    host = (os.environ.get("CC_HOST", "").strip().split(",")[0].strip() or "cordc.net")
    cc = CordCloud("", "", host=host)
    for part in cookie.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            cc.session.cookies.set(k, v, domain=cc.host)
    # Are we actually logged in? A guest gets 302 -> /auth/login.
    r = cc.session.get(cc._url("user"), timeout=cc.timeout, verify=False, allow_redirects=False)
    if r.status_code != 200:
        error(f"cookie 已失效(GET /user -> {r.status_code})，请在本机重跑一次登录助手刷新 cookie")
        return 2
    try:
        res = cc.check_in()
    except Exception as e:  # noqa: BLE001
        error(f"签到异常：{e}")
        return 1
    msg = res.get("msg", "")
    if res.get("ret") != 1 and "您似乎已经签到过" not in msg:
        warning(f"签到失败：{msg}")
        _save_cookie(cc)
        return 1
    info(f"签到结果：{msg}")
    t = cc.traffic()
    if t:
        info(f"流量：今日已用 {t[0]}, 过去已用 {t[1]}, 剩余 {t[2]}")
    _save_cookie(cc)  # persist any refreshed cookies (sliding session)
    info("CordCloud 签到成功结束 ✅（cookie 模式）")
    return 0


def run() -> int:
    cookie = _load_cookie()
    if cookie:
        return run_cookie(cookie)

    email = os.environ.get("CC_EMAIL", "").strip()
    passwd = os.environ.get("CC_PASSWD", "").strip()
    secret = os.environ.get("CC_SECRET", "").strip()
    host_input = os.environ.get("CC_HOST", "").strip() or DEFAULT_HOSTS

    if not email or not passwd:
        error("缺少 CC_EMAIL / CC_PASSWD（请在仓库 Settings → Secrets 中配置）")
        return 1

    code = ""
    if secret:
        if pyotp is None:
            error("设置了 CC_SECRET 但未安装 pyotp")
            return 1
        code = pyotp.TOTP(secret).now()

    hosts = [h.strip() for h in host_input.split(",") if h.strip()]
    info(f"将依次尝试 {len(hosts)} 个 host")

    for h in hosts:
        info(f"当前尝试 host：{h}")
        cc = CordCloud(email, passwd, code=code, host=h)
        try:
            res = cc.login()
            if res.get("ret") != 1:
                warning(f"登录失败：{res.get('msg', '未知错误')}，尝试下一个 host")
                continue
            info(f"登录成功：{res.get('msg', '')}")

            res = cc.check_in()
            msg = res.get("msg", "")
            if res.get("ret") != 1 and "您似乎已经签到过" not in msg:
                warning(f"签到失败：{msg}，尝试下一个 host")
                continue
            info(f"签到结果：{msg}")

            traffic = res.get("trafficInfo")
            if not traffic:
                t = cc.traffic()
                if t:
                    traffic = {"todayUsedTraffic": t[0], "lastUsedTraffic": t[1], "unUsedTraffic": t[2]}
            if traffic:
                info(f"流量：今日已用 {traffic['todayUsedTraffic']}, "
                     f"过去已用 {traffic['lastUsedTraffic']}, 剩余 {traffic['unUsedTraffic']}")

            info("CordCloud 签到成功结束 ✅")
            return 0
        except Exception as e:  # noqa: BLE001 — try the next host on any error
            warning(f"host {h} 异常：{e}")

    error("所有 host 都签到失败 ❌")
    return 1


if __name__ == "__main__":
    sys.exit(run())
