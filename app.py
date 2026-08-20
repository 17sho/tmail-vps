import imaplib
import html as html_lib
import json
import os
import re
import secrets
import threading
import time
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.header import decode_header
from email.utils import parsedate_to_datetime
from pathlib import Path

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CONFIG_FILE = DATA_DIR / "config.json"
VIEW_LOG_FILE = DATA_DIR / "view_logs.json"

DEFAULT_CONFIG = {
    "accounts": [],
    "search_since_days": 2,
    "max_emails": 20,
    "admin_password_hash": "",
    "blacklist": [],
    "max_concurrency": 4,
    "imap_timeout_seconds": 12,
    "code_rules": {"keywords": ["验证码", "校验码", "动态码", "安全码", "临时代码", "临时登录代码", "登录代码", "verification code", "security code", "one-time code", "otp", "pin", "access code", "launch code", "code"], "min_length": 4, "max_length": 8, "allow_alphanumeric": True},
    "share_links": [],
}

ACCOUNT_DEFAULTS = {
    "id": "", "account_name": "mail1", "provider": "custom", "enabled": True,
    "imap_host": "", "imap_port": 993, "use_ssl": True, "imap_user": "",
    "imap_password": "", "mailbox": "INBOX", "priority": 100, "timeout_seconds": 12,
}

PROVIDER_PRESETS = {
    "gmail": {"imap_host": "imap.gmail.com", "imap_port": 993, "use_ssl": True},
    "qq": {"imap_host": "imap.qq.com", "imap_port": 993, "use_ssl": True},
    "outlook": {"imap_host": "outlook.office365.com", "imap_port": 993, "use_ssl": True},
    "icloud": {"imap_host": "imap.mail.me.com", "imap_port": 993, "use_ssl": True},
    "netease163": {"imap_host": "imap.163.com", "imap_port": 993, "use_ssl": True},
    "netease126": {"imap_host": "imap.126.com", "imap_port": 993, "use_ssl": True},
    "sina": {"imap_host": "imap.sina.com", "imap_port": 993, "use_ssl": True},
    "yahoo": {"imap_host": "imap.mail.yahoo.com", "imap_port": 993, "use_ssl": True},
    "zoho": {"imap_host": "imap.zoho.com", "imap_port": 993, "use_ssl": True},
}

MAIL_CACHE_TTL_SECONDS = 15.0
_LOGIN_ATTEMPTS: dict[str, list[float]] = {}
_LOGIN_LOCK = threading.Lock()
_LOGIN_WINDOW_SECONDS = 300
_LOGIN_MAX_ATTEMPTS = 8
_FILE_LOCK = threading.RLock()
_MAIL_CACHE: dict[str, tuple[float, dict]] = {}
_MAIL_CACHE_LOCK = threading.Lock()
_QUERY_ATTEMPTS: dict[str, list[float]] = {}
_QUERY_LOCK = threading.Lock()
_QUERY_WINDOW_SECONDS = 60
_QUERY_MAX_NEW_TARGETS = 30
_TRUSTED_PROXIES = {"127.0.0.1", "::1"}
IMAP_TIMEOUT_SECONDS = 12
_CIRCUIT_STATE: dict[str, dict] = {}
_CIRCUIT_LOCK = threading.Lock()
_CIRCUIT_FAILURES = 3
_CIRCUIT_COOLDOWN_SECONDS = 300
_PERF_STATS: dict[str, dict] = {}
_PERF_LOCK = threading.Lock()


def clear_mail_cache() -> None:
    with _MAIL_CACHE_LOCK:
        _MAIL_CACHE.clear()

def ensure_config_file() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2), encoding="utf-8")
    if not VIEW_LOG_FILE.exists():
        VIEW_LOG_FILE.write_text("{}", encoding="utf-8")


def normalize_account(raw: dict) -> dict:
    account = ACCOUNT_DEFAULTS.copy()
    account.update(raw)
    account["id"] = str(account.get("id") or secrets.token_hex(6))
    account["imap_port"] = int(account.get("imap_port") or 993)
    account["use_ssl"] = bool(account.get("use_ssl", True))
    account["enabled"] = bool(account.get("enabled", True))
    account["priority"] = max(1, min(999, int(account.get("priority", 100) or 100)))
    account["timeout_seconds"] = max(3, min(60, int(account.get("timeout_seconds", 12) or 12)))
    return account


def load_config() -> dict:
    ensure_config_file()
    try:
        cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        cfg = DEFAULT_CONFIG.copy()

    merged = DEFAULT_CONFIG.copy()
    merged.update(cfg)
    if not isinstance(cfg.get("accounts"), list):
        legacy_user = str(cfg.get("imap_user", "")).strip()
        if legacy_user:
            legacy = normalize_account({
                "id": "legacy-1", "account_name": cfg.get("account_name", "mail1"),
                "provider": "gmail" if cfg.get("imap_host") == "imap.gmail.com" else "custom",
                "imap_host": cfg.get("imap_host", ""), "imap_port": cfg.get("imap_port", 993),
                "use_ssl": cfg.get("use_ssl", True), "imap_user": legacy_user,
                "imap_password": cfg.get("imap_password", ""), "mailbox": cfg.get("mailbox", "INBOX"),
            })
            merged["accounts"] = [legacy]
    merged["accounts"] = [normalize_account(item) for item in merged.get("accounts", []) if isinstance(item, dict)]
    if not isinstance(merged.get("blacklist"), list):
        merged["blacklist"] = []
    merged["blacklist"] = [str(e).strip().lower() for e in merged["blacklist"] if str(e).strip()]
    if not isinstance(merged.get("share_links"), list): merged["share_links"] = []
    if not isinstance(merged.get("code_rules"), dict): merged["code_rules"] = DEFAULT_CONFIG["code_rules"].copy()
    merged["accounts"].sort(key=lambda a: (a.get("priority", 100), a.get("account_name", "")))
    return merged


def _atomic_write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def save_config(cfg: dict) -> None:
    with _FILE_LOCK:
        ensure_config_file()
        merged = load_config()
        merged.update(cfg)
        _atomic_write_json(CONFIG_FILE, merged)
    clear_mail_cache()


def build_account(form, existing: dict | None = None) -> dict:
    provider = str(form.get("provider", "custom")).strip() or "custom"
    account = normalize_account(existing or {})
    account.update(PROVIDER_PRESETS.get(provider, {}))
    account.update({
        "provider": provider,
        "account_name": str(form.get("account_name", "")).strip() or {
            "gmail": "Gmail", "qq": "QQ邮箱", "outlook": "Outlook / Hotmail",
            "icloud": "iCloud Mail", "netease163": "网易163邮箱", "netease126": "网易126邮箱",
            "sina": "新浪邮箱", "yahoo": "Yahoo Mail", "zoho": "Zoho Mail",
        }.get(provider, "自定义邮箱"),
        "enabled": form.get("enabled") in ("on", "true", True, "1"),
        "imap_user": str(form.get("imap_user", "")).strip(),
        "mailbox": str(form.get("mailbox", "INBOX")).strip() or "INBOX",
        "priority": max(1, min(999, int(form.get("priority", account.get("priority", 100)) or 100))),
        "timeout_seconds": max(3, min(60, int(form.get("timeout_seconds", account.get("timeout_seconds", 12)) or 12))),
    })
    if provider == "custom":
        account["imap_host"] = str(form.get("imap_host", "")).strip()
        account["imap_port"] = int(form.get("imap_port", 993) or 993)
        account["use_ssl"] = form.get("use_ssl") in ("on", "true", True, "1")
    password = str(form.get("imap_password", ""))
    if password:
        account["imap_password"] = password
    if not account["imap_user"] or "@" not in account["imap_user"]:
        raise ValueError("邮箱格式不正确")
    if not account["imap_password"]:
        raise ValueError("首次添加必须填写 IMAP 授权码")
    if not account["imap_host"]:
        raise ValueError("IMAP 地址不能为空")
    return normalize_account(account)


def load_view_logs() -> dict:
    ensure_config_file()
    try:
        data = json.loads(VIEW_LOG_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def save_view_logs(data: dict) -> None:
    with _FILE_LOCK:
        ensure_config_file()
        _atomic_write_json(VIEW_LOG_FILE, data)


def log_email_view(target_email: str) -> None:
    with _FILE_LOCK:
        logs = load_view_logs()
        now_cn = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S 北京时间")
        key = target_email.lower().strip()
        if key not in logs:
            logs[key] = {"count": 0, "times": []}
        logs[key]["count"] = int(logs[key].get("count", 0)) + 1
        times = logs[key].get("times", [])
        if not isinstance(times, list):
            times = []
        times.insert(0, now_cn)
        logs[key]["times"] = times[:200]
        save_view_logs(logs)


def get_view_records() -> list[dict]:
    logs = load_view_logs()
    rows = []
    for email, info in logs.items():
        times = info.get("times", []) if isinstance(info.get("times", []), list) else []
        rows.append(
            {
                "email": email,
                "count": int(info.get("count", len(times)) or 0),
                "times": times,
            }
        )
    rows.sort(key=lambda x: x["count"], reverse=True)
    return rows

def search_view_records(query: str = "") -> list[dict]:
    rows = get_view_records()
    q = str(query or "").strip().lower()
    return [row for row in rows if q in row["email"].lower()] if q else rows


def delete_view_record(email: str | None = None) -> int:
    with _FILE_LOCK:
        logs = load_view_logs()
        if email is None:
            count = len(logs)
            save_view_logs({})
            return count
        key = str(email or "").strip().lower()
        existed = key in logs
        logs.pop(key, None)
        save_view_logs(logs)
        return 1 if existed else 0


def get_query_stats() -> dict:
    logs = load_view_logs()
    today = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d")
    total_queries = unique_today = 0
    busiest = []
    for email, info in logs.items():
        times = info.get("times", []) if isinstance(info, dict) else []
        today_count = sum(1 for value in times if str(value).startswith(today))
        if today_count:
            unique_today += 1
            total_queries += today_count
        busiest.append({"email": email, "count": int(info.get("count", len(times)) or 0), "today": today_count})
    busiest.sort(key=lambda row: (row["today"], row["count"]), reverse=True)
    health = []
    for account in load_config().get("accounts", []):
        state = _account_health(account["id"])
        health.append({"name": account["account_name"], "status": state.get("status", "unknown")})
    return {"today_queries": total_queries, "today_unique": unique_today, "total_unique": len(logs), "total_queries": sum(int(v.get("count", 0) or 0) for v in logs.values() if isinstance(v, dict)), "top": busiest[:5], "sources": health}


def normalize_blacklist_entry(value: str) -> str:
    entry = str(value or "").strip().lower()
    valid_full = re.match(r"^[^\s@]{1,64}@[^\s@]+\.[^\s@]+$", entry)
    valid_domain = re.match(r"^@[^\s@]+\.[^\s@]+$", entry)
    if not (valid_full or valid_domain):
        raise ValueError("黑名单格式不正确，请输入完整邮箱或 @域名")
    return entry


def is_blacklisted(target_email: str, blacklist) -> bool:
    if not blacklist:
        return False
    target = str(target_email or "").strip().lower()
    domain = target.split("@", 1)[1] if "@" in target else ""
    return target in blacklist or (f"@{domain}" in blacklist)


def parse_imap_line(raw: str) -> dict:
    parts = [p.strip() for p in (raw or "").split("|")]
    if len(parts) != 5:
        raise ValueError("格式应为: 名称|邮箱|密码|IMAP地址|端口")
    account_name, imap_user, imap_password, imap_host, imap_port = parts
    if not imap_user or "@" not in imap_user:
        raise ValueError("邮箱格式不正确")
    try:
        port = int(imap_port)
    except ValueError as exc:
        raise ValueError("端口必须是数字") from exc
    return {
        "account_name": account_name or "mail1",
        "imap_user": imap_user,
        "imap_password": imap_password,
        "imap_host": imap_host,
        "imap_port": port,
    }


def build_imap_line(cfg: dict) -> str:
    return "|".join(
        [
            str(cfg.get("account_name", "mail1")),
            str(cfg.get("imap_user", "")),
            str(cfg.get("imap_password", "")),
            str(cfg.get("imap_host", "")),
            str(cfg.get("imap_port", "")),
        ]
    )


def verify_admin_password(password: str, cfg: dict | None = None) -> bool:
    cfg = cfg or load_config()
    pwd_hash = cfg.get("admin_password_hash", "")
    if pwd_hash:
        return check_password_hash(pwd_hash, password)
    fallback = os.getenv("ADMIN_PASSWORD", "")
    return bool(fallback) and secrets.compare_digest(password, fallback)


def set_admin_password(new_password: str, cfg: dict | None = None) -> None:
    cfg = cfg or load_config()
    cfg["admin_password_hash"] = generate_password_hash(new_password)
    save_config(cfg)


def decode_mime(value: str) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    out = []
    for text, enc in parts:
        if isinstance(text, bytes):
            out.append(text.decode(enc or "utf-8", errors="ignore"))
        else:
            out.append(text)
    return "".join(out)


def html_to_text(html: str) -> str:
    if not html:
        return ""
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</(p|div|li|tr|h1|h2|h3|h4|h5|h6)>", "\n", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html_lib.unescape(text)
    text = re.sub(r"\r\n?", "\n", text)
    text = re.sub(r"[ \t\u00A0]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text)
    return text.strip()


def normalize_body_text(text: str) -> str:
    if not text:
        return ""
    lines = [re.sub(r"[ \t\u00A0]+", " ", ln).strip() for ln in text.splitlines()]
    compact = []
    blank = False
    for ln in lines:
        if not ln:
            if not blank:
                compact.append("")
            blank = True
            continue
        blank = False
        compact.append(ln)
    return "\n".join(compact).strip()


def extract_verification_codes(subject: str, body: str, rules: dict | None = None) -> list[str]:
    text = f"{subject or ''}\n{body or ''}"
    rules = rules or load_config().get("code_rules", DEFAULT_CONFIG["code_rules"])
    keywords = [str(x).strip() for x in rules.get("keywords", []) if str(x).strip()]
    min_len = max(3, min(12, int(rules.get("min_length", 4))))
    max_len = max(min_len, min(12, int(rules.get("max_length", 8))))
    # 只接受“验证码提示词紧邻候选值”的结构，不能仅因同一邮件出现 code/security
    # 就把年份、时间、订单号或 URL 参数识别成验证码。
    label = r"(?:" + "|".join(re.escape(k).replace(r"\ ", r"\s+") for k in keywords) + r")"
    token = rf"(?P<code>[A-Za-z0-9]{{{min_len},{max_len}}})"
    patterns = [
        re.compile(label + r"[^A-Za-z0-9\n]{0,12}" + token, re.I),
        re.compile(label + r"[^\n]{0,80}?(?:below|如下|：|:)\s*" + token, re.I),
        re.compile(label + r"[^\n]{0,24}?\b(?:is|为|是)\s*" + token, re.I),
        re.compile(r"\b(?:use|enter|输入)\s+" + token + r"[^\n]{0,24}?\b(?:to\s+(?:verify|login)|登录|验证)", re.I),
        re.compile(token + r"[^A-Za-z0-9\n]{0,8}" + label, re.I),
    ]
    found = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            code = match.group("code")
            if code.isalpha() or (not rules.get("allow_alphanumeric", True) and not code.isdigit()):
                continue
            start, end = match.span("code")
            before = text[start - 1] if start else ""
            after = text[end] if end < len(text) else ""
            after_next = text[end + 1] if end + 1 < len(text) else ""
            # 排除域名、邮箱、URL、路径中的片段。
            if (before and before in ".@/_-") or (after and after in "@/_-") or (after == "." and after_next.isalnum()):
                continue
            found.append((start, code.upper()))
    found.sort(key=lambda item: item[0])
    return list(dict.fromkeys(code for _, code in found))[:3]


def format_to_bjt(date_raw: str) -> str:
    if not date_raw:
        return ""
    try:
        dt = parsedate_to_datetime(date_raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        bj_tz = timezone(timedelta(hours=8), name="CST")
        bj = dt.astimezone(bj_tz)
        return bj.strftime("%Y-%m-%d %H:%M:%S 北京时间")
    except Exception:
        return date_raw


def extract_text_from_message(msg) -> str:
    plain_parts = []
    html_parts = []
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if content_type in ("text/plain", "text/html") and "attachment" not in disp.lower():
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    part_text = payload.decode(charset, errors="ignore")
                    if content_type == "text/plain":
                        plain_parts.append(part_text)
                    else:
                        html_parts.append(part_text)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            part_text = payload.decode(charset, errors="ignore")
            if msg.get_content_type() == "text/plain":
                plain_parts.append(part_text)
            else:
                html_parts.append(part_text)

    if plain_parts:
        return normalize_body_text("\n".join(plain_parts))
    if html_parts:
        return normalize_body_text(html_to_text("\n".join(html_parts)))
    return ""


def _friendly_imap_error(exc: Exception) -> str:
    text = str(exc).lower()
    if isinstance(exc, imaplib.IMAP4.error) or "auth" in text or "login" in text:
        return "认证失败，请检查账号和授权码"
    if "timed out" in text or "timeout" in text:
        return "连接超时"
    if "name or service" in text or "resolve" in text:
        return "IMAP 地址无法解析"
    return "连接失败"


def test_account_connection(account: dict) -> dict:
    started = time.monotonic()
    client = None
    try:
        connector = imaplib.IMAP4_SSL if account.get("use_ssl", True) else imaplib.IMAP4
        client = connector(account["imap_host"], int(account["imap_port"]), timeout=int(account.get("timeout_seconds", IMAP_TIMEOUT_SECONDS)))
        client.login(account["imap_user"], account["imap_password"])
        status, _ = client.select(account.get("mailbox", "INBOX"), readonly=True)
        if status != "OK":
            raise RuntimeError("邮箱文件夹不可用")
        return {"ok": True, "message": "连接正常", "elapsed_ms": round((time.monotonic()-started)*1000)}
    except Exception as exc:
        return {"ok": False, "message": _friendly_imap_error(exc), "elapsed_ms": round((time.monotonic()-started)*1000)}
    finally:
        if client:
            try: client.logout()
            except Exception: pass


def _account_health(account_id: str) -> dict:
    with _CIRCUIT_LOCK:
        state = dict(_CIRCUIT_STATE.get(account_id, {}))
    until = float(state.get("open_until", 0))
    if until > time.time():
        state["status"] = "paused"
        state["retry_after"] = max(1, int(until-time.time()))
    return state


def _record_account_result(account: dict, ok: bool, message: str = "") -> None:
    now = datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
    with _CIRCUIT_LOCK:
        state = _CIRCUIT_STATE.setdefault(account["id"], {"failures": 0})
        if ok:
            state.update(status="ok", failures=0, last_success=now, last_error="", open_until=0)
        else:
            failures = int(state.get("failures", 0))+1
            state.update(status="error", failures=failures, last_error=message, last_failure=now)
            if failures >= _CIRCUIT_FAILURES:
                state.update(status="paused", open_until=time.time()+_CIRCUIT_COOLDOWN_SECONDS)


def fetch_account_emails(account: dict, target_email: str, search_since_days: int, max_emails: int) -> list[dict]:
    connector = imaplib.IMAP4_SSL if account.get("use_ssl", True) else imaplib.IMAP4
    client = connector(account["imap_host"], int(account["imap_port"]), timeout=int(account.get("timeout_seconds", IMAP_TIMEOUT_SECONDS)))
    started = time.perf_counter()
    try:
        login_started = time.perf_counter()
        client.login(account["imap_user"], account["imap_password"])
        login_ms = round((time.perf_counter()-login_started)*1000)
        client.select(account.get("mailbox", "INBOX"))
        since_date = (datetime.now(timezone.utc) - timedelta(days=search_since_days)).strftime("%d-%b-%Y")
        status, data = client.search(None, f'(SINCE "{since_date}" TO "{target_email}")')
        if status != "OK":
            raise RuntimeError("搜索邮件失败")
        msg_ids = data[0].split()[-max_emails:]
        msg_ids.reverse()
        emails = []
        for msg_id in msg_ids:
            status, payload = client.fetch(msg_id, "(RFC822)")
            if status != "OK" or not payload or not payload[0]:
                continue
            msg = message_from_bytes(payload[0][1])
            date_raw = msg.get("Date", "")
            body = extract_text_from_message(msg)
            subject = decode_mime(msg.get("Subject", ""))
            emails.append({
                "id": f'{account["id"]}:{msg_id.decode(errors="ignore")}',
                "source": account["account_name"],
                "subject": subject,
                "from": decode_mime(msg.get("From", "")),
                "date": format_to_bjt(date_raw),
                "date_sort": parsedate_to_datetime(date_raw).timestamp() if date_raw else 0,
                "preview": re.sub(r"\s+", " ", body).strip()[:180],
                "body": body.strip(),
                "codes": extract_verification_codes(subject, body),
            })
        elapsed_ms = round((time.perf_counter()-started)*1000)
        with _PERF_LOCK:
            row = _PERF_STATS.setdefault(account["id"], {"queries": 0, "failures": 0})
            row.update(last_ms=elapsed_ms, login_ms=login_ms, emails=len(emails), last_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), queries=int(row.get("queries",0))+1)
            row["avg_ms"] = round(((row.get("avg_ms", elapsed_ms)*(row["queries"]-1))+elapsed_ms)/row["queries"])
        return emails
    finally:
        try:
            client.logout()
        except Exception:
            pass


def fetch_emails(target_email: str) -> dict:
    cfg = load_config()
    accounts = [a for a in cfg.get("accounts", []) if a.get("enabled") and a.get("imap_user") and a.get("imap_password")]
    paused = [a for a in accounts if _account_health(a["id"]).get("status") == "paused"]
    accounts = [a for a in accounts if a not in paused]
    if not accounts:
        return {"ok": False, "error": "管理员尚未配置启用的 IMAP 账号"}
    if is_blacklisted(target_email, cfg.get("blacklist", [])):
        return {"ok": True, "target_email": target_email, "emails": [], "warnings": []}

    emails = []
    warnings = [{"source": a["account_name"], "error": "暂时停用，稍后自动重试"} for a in paused]
    days = int(cfg.get("search_since_days", 2))
    limit = int(cfg.get("max_emails", 20))
    max_workers = max(1, min(len(accounts), int(cfg.get("max_concurrency", 4) or 4), 16))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fetch_account_emails, account, target_email, days, limit): account for account in accounts}
        for future in as_completed(futures):
            account = futures[future]
            try:
                emails.extend(future.result())
                _record_account_result(account, True)
            except Exception as exc:
                error = _friendly_imap_error(exc)
                _record_account_result(account, False, error)
                with _PERF_LOCK:
                    row = _PERF_STATS.setdefault(account["id"], {"queries": 0, "failures": 0}); row["failures"] = int(row.get("failures", 0))+1; row["last_error"] = error
                app.logger.warning("IMAP source failed: %s", account.get("account_name", "unknown"))
                warnings.append({"source": account["account_name"], "error": error})
    emails.sort(key=lambda item: item.pop("date_sort", 0), reverse=True)
    return {"ok": True, "target_email": target_email, "emails": emails, "warnings": warnings}


def fetch_emails_cached(target_email: str, force_refresh: bool = False) -> dict:
    key = target_email.lower().strip()
    now = time.monotonic()
    with _MAIL_CACHE_LOCK:
        cached = _MAIL_CACHE.get(key)
        if not force_refresh and cached and now - cached[0] < MAIL_CACHE_TTL_SECONDS:
            result = deepcopy(cached[1])
            result["cached"] = True
            return result
        if cached:
            _MAIL_CACHE.pop(key, None)

    result = fetch_emails(key)
    result["cached"] = False
    if result.get("ok"):
        with _MAIL_CACHE_LOCK:
            _MAIL_CACHE[key] = (now, deepcopy(result))
            if len(_MAIL_CACHE) > 500:
                oldest = min(_MAIL_CACHE, key=lambda item: _MAIL_CACHE[item][0])
                _MAIL_CACHE.pop(oldest, None)
    return result

def share_public_state(link: dict, now: int | None = None) -> str:
    now = int(time.time()) if now is None else now
    if not link.get("enabled", True):
        return "revoked"
    if int(link.get("expires_at", 0)) <= now:
        return "expired"
    if int(link.get("uses", 0)) >= int(link.get("max_uses", 1)):
        return "exhausted"
    return "active"


def share_status(token: str, email: str = "") -> tuple[dict | None, str]:
    """Return the matching share and a stable status without exposing its email."""
    if not token:
        return None, "missing"
    now = int(time.time())
    cfg = load_config()
    for link in cfg.get("share_links", []):
        if not secrets.compare_digest(str(link.get("token", "")), str(token)):
            continue
        if email and str(link.get("email", "")).lower() != email.lower():
            return None, "invalid"
        if not link.get("enabled", True):
            return None, "revoked"
        if int(link.get("expires_at", 0)) <= now:
            return None, "expired"
        if int(link.get("uses", 0)) >= int(link.get("max_uses", 1)):
            return None, "exhausted"
        return link, "active"
    return None, "invalid"


def active_share(token: str, email: str = "") -> dict | None:
    return share_status(token, email)[0]


def create_share_link(email: str, minutes: int, max_uses: int) -> dict:
    cfg = load_config(); now = int(time.time())
    link = {"token": secrets.token_urlsafe(24), "email": email.lower().strip(), "created_at": now, "expires_at": now + max(1, min(minutes, 10080))*60, "max_uses": max(1, min(max_uses, 1000)), "uses": 0, "enabled": True}
    links = [x for x in cfg.get("share_links", []) if int(x.get("expires_at", 0)) > now][-99:] + [link]
    save_config({"share_links": links}); return link


def consume_share(token: str, email: str) -> bool:
    with _FILE_LOCK:
        cfg = load_config(); link = active_share(token, email)
        if not link: return False
        for item in cfg.get("share_links", []):
            if secrets.compare_digest(str(item.get("token", "")), token): item["uses"] = int(item.get("uses", 0))+1
        save_config({"share_links": cfg["share_links"]}); return True


def performance_stats(cfg: dict | None = None) -> list[dict]:
    cfg = cfg or load_config()
    with _PERF_LOCK: perf = deepcopy(_PERF_STATS)
    return [{"id": a["id"], "name": a["account_name"], "priority": a.get("priority",100), "timeout": a.get("timeout_seconds",12), **perf.get(a["id"], {})} for a in cfg.get("accounts", [])]


app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    MAX_CONTENT_LENGTH=64 * 1024,
)


def client_ip() -> str:
    direct = request.remote_addr or "unknown"
    if direct in _TRUSTED_PROXIES:
        forwarded = request.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
        if forwarded:
            return forwarded[:64]
    return direct[:64]


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _query_rate_limited(ip: str, target: str, is_refresh: bool) -> bool:
    if is_refresh:
        return False
    now = time.monotonic()
    key = f"{ip}:{target}"
    with _QUERY_LOCK:
        recent = [t for t in _QUERY_ATTEMPTS.get(key, []) if now - t < _QUERY_WINDOW_SECONDS]
        if len(recent) >= _QUERY_MAX_NEW_TARGETS:
            _QUERY_ATTEMPTS[key] = recent
            return True
        recent.append(now)
        _QUERY_ATTEMPTS[key] = recent
        if len(_QUERY_ATTEMPTS) > 2000:
            stale = [k for k, values in _QUERY_ATTEMPTS.items() if not values or now - values[-1] >= _QUERY_WINDOW_SECONDS]
            for stale_key in stale:
                _QUERY_ATTEMPTS.pop(stale_key, None)
        return False


@app.context_processor
def inject_template_helpers():
    return {"csrf_token": csrf_token}


@app.before_request
def enforce_admin_csrf():
    if request.method == "POST" and request.path == "/admin":
        provided = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(provided, expected):
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(ok=False, message="安全校验失败，请刷新页面后重试"), 403
            abort(403)


@app.route("/")
def index():
    token = request.args.get("share", "")
    if token:
        share, status = share_status(token)
        if not share:
            messages = {
                "revoked": ("链接已撤销", "该临时查询链接已被管理员撤销，请联系管理员重新生成。"),
                "expired": ("链接已过期", "该临时查询链接已超过有效期，请联系管理员重新生成。"),
                "exhausted": ("使用次数已用完", "该临时查询链接已达到使用次数上限，请联系管理员重新生成。"),
                "invalid": ("链接无效", "该临时查询链接不存在或地址不完整，请检查链接。"),
            }
            title, detail = messages.get(status, messages["invalid"])
            return render_template("share_invalid.html", title=title, detail=detail), 410
        return render_template("index.html", shared_email=share.get("email", ""), share_token=share.get("token", ""))
    return render_template("index.html", shared_email="", share_token="")


@app.post("/api/fetch-emails")
def api_fetch_emails():
    target_email = (request.json or {}).get("email", "").strip()
    if not target_email or "@" not in target_email:
        return jsonify({"ok": False, "error": "请输入有效邮箱"}), 400

    try:
        force_refresh = bool((request.json or {}).get("refresh"))
        share_token = str((request.json or {}).get("share_token", ""))
        if share_token and not active_share(share_token, target_email): return jsonify({"ok": False, "error": "分享链接无效、已过期或已用完"}), 403
        if _query_rate_limited(client_ip(), target_email.lower(), force_refresh):
            return jsonify({"ok": False, "error": "查询过于频繁，请稍后再试"}), 429
        if share_token and not force_refresh and not consume_share(share_token, target_email): return jsonify({"ok": False, "error": "分享链接已失效"}), 403
        # Count a user's explicit query once; background refresh polling must not inflate statistics.
        if not force_refresh:
            log_email_view(target_email)
        result = fetch_emails_cached(target_email, force_refresh=force_refresh)
        status = 200 if result.get("ok") else 400
        return jsonify(result), status
    except Exception as exc:
        app.logger.exception("fetch-emails failed")
        return jsonify({"ok": False, "error": "读取邮件失败，请稍后重试"}), 500


@app.post("/api/fetch-codes")
def api_fetch_codes_compat():
    return api_fetch_emails()


def is_admin() -> bool:
    return bool(session.get("admin_authed"))


def _login_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    with _LOGIN_LOCK:
        recent = [t for t in _LOGIN_ATTEMPTS.get(ip, []) if now - t < _LOGIN_WINDOW_SECONDS]
        _LOGIN_ATTEMPTS[ip] = recent
        return len(recent) >= _LOGIN_MAX_ATTEMPTS


def _record_login_failure(ip: str) -> None:
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS.setdefault(ip, []).append(time.monotonic())


def _clear_login_failures(ip: str) -> None:
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS.pop(ip, None)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if request.path.startswith("/admin"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "GET":
        return render_template("admin_login.html")

    ip = client_ip()
    if _login_rate_limited(ip):
        return render_template("admin_login.html", error="尝试次数过多，请 5 分钟后再试"), 429
    password = request.form.get("password", "")
    if verify_admin_password(password):
        _clear_login_failures(ip)
        session.clear()
        session["admin_authed"] = True
        session["csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True
        return redirect(url_for("admin_dashboard"))

    _record_login_failure(ip)
    return render_template("admin_login.html", error="密码错误"), 401


@app.get("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))


@app.get("/admin/view-records")
def admin_view_records():
    if not is_admin():
        return jsonify(ok=False, message="登录已失效，请重新登录"), 401
    all_records = search_view_records(request.args.get("q", ""))
    per_page = 10
    total = len(all_records)
    pages = max(1, (total + per_page - 1) // per_page)
    try:
        page = int(request.args.get("page", "1"))
    except (TypeError, ValueError):
        page = 1
    page = max(1, min(pages, page))
    start = (page - 1) * per_page
    return jsonify(ok=True, records=all_records[start:start + per_page], page=page, pages=pages, total=total)


@app.route("/admin/tools", methods=["GET", "POST", "DELETE"])
def admin_tools():
    if not is_admin():
        return jsonify(ok=False, message="登录已失效，请重新登录"), 401
    if request.method != "GET":
        provided = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf_token", "")
        if not expected or not provided or not secrets.compare_digest(provided, expected):
            return jsonify(ok=False, message="安全校验失败"), 403
    cfg = load_config()
    action = request.values.get("action", "health")
    if action == "health":
        return jsonify(ok=True, health={a["id"]: _account_health(a["id"]) for a in cfg.get("accounts", [])})
    if action == "stats":
        return jsonify(ok=True, stats=get_query_stats())
    if action == "performance":
        return jsonify(ok=True, performance=performance_stats(cfg))
    if action == "test_code_rules":
        return jsonify(ok=True, codes=extract_verification_codes(request.form.get("subject", ""), request.form.get("body", ""), cfg.get("code_rules")))
    if action == "create_share":
        email = request.form.get("email", "").strip()
        if "@" not in email: return jsonify(ok=False, message="邮箱格式不正确"), 400
        link = create_share_link(email, int(request.form.get("minutes",60)), int(request.form.get("max_uses",1)))
        return jsonify(ok=True, message="分享链接已创建", link={**link, "url": url_for("index", share=link["token"], _external=True)})
    if action == "revoke_share":
        token = request.form.get("token", ""); links = cfg.get("share_links", [])
        for item in links:
            if secrets.compare_digest(str(item.get("token", "")), token): item["enabled"] = False
        save_config({"share_links": links}); return jsonify(ok=True, message="分享链接已撤销")
    if action == "delete_share":
        token = request.form.get("token", "")
        links = [item for item in cfg.get("share_links", []) if not secrets.compare_digest(str(item.get("token", "")), token)]
        if len(links) == len(cfg.get("share_links", [])):
            return jsonify(ok=False, message="分享链接不存在"), 404
        save_config({"share_links": links}); return jsonify(ok=True, message="分享记录已删除")
    if action == "test_account":
        account_id = request.form.get("account_id", "")
        account = next((a for a in cfg.get("accounts", []) if a.get("id") == account_id), None)
        if not account: return jsonify(ok=False, message="邮箱源不存在"), 404
        result = test_account_connection(account)
        _record_account_result(account, result["ok"], result["message"])
        return jsonify(**result, health=_account_health(account_id))
    if action == "reset_circuit":
        account_id = request.form.get("account_id", "")
        with _CIRCUIT_LOCK: _CIRCUIT_STATE.pop(account_id, None)
        return jsonify(ok=True, message="已恢复重试")
    if action == "delete_record":
        delete_view_record(request.form.get("email", ""))
        return jsonify(ok=True, message="记录已删除")
    if action == "clear_records":
        count = delete_view_record(None)
        return jsonify(ok=True, message=f"已清空 {count} 条记录")
    return jsonify(ok=False, message="未知操作"), 400


@app.route("/admin", methods=["GET", "POST"])
def admin_dashboard():
    if not is_admin():
        return redirect(url_for("admin_login"))

    cfg = load_config()
    message = None
    message_type = "success"

    if request.method == "POST":
        is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
        try:
            action = request.form.get("action", "save_imap")
            if action == "change_admin_password":
                current_password = request.form.get("current_password", "")
                new_password = request.form.get("new_password", "")
                confirm_password = request.form.get("confirm_password", "")

                if not verify_admin_password(current_password, cfg):
                    raise ValueError("当前管理员密码不正确")
                if len(new_password) < 6:
                    raise ValueError("新密码至少 6 位")
                if new_password != confirm_password:
                    raise ValueError("两次输入的新密码不一致")

                set_admin_password(new_password, cfg)
                cfg = load_config()
                message = "管理员密码已更新"
            elif action in ("add_blacklist", "remove_blacklist"):
                entry = normalize_blacklist_entry(request.form.get("blacklist_entry", ""))
                blacklist = [str(e).strip().lower() for e in cfg.get("blacklist", [])]
                if action == "add_blacklist":
                    if entry in blacklist:
                        raise ValueError(f"已在黑名单中: {entry}")
                    blacklist.append(entry)
                    message = f"已加入黑名单: {entry}"
                else:
                    if entry not in blacklist:
                        raise ValueError(f"不在黑名单中: {entry}")
                    blacklist.remove(entry)
                    message = f"已移出黑名单: {entry}"
                save_config({"blacklist": blacklist})
                cfg = load_config()
                if is_ajax:
                    return jsonify(ok=True, message=message, blacklist=cfg.get("blacklist", []))
            else:
                accounts = cfg.get("accounts", [])
                account_id = request.form.get("account_id", "").strip()
                if action == "delete_account":
                    accounts = [item for item in accounts if item.get("id") != account_id]
                    save_config({"accounts": accounts})
                    message = "邮箱源已删除"
                elif action == "save_settings":
                    save_config({
                        "search_since_days": max(1, min(30, int(request.form.get("search_since_days", "2") or "2"))),
                        "max_emails": max(1, min(200, int(request.form.get("max_emails", "20") or "20"))),
                        "max_concurrency": max(1, min(16, int(request.form.get("max_concurrency", "4") or "4"))),
                    })
                    message = "查询设置已保存"
                elif action == "save_code_rules":
                    keywords = [x.strip() for x in request.form.get("keywords", "").splitlines() if x.strip()][:100]
                    save_config({"code_rules": {"keywords": keywords, "min_length": max(3,min(12,int(request.form.get("min_length",4)))), "max_length": max(3,min(12,int(request.form.get("max_length",8)))), "allow_alphanumeric": request.form.get("allow_alphanumeric") in ("on","1","true")}})
                    message = "验证码规则已保存"
                else:
                    existing = next((item for item in accounts if item.get("id") == account_id), None)
                    account = build_account(request.form, existing)
                    if existing:
                        accounts = [account if item.get("id") == account_id else item for item in accounts]
                    else:
                        accounts.append(account)
                    save_config({"accounts": accounts})
                    message = "邮箱源已保存"
                cfg = load_config()
            if is_ajax:
                return jsonify(ok=True, message=message, refresh_sources=action in ("save_account", "delete_account"))
        except Exception as exc:
            message = f"保存失败: {exc}"
            message_type = "error"
            if is_ajax:
                return jsonify(ok=False, message=message)

    records_query = request.args.get("records_q", "").strip()
    all_view_records = search_view_records(records_query)
    records_per_page = 10
    records_total = len(all_view_records)
    records_pages = max(1, (records_total + records_per_page - 1) // records_per_page)
    try:
        records_page = int(request.args.get("records_page", "1"))
    except (TypeError, ValueError):
        records_page = 1
    records_page = max(1, min(records_pages, records_page))
    records_start = (records_page - 1) * records_per_page

    return render_template(
        "admin.html",
        cfg=cfg,
        share_state=share_public_state,
        message=message,
        message_type=message_type,
        view_records=all_view_records[records_start:records_start + records_per_page],
        records_page=records_page,
        records_pages=records_pages,
        records_total=records_total,
        records_query=records_query,
        query_stats=get_query_stats(),
    )


if __name__ == "__main__":
    ensure_config_file()
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    print(f"[startup] server http://{host}:{port} debug={debug}", flush=True)
    if debug:
        app.run(host=host, port=port, debug=True, use_reloader=False)
    else:
        from waitress import serve
        serve(app, host=host, port=port, threads=8, channel_timeout=45, cleanup_interval=10)

