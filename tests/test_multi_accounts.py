import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import app


class FakeImap:
    messages_by_user = {}
    failing_users = set()

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.user = None

    def login(self, user, password):
        self.user = user
        if user in self.failing_users:
            raise RuntimeError("connection failed with secret details")

    def select(self, mailbox):
        return "OK", []

    def search(self, charset, query):
        ids = [str(i + 1).encode() for i, _ in enumerate(self.messages_by_user.get(self.user, []))]
        return "OK", [b" ".join(ids)]

    def fetch(self, msg_id, spec):
        raw = self.messages_by_user[self.user][int(msg_id) - 1]
        return "OK", [(b"RFC822", raw)]

    def logout(self):
        return "BYE", []


class MultiAccountTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_config = app.CONFIG_FILE
        self.old_logs = app.VIEW_LOG_FILE
        app.CONFIG_FILE = Path(self.tmp.name) / "config.json"
        app.VIEW_LOG_FILE = Path(self.tmp.name) / "logs.json"

    def tearDown(self):
        app.CONFIG_FILE = self.old_config
        app.VIEW_LOG_FILE = self.old_logs
        self.tmp.cleanup()

    def test_legacy_single_account_is_migrated_without_losing_credentials(self):
        app.CONFIG_FILE.write_text(json.dumps({
            "account_name": "gmail1", "imap_host": "imap.gmail.com",
            "imap_port": 993, "use_ssl": True, "imap_user": "old@gmail.com",
            "imap_password": "gmail-secret", "mailbox": "INBOX",
            "search_since_days": 10, "max_emails": 3
        }))
        cfg = app.load_config()
        self.assertEqual(1, len(cfg["accounts"]))
        self.assertEqual("old@gmail.com", cfg["accounts"][0]["imap_user"])
        self.assertEqual("gmail-secret", cfg["accounts"][0]["imap_password"])

    def test_fetch_merges_enabled_accounts_and_isolates_one_account_failure(self):
        app.save_config({"accounts": [
            {"id": "gmail", "account_name": "Gmail", "enabled": True, "imap_host": "imap.gmail.com", "imap_port": 993, "use_ssl": True, "imap_user": "a@gmail.com", "imap_password": "g-secret", "mailbox": "INBOX"},
            {"id": "qq", "account_name": "QQ邮箱", "enabled": True, "imap_host": "imap.qq.com", "imap_port": 993, "use_ssl": True, "imap_user": "123@qq.com", "imap_password": "q-secret", "mailbox": "INBOX"},
        ], "search_since_days": 2, "max_emails": 20})
        FakeImap.messages_by_user = {
            "a@gmail.com": [b"Subject: Gmail code\r\nFrom: x@example.com\r\nTo: target@example.com\r\nDate: Tue, 04 Aug 2026 10:00:00 +0000\r\n\r\n111111"],
            "123@qq.com": [b"Subject: QQ code\r\nFrom: y@example.com\r\nTo: target@example.com\r\nDate: Tue, 04 Aug 2026 11:00:00 +0000\r\n\r\n222222"],
        }
        FakeImap.failing_users = {"a@gmail.com"}
        with patch("app.imaplib.IMAP4_SSL", FakeImap):
            result = app.fetch_emails("target@example.com")
        self.assertTrue(result["ok"])
        self.assertEqual(["QQ邮箱"], [m["source"] for m in result["emails"]])
        self.assertEqual("Gmail", result["warnings"][0]["source"])
        self.assertNotIn("secret", result["warnings"][0]["error"].lower())

    def test_admin_does_not_render_saved_app_password(self):
        app.save_config({"accounts": [{
            "id": "qq", "account_name": "QQ邮箱", "enabled": True,
            "imap_host": "imap.qq.com", "imap_port": 993, "use_ssl": True,
            "imap_user": "123@qq.com", "imap_password": "super-secret-auth-code", "mailbox": "INBOX"
        }]})
        client = app.app.test_client()
        with client.session_transaction() as session:
            session["admin_authed"] = True
        response = client.get("/admin")
        self.assertEqual(200, response.status_code)
        self.assertNotIn(b"super-secret-auth-code", response.data)
        self.assertIn("QQ邮箱".encode(), response.data)

    def test_short_cache_avoids_repeated_imap_fetch_and_expires(self):
        app.save_config({"accounts": [{
            "id": "qq", "account_name": "QQ邮箱", "enabled": True,
            "imap_host": "imap.qq.com", "imap_port": 993, "use_ssl": True,
            "imap_user": "123@qq.com", "imap_password": "q-secret", "mailbox": "INBOX"
        }], "search_since_days": 2, "max_emails": 20})
        FakeImap.messages_by_user = {
            "123@qq.com": [b"Subject: Latest code\r\nFrom: y@example.com\r\nTo: target@example.com\r\nDate: Tue, 04 Aug 2026 11:00:00 +0000\r\n\r\n222222"]
        }
        FakeImap.failing_users = set()
        app.clear_mail_cache()
        with patch("app.imaplib.IMAP4_SSL", FakeImap), patch("app.time.monotonic", side_effect=[100.0, 101.0, 102.0, 116.0]):
            first = app.fetch_emails_cached("target@example.com")
            FakeImap.messages_by_user["123@qq.com"] = []
            second = app.fetch_emails_cached("target@example.com")
            forced = app.fetch_emails_cached("target@example.com", force_refresh=True)
            third = app.fetch_emails_cached("target@example.com")
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(1, len(second["emails"]))
        self.assertFalse(forced["cached"])
        self.assertEqual(0, len(forced["emails"]))
        self.assertTrue(third["cached"])
        self.assertEqual(0, len(third["emails"]))

    def test_admin_provider_controls_have_dynamic_binding(self):
        app.save_config({"accounts": [{
            "id": "qq", "account_name": "QQ邮箱", "provider": "qq", "enabled": True,
            "imap_host": "imap.qq.com", "imap_port": 993, "use_ssl": True,
            "imap_user": "123@qq.com", "imap_password": "secret", "mailbox": "INBOX"
        }]})
        client = app.app.test_client()
        with client.session_transaction() as session:
            session["admin_authed"] = True
        html = client.get("/admin").get_data(as_text=True)
        self.assertIn('data-provider-select', html)
        self.assertIn('data-imap-host', html)
        self.assertIn('imap.gmail.com', html)
        self.assertIn("document.addEventListener('change'", html)

    def test_public_page_retries_until_newest_message_changes(self):
        html = app.app.test_client().get("/").get_data(as_text=True)
        self.assertIn("AUTO_REFRESH_INTERVAL_MS = 3000", html)
        self.assertIn("AUTO_REFRESH_MAX_DURATION_MS = 60000", html)
        self.assertIn("自动检查新邮件", html)
        self.assertNotIn("等待 QQ 邮箱同步", html)
        self.assertIn("messageIds", html)
        self.assertIn("取消获取", html)
        self.assertIn("activeController.abort()", html)
        self.assertIn("signal", html)

    def test_qq_preset_creates_correct_imap_account(self):
        account = app.build_account({
            "provider": "qq", "account_name": "我的QQ", "imap_user": "123@qq.com",
            "imap_password": "authorization-code", "enabled": "on"
        })
        self.assertEqual("imap.qq.com", account["imap_host"])
        self.assertEqual(993, account["imap_port"])
        self.assertTrue(account["use_ssl"])



class ExplodingImap:
    def __init__(self, *a, **k):
        raise AssertionError("IMAP must not be contacted for blacklisted target")


class BlacklistTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_config = app.CONFIG_FILE
        self.old_logs = app.VIEW_LOG_FILE
        app.CONFIG_FILE = Path(self.tmp.name) / "config.json"
        app.VIEW_LOG_FILE = Path(self.tmp.name) / "logs.json"

    def tearDown(self):
        app.CONFIG_FILE = self.old_config
        app.VIEW_LOG_FILE = self.old_logs
        self.tmp.cleanup()

    def _cfg(self):
        app.save_config({"accounts": [{
            "id": "qq", "account_name": "QQ邮箱", "enabled": True,
            "imap_host": "imap.qq.com", "imap_port": 993, "use_ssl": True,
            "imap_user": "123@qq.com", "imap_password": "q-secret", "mailbox": "INBOX"
        }], "blacklist": ["blocked@example.com", "@spam-domain.com"]})

    def test_blacklisted_email_returns_empty_ok_without_imap(self):
        self._cfg()
        result = app.fetch_emails("Blocked@Example.com")
        self.assertTrue(result["ok"])
        self.assertEqual([], result["emails"])
        self.assertEqual([], result["warnings"])

    def test_blacklisted_email_no_result(self):
        self._cfg()
        with patch("app.imaplib.IMAP4_SSL", ExplodingImap):
            result = app.fetch_emails("blocked@example.com")
        self.assertTrue(result["ok"])
        self.assertEqual([], result["emails"])

    def test_blacklist_domain_matches(self):
        self._cfg()
        with patch("app.imaplib.IMAP4_SSL", ExplodingImap):
            result = app.fetch_emails("someone@spam-domain.com")
        self.assertTrue(result["ok"])
        self.assertEqual([], result["emails"])

    def test_blacklist_case_and_whitespace_insensitive(self):
        self._cfg()
        with patch("app.imaplib.IMAP4_SSL", ExplodingImap):
            result = app.fetch_emails("  BLOCKED@example.COM ")
        self.assertTrue(result["ok"])
        self.assertEqual([], result["emails"])

    def test_non_blacklisted_target_still_fetches(self):
        self._cfg()
        FakeImap.messages_by_user = {"123@qq.com": [
            b"Subject: code\r\nFrom: x@example.com\r\nTo: target@example.com\r\nDate: Tue, 04 Aug 2026 10:00:00 +0000\r\n\r\n999999"
        ]}
        FakeImap.failing_users = set()
        with patch("app.imaplib.IMAP4_SSL", FakeImap):
            result = app.fetch_emails("target@example.com")
        self.assertTrue(result["ok"])
        self.assertEqual(1, len(result["emails"]))

    def test_normalize_blacklist_entry(self):
        self.assertEqual("x@y.com", app.normalize_blacklist_entry("  X@Y.COM "))
        self.assertEqual("@y.com", app.normalize_blacklist_entry("@y.com"))
        for bad in ["not-an-email", "a b@c.com", "@", "@nodot", "@a b.com"]:
            with self.assertRaises(ValueError, msg=bad):
                app.normalize_blacklist_entry(bad)

    def test_admin_add_remove_blacklist(self):
        app.save_config({"accounts": [], "blacklist": []})
        client = app.app.test_client()
        with client.session_transaction() as s:
            s["admin_authed"] = True
            s["csrf_token"] = "test-token"
        r = client.post("/admin", data={"csrf_token": "test-token", "action": "add_blacklist", "blacklist_entry": "Spam@Example.com"}, follow_redirects=True)
        self.assertIn("已加入黑名单", r.get_data(as_text=True))
        self.assertIn("spam@example.com", app.load_config()["blacklist"])
        r2 = client.post("/admin", data={"csrf_token": "test-token", "action": "remove_blacklist", "blacklist_entry": "spam@example.com"}, follow_redirects=True)
        self.assertIn("已移出黑名单", r2.get_data(as_text=True))
        self.assertNotIn("spam@example.com", app.load_config()["blacklist"])

    def test_admin_rejects_duplicate_and_invalid_blacklist(self):
        app.save_config({"accounts": [], "blacklist": ["dup@example.com"]})
        client = app.app.test_client()
        with client.session_transaction() as s:
            s["admin_authed"] = True
            s["csrf_token"] = "test-token"
        r = client.post("/admin", data={"csrf_token": "test-token", "action": "add_blacklist", "blacklist_entry": "DUP@example.com"}, follow_redirects=True)
        self.assertIn("已在黑名单中", r.get_data(as_text=True))
        r2 = client.post("/admin", data={"csrf_token": "test-token", "action": "add_blacklist", "blacklist_entry": "bad entry"}, follow_redirects=True)
        self.assertIn("黑名单格式不正确", r2.get_data(as_text=True))
        r3 = client.post("/admin", data={"csrf_token": "test-token", "action": "remove_blacklist", "blacklist_entry": "missing@example.com"}, follow_redirects=True)
        self.assertIn("不在黑名单中", r3.get_data(as_text=True))

    def test_blacklist_survives_config_roundtrip(self):
        app.save_config({"accounts": [], "blacklist": ["a@b.com", "@c.com"]})
        cfg = app.load_config()
        self.assertEqual(["a@b.com", "@c.com"], cfg["blacklist"])


class SecurityAndRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_config = app.CONFIG_FILE
        self.old_logs = app.VIEW_LOG_FILE
        app.CONFIG_FILE = Path(self.tmp.name) / "config.json"
        app.VIEW_LOG_FILE = Path(self.tmp.name) / "logs.json"
        app._QUERY_ATTEMPTS.clear()

    def tearDown(self):
        app.CONFIG_FILE = self.old_config
        app.VIEW_LOG_FILE = self.old_logs
        self.tmp.cleanup()

    def authed_client(self):
        client = app.app.test_client()
        with client.session_transaction() as sess:
            sess["admin_authed"] = True
            sess["csrf_token"] = "test-token"
        return client

    def test_admin_post_requires_csrf(self):
        client = self.authed_client()
        denied = client.post("/admin", data={"action": "save_settings", "search_since_days": "2", "max_emails": "20"})
        self.assertEqual(403, denied.status_code)
        allowed = client.post("/admin", data={"csrf_token": "test-token", "action": "save_settings", "search_since_days": "2", "max_emails": "20"})
        self.assertEqual(200, allowed.status_code)

    def test_admin_records_are_paginated(self):
        original = app.get_view_records
        app.get_view_records = lambda: [{"email": f"u{i}@example.com", "count": i, "times": []} for i in range(25)]
        try:
            with app.app.test_client() as client:
                with client.session_transaction() as sess:
                    sess["admin_authed"] = True
                html = client.get("/admin?records_page=2").get_data(as_text=True)
                self.assertIn('data-page="2" data-pages="3"', html)
                self.assertIn("function loadRecords", html)
                self.assertIn("records-page-status", html)
                self.assertNotIn("user00@example.com", html)
                self.assertNotIn("user09@example.com", html)
        finally:
            app.get_view_records = original

    def test_admin_settings_ajax_does_not_redirect(self):
        client = self.authed_client()
        response = client.post("/admin", data={"action": "save_settings", "csrf_token": "test-token", "search_since_days": "3", "max_emails": "25"}, headers={"X-Requested-With": "XMLHttpRequest"})
        self.assertEqual(200, response.status_code)
        self.assertTrue(response.get_json()["ok"])
        self.assertEqual("查询设置已保存", response.get_json()["message"])

    def test_admin_records_ajax_endpoint(self):
        original = app.get_view_records
        app.get_view_records = lambda: [{"email": f"u{i}@example.com", "count": i, "times": []} for i in range(25)]
        try:
            client = self.authed_client()
            response = client.get("/admin/view-records?page=3")
            data = response.get_json()
            self.assertEqual(200, response.status_code)
            self.assertEqual(3, data["page"])
            self.assertEqual(3, data["pages"])
            self.assertEqual(5, len(data["records"]))
        finally:
            app.get_view_records = original

    def test_admin_page_contains_csrf_tokens(self):
        html = self.authed_client().get("/admin").get_data(as_text=True)
        self.assertIn('name="csrf_token" value="test-token"', html)

    def test_security_headers_and_admin_no_store(self):
        response = self.authed_client().get("/admin")
        self.assertEqual("DENY", response.headers["X-Frame-Options"])
        self.assertEqual("no-store", response.headers["Cache-Control"])

    def test_trusted_proxy_client_ip(self):
        with app.app.test_request_context("/", headers={"X-Forwarded-For": "203.0.113.9, 127.0.0.1"}, environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            self.assertEqual("203.0.113.9", app.client_ip())

    def test_public_rate_limit_ignores_refresh_polling(self):
        for _ in range(app._QUERY_MAX_NEW_TARGETS):
            self.assertFalse(app._query_rate_limited("ip", "x@example.com", False))
        self.assertTrue(app._query_rate_limited("ip", "x@example.com", False))
        self.assertFalse(app._query_rate_limited("ip", "x@example.com", True))



class BatchFeatureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_cfg, self.old_logs = app.CONFIG_FILE, app.VIEW_LOG_FILE
        app.CONFIG_FILE = Path(self.tmp.name) / "config.json"
        app.VIEW_LOG_FILE = Path(self.tmp.name) / "logs.json"
        app.CONFIG_FILE.write_text(json.dumps({**app.DEFAULT_CONFIG, "admin_password_hash": app.generate_password_hash("secret")}), encoding="utf-8")
        app.VIEW_LOG_FILE.write_text("{}", encoding="utf-8")
        app.app.config.update(TESTING=True, SECRET_KEY="test")
        self.client = app.app.test_client()
        with self.client.session_transaction() as sess:
            sess["admin_authed"] = True; sess["csrf_token"] = "csrf"
    def tearDown(self):
        app.CONFIG_FILE, app.VIEW_LOG_FILE = self.old_cfg, self.old_logs
        self.tmp.cleanup()
    def test_custom_code_rules(self):
        rules={"keywords":["登录口令"],"min_length":6,"max_length":6,"allow_alphanumeric":False}
        self.assertEqual(["123456"], app.extract_verification_codes("登录口令：123456", "", rules))
        self.assertEqual([], app.extract_verification_codes("登录口令：A2B3C4", "", rules))
    def test_share_link_expiry_usage_and_revoke(self):
        link=app.create_share_link("a@example.com",10,1)
        self.assertIsNotNone(app.active_share(link["token"],"a@example.com"))
        self.assertTrue(app.consume_share(link["token"],"a@example.com"))
        self.assertIsNone(app.active_share(link["token"],"a@example.com"))
    def test_admin_batch_tools(self):
        r=self.client.post('/admin/tools',data={"csrf_token":"csrf","action":"create_share","email":"a@example.com","minutes":"10","max_uses":"2"})
        self.assertEqual(200,r.status_code); self.assertIn("url",r.get_json()["link"])
        r=self.client.post('/admin/tools',data={"csrf_token":"csrf","action":"test_code_rules","subject":"验证码：123456","body":""})
        self.assertEqual(["123456"],r.get_json()["codes"])
        self.assertEqual(200,self.client.get('/admin/tools?action=performance').status_code)
    def test_account_priority_timeout_normalization(self):
        a=app.normalize_account({"priority":-5,"timeout_seconds":99})
        self.assertEqual(1,a["priority"]); self.assertEqual(60,a["timeout_seconds"])

class ProviderPresetTests(unittest.TestCase):
    def test_mainstream_provider_presets_use_secure_imap(self):
        expected = {
            "gmail": "imap.gmail.com", "qq": "imap.qq.com",
            "outlook": "outlook.office365.com", "icloud": "imap.mail.me.com",
            "netease163": "imap.163.com", "netease126": "imap.126.com",
            "sina": "imap.sina.com", "yahoo": "imap.mail.yahoo.com",
            "zoho": "imap.zoho.com",
        }
        self.assertEqual(set(expected), set(app.PROVIDER_PRESETS))
        for provider, host in expected.items():
            preset = app.PROVIDER_PRESETS[provider]
            self.assertEqual(host, preset["imap_host"])
            self.assertEqual(993, preset["imap_port"])
            self.assertTrue(preset["use_ssl"])

    def test_build_account_applies_outlook_preset(self):
        account = app.build_account({
            "provider": "outlook", "account_name": "", "enabled": "on",
            "imap_user": "person@outlook.com", "imap_password": "secret",
            "mailbox": "INBOX", "priority": "100", "timeout_seconds": "12",
        })
        self.assertEqual("Outlook / Hotmail", account["account_name"])
        self.assertEqual("outlook.office365.com", account["imap_host"])
        self.assertEqual(993, account["imap_port"])
        self.assertTrue(account["use_ssl"])


class ShareInvalidPageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_config = app.CONFIG_FILE
        app.CONFIG_FILE = Path(self.temp.name) / "config.json"
        self.client = app.app.test_client()

    def tearDown(self):
        app.CONFIG_FILE = self.old_config
        self.temp.cleanup()

    def _save(self, **changes):
        now = int(time.time())
        link = {"token": "test-token", "email": "target@example.com", "created_at": now - 60,
                "expires_at": now + 3600, "max_uses": 2, "uses": 0, "enabled": True}
        link.update(changes)
        app.save_config({"share_links": [link]})

    def test_revoked_share_has_terminal_page_without_query_form(self):
        self._save(enabled=False)
        response = self.client.get("/?share=test-token")
        self.assertEqual(410, response.status_code)
        self.assertIn("链接已撤销".encode(), response.data)
        self.assertNotIn(b'id="fetch-form"', response.data)
        self.assertNotIn(b"target@example.com", response.data)

    def test_expired_exhausted_and_unknown_share_reasons(self):
        self._save(expires_at=int(time.time()) - 1)
        self.assertIn("链接已过期".encode(), self.client.get("/?share=test-token").data)
        self._save(uses=2, max_uses=2)
        self.assertIn("使用次数已用完".encode(), self.client.get("/?share=test-token").data)
        self.assertIn("链接无效".encode(), self.client.get("/?share=unknown-token").data)


    def test_one_use_link_is_consumed_and_cannot_be_reopened(self):
        self._save(max_uses=1, uses=0)
        self.assertTrue(app.consume_share("test-token", "target@example.com"))
        self.assertIsNone(app.active_share("test-token", "target@example.com"))
        response = self.client.get("/?share=test-token")
        self.assertEqual(410, response.status_code)
        self.assertIn("使用次数已用完".encode(), response.data)

    def test_public_script_marks_initial_share_query_as_non_refresh(self):
        response = self.client.get("/")
        self.assertIn(b"fetchLatest(email, controller.signal, false)", response.data)


    def test_share_public_state_and_delete_action_are_available(self):
        now = int(time.time())
        self.assertEqual("exhausted", app.share_public_state({"enabled": True, "expires_at": now + 60, "uses": 1, "max_uses": 1}, now))
        self.assertEqual("expired", app.share_public_state({"enabled": True, "expires_at": now, "uses": 0, "max_uses": 1}, now))
        self.assertEqual("revoked", app.share_public_state({"enabled": False, "expires_at": now + 60, "uses": 0, "max_uses": 1}, now))
        source = Path(app.__file__).read_text()
        self.assertIn('action == "delete_share"', source)


    def test_refresh_polling_does_not_increment_view_statistics(self):
        source = Path(app.__file__).read_text()
        self.assertIn("if not force_refresh:\n            log_email_view(target_email)", source)
        self.assertNotIn("\n        log_email_view(target_email)\n        result = fetch_emails_cached", source)


    def test_records_frontend_uses_ajax_without_page_reload(self):
        with app.app.test_request_context("/"):
            app.session["admin_authed"] = True
            response = app.admin_dashboard()
        body = response if isinstance(response, str) else response.get_data(as_text=True)
        self.assertIn("function loadRecords", body)
        self.assertIn("/admin/view-records?page=", body)
        self.assertIn("setInterval", body)
        self.assertNotIn("location.reload()", body)


    def test_admin_tools_rejects_missing_csrf_even_when_session_token_missing(self):
        with app.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["admin_authed"] = True
            response = client.post("/admin/tools", data={"action": "clear_records"})
        self.assertEqual(response.status_code, 403)

    def test_empty_admin_fallback_password_is_rejected(self):
        original = os.environ.pop("ADMIN_PASSWORD", None)
        try:
            self.assertFalse(app.verify_admin_password("", {"admin_password_hash": ""}))
        finally:
            if original is not None:
                os.environ["ADMIN_PASSWORD"] = original

if __name__ == "__main__":
    unittest.main()


class CodeAndStatsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_config, self.old_logs = app.CONFIG_FILE, app.VIEW_LOG_FILE
        app.CONFIG_FILE = Path(self.tmp.name) / "config.json"
        app.VIEW_LOG_FILE = Path(self.tmp.name) / "logs.json"
        app.save_config({"accounts": []})

    def tearDown(self):
        app.CONFIG_FILE, app.VIEW_LOG_FILE = self.old_config, self.old_logs
        self.tmp.cleanup()

    def test_extract_verification_codes_requires_context(self):
        self.assertEqual(["123456"], app.extract_verification_codes("您的验证码是 123456", "请勿泄露"))
        self.assertEqual(["A7B9C2"], app.extract_verification_codes("Security code", "Use A7B9C2 to verify"))
        self.assertEqual([], app.extract_verification_codes("订单号 123456", "感谢购买"))
        self.assertEqual(["785127"], app.extract_verification_codes(
            "Cloudflare Access login code for admin.pass.23cm.me",
            "Your Cloudflare Access code 785127. This code expires after 10 minutes.",
        ))
        self.assertEqual(["001830"], app.extract_verification_codes(
            "你的临时 ChatGPT 登录代码",
            "你也可以输入此临时代码：001830 如果你无意登录 ChatGPT，请重置密码。",
        ))
        self.assertEqual([], app.extract_verification_codes(
            "New sign-in to your OpenAI account",
            "New sign-in details. Time: August 04, 2026 at 2:28 PM. Security notice only.",
        ))
        self.assertEqual(["17176202"], app.extract_verification_codes(
            "Your GitHub launch code",
            "Your GitHub launch code: 17176202",
        ))

    def test_query_stats(self):
        app.VIEW_LOG_FILE.write_text(json.dumps({"a@example.com": {"count": 3, "times": []}, "b@example.com": {"count": 1, "times": []}}))
        stats = app.get_query_stats()
        self.assertEqual(4, stats["total_queries"])
        self.assertEqual(2, stats["total_unique"])
        self.assertEqual("a@example.com", stats["top"][0]["email"])

    def test_admin_stats_endpoint(self):
        client = app.app.test_client()
        with client.session_transaction() as session:
            session["admin_authed"] = True
        response = client.get("/admin/tools?action=stats")
        self.assertEqual(200, response.status_code)
        self.assertTrue(response.get_json()["ok"])
