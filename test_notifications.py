# ==========================================================
# GuardianX Notification System Tests
#
# Runs with the standard library (unittest), no pytest needed:
#     venv\Scripts\python.exe -m unittest test_notifications -v
#
# Uses a dedicated temporary SQLite database so the real
# guardianx.db is never touched. The Config class is patched
# BEFORE app.py is imported because app.py reads it directly
# and runs db.create_all() at import time.
# ==========================================================

import os
import shutil
import tempfile
import unittest

_TMP_DIR = tempfile.mkdtemp(prefix="guardianx-test-")

from config import Config

Config.SQLALCHEMY_DATABASE_URI = (
    "sqlite:///" + os.path.join(_TMP_DIR, "test.db")
)

import app as app_module

from database.db import db
from database.db import User
from models.notification import Notification
from models.user_settings import UserSettings
from models.scan_history import ScanHistory

from services.notification_service import (
    create_security_notification,
    create_scan_notification,
    unread_count,
)


def _new_user(username, email, password="Test@1234"):
    user = User(
        full_name=username.title(),
        username=username,
        email=email,
        mobile=None,
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user


def _login(client, username, password="Test@1234"):
    return client.post(
        "/login",
        data={
            "username": username,
            "password": password,
        },
        follow_redirects=False,
    )


def _url_high_result():
    return {
        "valid": True,
        "risk_score": 80,
        "risk_level": "HIGH",
        "verdict": "Multiple high-risk phishing indicators were detected.",
        "recommendation": "Do not open the link.",
        "indicators": ["Lookalike domain detected; may impersonate PayPal."],
        "checks": [],
    }


def _url_medium_result():
    return {
        "valid": True,
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "verdict": "This URL contains some suspicious characteristics.",
        "recommendation": "Verify the destination.",
        "indicators": ["Suspicious path keyword(s) detected: login."],
        "checks": [],
    }


def _url_medium_no_indicators():
    return {
        "valid": True,
        "risk_score": 45,
        "risk_level": "MEDIUM",
        "verdict": "This URL contains some suspicious characteristics.",
        "recommendation": "Verify the destination.",
        "indicators": ["No major suspicious indicators were detected."],
        "checks": [],
    }


def _url_low_result():
    return {
        "valid": True,
        "risk_score": 10,
        "risk_level": "LOW",
        "verdict": "No major suspicious indicators were detected.",
        "recommendation": "The URL appears relatively safe.",
        "indicators": ["No major suspicious indicators were detected."],
        "checks": [],
    }


class NotificationTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = app_module.app
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP_DIR, ignore_errors=True)

    def setUp(self):
        self.ctx = self.app.test_request_context()
        self.ctx.push()
        Notification.query.delete()
        ScanHistory.query.delete()
        UserSettings.query.delete()
        User.query.delete()
        db.session.commit()

        self.user_a = _new_user("alice", "alice@example.com")
        self.user_b = _new_user("bob", "bob@example.com")

    def tearDown(self):
        db.session.remove()
        self.ctx.pop()

    # --------------------------------------------------
    # Helpers
    # --------------------------------------------------

    def client_logged_in(self, user=None):
        client = self.app.test_client()
        target = user or self.user_a
        response = _login(client, target.username)
        self.assertEqual(response.status_code, 302)
        return client

    def make_notification(self, user_id=None, **kwargs):
        defaults = {
            "notification_type": "system",
            "title": "Test Alert",
            "message": "A test security alert.",
            "severity": "INFO",
        }
        defaults.update(kwargs)
        return create_security_notification(
            user_id=user_id or self.user_a.id,
            **defaults,
        )


# ==========================================================
# Auth gating
# ==========================================================

class AuthGatingTests(NotificationTestCase):

    def test_page_requires_login(self):
        client = self.app.test_client()
        response = client.get("/notifications")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers.get("Location", ""))

    def test_data_requires_login(self):
        client = self.app.test_client()
        self.assertEqual(client.get("/notifications/data").status_code, 302)

    def test_mutations_require_login(self):
        client = self.app.test_client()
        self.assertEqual(
            client.post("/notifications/1/read").status_code, 302
        )
        self.assertEqual(
            client.post("/notifications/read-all").status_code, 302
        )
        self.assertEqual(
            client.post("/notifications/1/delete").status_code, 302
        )
        self.assertEqual(
            client.post("/notifications/clear").status_code, 302
        )


# ==========================================================
# Service layer
# ==========================================================

class ServiceTests(NotificationTestCase):

    def test_create_high_always_fires(self):
        notification = self.make_notification(
            notification_type="url",
            title="High-Risk URL Detected",
            message="Beware of the link.",
            severity="HIGH",
        )
        self.assertIsNotNone(notification)
        self.assertEqual(notification.severity, "HIGH")
        self.assertEqual(notification.notification_type, "url")
        self.assertEqual(notification.user_id, self.user_a.id)

    def test_destination_built_from_type(self):
        notification = self.make_notification(
            notification_type="url",
            title="Alert",
            message="Message",
            severity="HIGH",
            destination=None,
        )
        self.assertTrue(notification.destination)
        self.assertIn("/url-scanner", notification.destination)

    def test_truncation_of_long_text(self):
        notification = self.make_notification(
            notification_type="system",
            title="x" * 500,
            message="y" * 800,
            severity="HIGH",
        )
        self.assertLessEqual(len(notification.title), 200)
        self.assertLessEqual(len(notification.message), 300)

    def test_request_id_dedup(self):
        first = create_security_notification(
            user_id=self.user_a.id,
            notification_type="system",
            title="Alert",
            message="Message",
            severity="HIGH",
            request_id="req-1",
        )
        second = create_security_notification(
            user_id=self.user_a.id,
            notification_type="system",
            title="Alert",
            message="Message",
            severity="HIGH",
            request_id="req-1",
        )
        self.assertEqual(first.id, second.id)
        self.assertEqual(
            Notification.query.filter_by(
                user_id=self.user_a.id
            ).count(),
            1,
        )

    def test_scan_high_url_notification(self):
        notification = create_scan_notification(
            user_id=self.user_a.id,
            scan_type="url",
            result=_url_high_result(),
        )
        self.assertIsNotNone(notification)
        self.assertEqual(notification.notification_type, "url")
        self.assertEqual(notification.severity, "HIGH")

    def test_scan_low_no_notification(self):
        notification = create_scan_notification(
            user_id=self.user_a.id,
            scan_type="url",
            result=_url_low_result(),
        )
        self.assertIsNone(notification)

    def test_scan_medium_needs_indicators(self):
        no_indicator = create_scan_notification(
            user_id=self.user_a.id,
            scan_type="url",
            result=_url_medium_no_indicators(),
        )
        self.assertIsNone(no_indicator)

        with_indicator = create_scan_notification(
            user_id=self.user_a.id,
            scan_type="url",
            result=_url_medium_result(),
        )
        self.assertIsNotNone(with_indicator)
        self.assertEqual(with_indicator.severity, "MEDIUM")

    def test_password_notifications(self):
        weak = create_scan_notification(
            user_id=self.user_a.id,
            scan_type="password",
            result={
                "score": 10,
                "security_message": "This password is very weak.",
                "weaknesses": ["Short password."],
            },
        )
        self.assertIsNotNone(weak)
        self.assertEqual(weak.severity, "HIGH")

        medium = create_scan_notification(
            user_id=self.user_a.id,
            scan_type="password",
            result={
                "score": 50,
                "security_message": "Can be improved.",
                "weaknesses": ["No special characters."],
            },
        )
        self.assertIsNotNone(medium)
        self.assertEqual(medium.severity, "MEDIUM")

        strong = create_scan_notification(
            user_id=self.user_a.id,
            scan_type="password",
            result={
                "score": 85,
                "security_message": "Good password strength.",
                "weaknesses": [],
            },
        )
        self.assertIsNone(strong)

    def test_alerts_disabled_blocks_gated_severities(self):
        settings = UserSettings(
            user_id=self.user_a.id,
            security_alerts=False,
        )
        db.session.add(settings)
        db.session.commit()

        high = create_security_notification(
            user_id=self.user_a.id,
            notification_type="system",
            title="High",
            message="High alert",
            severity="HIGH",
        )
        self.assertIsNotNone(high)

        medium = create_security_notification(
            user_id=self.user_a.id,
            notification_type="system",
            title="Medium",
            message="Medium alert",
            severity="MEDIUM",
        )
        self.assertIsNone(medium)


# ==========================================================
# Data API + ownership
# ==========================================================

class DataApiTests(NotificationTestCase):

    def test_empty_data(self):
        client = self.client_logged_in()
        response = client.get("/notifications/data")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["items"], [])
        self.assertEqual(data["total"], 0)
        self.assertEqual(data["unread_count"], 0)
        self.assertEqual(data["stats"]["total"], 0)

    def test_list_serialized_items(self):
        self.make_notification(
            notification_type="url",
            title="High-Risk URL Detected",
            message="Beware of the link.",
            severity="HIGH",
        )
        client = self.client_logged_in()
        data = client.get("/notifications/data").get_json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["unread_count"], 1)
        item = data["items"][0]
        self.assertEqual(item["notification_type"], "url")
        self.assertEqual(item["severity"], "HIGH")
        self.assertEqual(item["title"], "High-Risk URL Detected")
        self.assertFalse(item["is_read"])
        self.assertIn("/url-scanner", item["destination"])
        self.assertEqual(item["type_label"], "URL")
        self.assertNotIn("user_id", item)

    def test_filters(self):
        self.make_notification(
            notification_type="url",
            title="URL Alert",
            message="Message",
            severity="HIGH",
        )
        self.make_notification(
            notification_type="sms",
            title="SMS Alert",
            message="Message",
            severity="MEDIUM",
        )
        self.make_notification(
            notification_type="system",
            title="System Alert",
            message="Message",
            severity="INFO",
        )
        client = self.client_logged_in()

        only_urls = client.get(
            "/notifications/data?type=url"
        ).get_json()
        self.assertEqual(only_urls["total"], 1)
        self.assertEqual(
            only_urls["items"][0]["notification_type"], "url"
        )

        only_high = client.get(
            "/notifications/data?severity=HIGH"
        ).get_json()
        self.assertEqual(only_high["total"], 1)
        self.assertEqual(only_high["items"][0]["severity"], "HIGH")

        only_unread = client.get(
            "/notifications/data?read=unread"
        ).get_json()
        self.assertEqual(only_unread["total"], 3)

        bad_severity = client.get(
            "/notifications/data?severity=NOPE"
        ).get_json()
        self.assertEqual(bad_severity["total"], 3)

    def test_stats_counts(self):
        self.make_notification(severity="HIGH")
        self.make_notification(severity="MEDIUM")
        self.make_notification(severity="MEDIUM")
        self.make_notification(severity="INFO")
        client = self.client_logged_in()
        data = client.get("/notifications/data").get_json()
        stats = data["stats"]
        self.assertEqual(stats["total"], 4)
        self.assertEqual(stats["unread"], 4)
        self.assertEqual(stats["high"], 1)
        self.assertEqual(stats["medium"], 2)
        self.assertEqual(stats["info"], 1)
        self.assertEqual(data["unread_count"], 4)

    def test_ownership_isolation(self):
        victim = self.make_notification(
            user_id=self.user_a.id,
            severity="HIGH",
        )
        client_b = self.client_logged_in(user=self.user_b)

        data = client_b.get("/notifications/data").get_json()
        self.assertEqual(data["total"], 0)

        read = client_b.post(
            "/notifications/{}/read".format(victim.id)
        )
        self.assertEqual(read.status_code, 404)

        delete = client_b.post(
            "/notifications/{}/delete".format(victim.id)
        )
        self.assertEqual(delete.status_code, 404)

        self.assertIsNotNone(
            Notification.query.get(victim.id)
        )


# ==========================================================
# Mutation endpoints
# ==========================================================

class MutationTests(NotificationTestCase):

    def test_mark_one_read(self):
        notification = self.make_notification(severity="HIGH")
        client = self.client_logged_in()

        response = client.post(
            "/notifications/{}/read".format(notification.id)
        )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["unread_count"], 0)
        self.assertIn("/dashboard", payload["destination"])

        self.assertIsNotNone(
            Notification.query.get(notification.id).is_read
        )

        data = client.get("/notifications/data").get_json()
        self.assertEqual(data["unread_count"], 0)

    def test_mark_all_read(self):
        self.make_notification(severity="HIGH")
        self.make_notification(severity="MEDIUM")
        self.make_notification(severity="INFO")
        client = self.client_logged_in()

        response = client.post("/notifications/read-all")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["updated"], 3)
        self.assertEqual(payload["unread_count"], 0)

        data = client.get("/notifications/data").get_json()
        self.assertEqual(data["unread_count"], 0)
        self.assertTrue(all(item["is_read"] for item in data["items"]))

    def test_delete_one(self):
        notification = self.make_notification(severity="HIGH")
        client = self.client_logged_in()

        response = client.post(
            "/notifications/{}/delete".format(notification.id)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["deleted"], notification.id)

        self.assertIsNone(Notification.query.get(notification.id))

    def test_clear_all(self):
        self.make_notification(severity="HIGH")
        self.make_notification(severity="MEDIUM")
        client = self.client_logged_in()

        response = client.post("/notifications/clear")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["deleted"], 2)

        data = client.get("/notifications/data").get_json()
        self.assertEqual(data["total"], 0)


# ==========================================================
# Scan trigger integration
# ==========================================================

HIGH_SUSPICIOUS_URL = "http://paypa1.com/login?password=secret&otp=1234"
SAFE_URL = "https://www.example.com/"


class TriggerIntegrationTests(NotificationTestCase):

    def _last_notification(self):
        return (
            Notification.query
            .filter_by(user_id=self.user_a.id)
            .order_by(Notification.id.desc())
            .first()
        )

    def test_url_scan_triggers_high_notification(self):
        client = self.client_logged_in()
        response = client.post(
            "/url-scanner/scan",
            json={
                "url": HIGH_SUSPICIOUS_URL,
                "request_id": "t-url-1",
            },
        )
        self.assertEqual(response.status_code, 200)
        notification = self._last_notification()
        self.assertIsNotNone(notification)
        self.assertEqual(notification.notification_type, "url")
        self.assertEqual(notification.severity, "HIGH")

    def test_url_scan_retry_does_not_duplicate(self):
        client = self.client_logged_in()
        for _ in range(2):
            client.post(
                "/url-scanner/scan",
                json={
                    "url": HIGH_SUSPICIOUS_URL,
                    "request_id": "t-url-2",
                },
            )
        self.assertEqual(
            Notification.query.filter_by(
                user_id=self.user_a.id
            ).count(),
            1,
        )

    def test_safe_url_scan_no_notification(self):
        client = self.client_logged_in()
        response = client.post(
            "/url-scanner/scan",
            json={
                "url": SAFE_URL,
                "request_id": "t-url-3",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self._last_notification())

    def test_sms_scan_triggers_notification(self):
        client = self.client_logged_in()
        response = client.post(
            "/sms-detector/scan",
            json={
                "sender": "WINNER",
                "message": (
                    "URGENT: You have won a cash prize! Your account "
                    "has been suspended. Click here http://"
                    "paypa1-secure-login.com/account/verify and enter "
                    "your OTP immediately or legal action will be taken."
                ),
                "request_id": "t-sms-1",
            },
        )
        self.assertEqual(response.status_code, 200)
        notification = self._last_notification()
        self.assertIsNotNone(notification)
        self.assertEqual(notification.notification_type, "sms")
        self.assertEqual(notification.severity, "HIGH")

    def test_qr_scan_triggers_notification(self):
        client = self.client_logged_in()
        response = client.post(
            "/qr-scanner/scan",
            json={
                "content": HIGH_SUSPICIOUS_URL,
                "request_id": "t-qr-1",
            },
        )
        self.assertEqual(response.status_code, 200)
        notification = self._last_notification()
        self.assertIsNotNone(notification)
        self.assertEqual(notification.notification_type, "qr")
        self.assertEqual(notification.severity, "HIGH")

    def test_email_scan_triggers_notification(self):
        client = self.client_logged_in()
        response = client.post(
            "/email-detector/scan",
            json={
                "sender": "support@paypa1-secure-login.com",
                "subject": "URGENT ACCOUNT ACTION REQUIRED!!!",
                "body": (
                    "Your account has been flagged. Verify your "
                    "password and login details immediately by clicking "
                    "http://paypa1-secure-login.com/account/verify"
                ),
                "request_id": "t-email-1",
            },
        )
        self.assertEqual(response.status_code, 200)
        notification = self._last_notification()
        self.assertIsNotNone(notification)
        self.assertEqual(notification.notification_type, "email")
        self.assertEqual(notification.severity, "HIGH")

    def test_password_analyzer_triggers_notification(self):
        client = self.client_logged_in()
        response = client.post(
            "/password-analyzer/analyze",
            json={
                "password": "123456",
                "request_id": "t-pw-1",
            },
        )
        self.assertEqual(response.status_code, 200)
        notification = self._last_notification()
        self.assertIsNotNone(notification)
        self.assertEqual(notification.notification_type, "password")
        self.assertEqual(notification.severity, "HIGH")

    def test_password_analyzer_strong_no_notification(self):
        client = self.client_logged_in()
        response = client.post(
            "/password-analyzer/analyze",
            json={
                "password": "X7$k9#mP2!qR5@vL3&zN",
                "request_id": "t-pw-2",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self._last_notification())

    def test_ai_assistant_triggers_notification(self):
        client = self.client_logged_in()
        response = client.post(
            "/analyze",
            json={
                "message": (
                    "URGENT: Your bank account has been suspended. Click "
                    "here http://login-secure.com and enter your password "
                    "and otp immediately to verify account or update details."
                ),
            },
        )
        self.assertEqual(response.status_code, 200)
        notification = self._last_notification()
        self.assertIsNotNone(notification)
        self.assertEqual(
            notification.notification_type, "ai_assistant"
        )
        self.assertEqual(notification.severity, "HIGH")

    def test_ai_assistant_safe_message_no_notification(self):
        client = self.client_logged_in()
        response = client.post(
            "/analyze",
            json={
                "message": "Meeting tomorrow at 10am. Please bring the slides.",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self._last_notification())

    def test_ai_assistant_anonymous_no_notification(self):
        client = self.app.test_client()
        response = client.post(
            "/analyze",
            json={
                "message": (
                    "URGENT: verify your password now at "
                    "http://paypa1-secure-login.com/login"
                ),
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            Notification.query.count(),
            0,
        )


if __name__ == "__main__":
    unittest.main()
