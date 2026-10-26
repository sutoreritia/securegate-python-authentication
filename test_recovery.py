"""Integration tests: DB upgrades, recovery, and failure cases."""
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
from auth import (
    check_password,
    create_totp_secret,
    generate_recovery_codes,
    hash_password,
    hash_recovery_code,
    totp,
)


class RecoveryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.database = Path(self.tempdir.name) / "test_securegate.db"
        patcher = patch.object(main, "DATABASE", self.database)
        patcher.start()
        self.addCleanup(patcher.stop)
        main.setup_db()
        self.username = "Tin"
        self.secret = create_totp_secret()
        salt, digest = hash_password("old-password-123")
        self.code = generate_recovery_codes(1)[0]
        with main.connect_db() as db:
            cursor = db.execute(
                "INSERT INTO users (username, salt, password_hash, totp_secret) "
                "VALUES (?, ?, ?, ?)",
                (self.username, salt, digest, self.secret),
            )
            db.execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
                       (cursor.lastrowid, hash_recovery_code(self.code)))

    def password_matches(self, value):
        with main.connect_db() as db:
            salt, digest = db.execute(
                "SELECT salt, password_hash FROM users WHERE username = ?",
                (self.username,),
            ).fetchone()
        return check_password(value, salt, digest)

    def test_totp_reset_and_code_rotation(self):
        valid_code = totp(self.secret)
        ok, backups = main.reset_user_password(
            self.username, "totp", valid_code, "new-password-123")
        self.assertTrue(ok)
        self.assertEqual(len(backups), 8)
        self.assertFalse(self.password_matches("old-password-123"))
        self.assertTrue(self.password_matches("new-password-123"))
        with main.connect_db() as db:
            recovery_hashes = [row[0] for row in db.execute(
                "SELECT code_hash FROM recovery_codes")]
        self.assertNotIn(hash_recovery_code(self.code), recovery_hashes)
        self.assertNotIn(backups[0], recovery_hashes)  # hash only; never plaintext
        self.assertIn(hash_recovery_code(backups[0]), recovery_hashes)

    def test_totp_reset_prevents_same_counter_replay(self):
        valid_code = totp(self.secret)
        self.assertTrue(main.reset_user_password(
            self.username, "totp", valid_code, "new-password-123")[0])
        self.assertFalse(main.reset_user_password(
            self.username, "totp", valid_code, "third-password-123")[0])
        self.assertTrue(self.password_matches("new-password-123"))

    def test_one_time_recovery_code(self):
        self.assertTrue(main.reset_user_password(
            self.username, "recovery", self.code.lower(), "new-password-123")[0])
        self.assertFalse(main.reset_user_password(
            self.username, "recovery", self.code, "third-password-123")[0])
        self.assertTrue(self.password_matches("new-password-123"))
        with main.connect_db() as db:
            self.assertIsNotNone(db.execute(
                "SELECT used_at FROM recovery_codes WHERE code_hash = ?",
                (hash_recovery_code(self.code),)).fetchone()[0])

    def test_invalid_proof_does_not_change_password(self):
        self.assertFalse(main.reset_user_password(
            self.username, "totp", "not-valid", "new-password-123")[0])
        self.assertFalse(main.reset_user_password(
            self.username, "recovery", "NOT-A-RECOVERY-CODE", "new-password-123")[0])
        self.assertFalse(main.reset_user_password(
            "missing", "recovery", self.code, "new-password-123")[0])
        self.assertFalse(main.reset_user_password(
            self.username, "recovery", self.code, "short")[0])
        self.assertTrue(self.password_matches("old-password-123"))

    def test_reset_rate_limit(self):
        for _ in range(main.MAX_RESET_FAILURES):
            self.assertFalse(main.reset_user_password(
                self.username, "totp", "invalid", "new-password-123")[0])
        self.assertFalse(main.reset_user_password(
            self.username, "recovery", self.code, "new-password-123")[0])
        self.assertTrue(self.password_matches("old-password-123"))

    def test_register_shows_codes_once_and_stores_hashes(self):
        with patch("builtins.input", return_value="NewUser"), \
             patch("main.getpass.getpass", return_value="testing-password-123"), \
             patch("builtins.print") as output:
            main.register()
        messages = "\n".join(" ".join(map(str, call.args)) for call in output.call_args_list)
        self.assertIn("One-time recovery codes", messages)
        with main.connect_db() as db:
            rows = db.execute("SELECT code_hash FROM recovery_codes").fetchall()
            self.assertEqual(len(rows), 9)  # 1 fixture code + 8 new user codes
        self.assertNotIn(self.code, str(rows))


class LegacyUpgradeTests(unittest.TestCase):
    def test_existing_account_is_preserved_and_can_reset_via_totp(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "legacy.db"
            secret = create_totp_secret()
            salt, digest = hash_password("legacy-password-123")
            with closing(sqlite3.connect(database)) as db:
                db.execute("""CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    salt TEXT NOT NULL, password_hash TEXT NOT NULL,
                    totp_secret TEXT NOT NULL
                )""")
                db.execute("INSERT INTO users (username, salt, password_hash, totp_secret) "
                           "VALUES (?, ?, ?, ?)", ("LegacyUser", salt, digest, secret))
                db.commit()
            with patch.object(main, "DATABASE", database):
                main.setup_db()
                ok, codes = main.reset_user_password(
                    "LegacyUser", "totp", totp(secret), "brand-new-password-123")
                self.assertTrue(ok)
                self.assertEqual(len(codes), 8)
                with main.connect_db() as db:
                    stored_salt, stored_hash = db.execute(
                        "SELECT salt, password_hash FROM users WHERE username = 'LegacyUser'"
                    ).fetchone()
                    self.assertTrue(check_password("brand-new-password-123",
                                                   stored_salt, stored_hash))


if __name__ == "__main__":
    unittest.main()
