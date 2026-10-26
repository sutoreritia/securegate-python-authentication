"""Run with python -m unittest -v."""
import unittest
from auth import hash_password, check_password, create_totp_secret, totp, verify_totp


class AuthTests(unittest.TestCase):
    def test_password(self):
        salt, hashed = hash_password("test-password-123")
        self.assertTrue(check_password("test-password-123", salt, hashed))
        self.assertFalse(check_password("wrong-password", salt, hashed))

    def test_unique_salts(self):
        first = hash_password("same password")
        second = hash_password("same password")
        self.assertNotEqual(first, second)

    def test_totp(self):
        secret = create_totp_secret()
        code = totp(secret, now=1_700_000_000)
        self.assertEqual(len(code), 6)
        self.assertTrue(verify_totp(secret, code, now=1_700_000_000))
        self.assertFalse(verify_totp(secret, "notacode", now=1_700_000_000))


if __name__ == "__main__":
    unittest.main()
