import unittest
from secure_file import encrypt_bytes, decrypt_bytes

class SecureFileTests(unittest.TestCase):
    def test_round_trip(self):
        original = b"Confidential seminar project data"
        self.assertEqual(decrypt_bytes(encrypt_bytes(original, "correct horse"), "correct horse"), original)

    def test_empty_file(self):
        original = b""
        self.assertEqual(decrypt_bytes(encrypt_bytes(original, "passphrase"), "passphrase"), original)

    def test_wrong_password_rejected(self):
        blob = encrypt_bytes(b"secret", "right-password")
        with self.assertRaises(ValueError):
            decrypt_bytes(blob, "wrong-password")

    def test_tampering_rejected(self):
        blob = bytearray(encrypt_bytes(b"secret", "passphrase"))
        blob[-1] ^= 1
        with self.assertRaises(ValueError):
            decrypt_bytes(bytes(blob), "passphrase")

    def test_invalid_header_rejected(self):
        with self.assertRaises(ValueError):
            decrypt_bytes(b"not-an-encrypted-file", "passphrase")

if __name__ == "__main__":
    unittest.main(verbosity=2)
