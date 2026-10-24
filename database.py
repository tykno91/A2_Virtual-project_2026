import base64
import os
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DB_FILE = "vault.db"


def get_connection():
    return sqlite3.connect(DB_FILE)


def init_db():
    with get_connection() as conn:
        cursor = conn.cursor()
        # Stores the master password hash and salt
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS master_auth (
                id INTEGER PRIMARY KEY,
                master_hash TEXT NOT NULL,
                salt BLOB NOT NULL
            )
        """
        )
        # Stores encrypted credentials
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL
            )
        """
        )
        conn.commit()


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a Fernet-compatible key using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def is_master_set() -> bool:
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM master_auth")
        return cursor.fetchone()[0] > 0


def set_master_password(master_password: str):
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    # Encrypt a fixed token to verify correctness upon subsequent logins
    token = fernet.encrypt(b"vault_unlocked").decode()

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO master_auth (id, master_hash, salt) VALUES (1, ?, ?)",
            (token, salt),
        )
        conn.commit()


def verify_master_password(master_password: str):
    """Returns a Fernet instance if valid, or None if invalid."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT master_hash, salt FROM master_auth WHERE id = 1")
        row = cursor.fetchone()

    if not row:
        return None

    token, salt = row
    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(token.encode())
        if decrypted == b"vault_unlocked":
            return fernet
    except Exception:
        return None
    return None


def add_credential(fernet: Fernet, service: str, username: str, password: str):
    encrypted_pw = fernet.encrypt(password.encode())
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO credentials (service, username, password) VALUES (?, ?, ?)",
            (service, username, encrypted_pw),
        )
        conn.commit()


def get_credentials(fernet: Fernet):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, service, username, password FROM credentials")
        rows = cursor.fetchall()

    results = []
    for cred_id, service, username, enc_pw in rows:
        try:
            decrypted_pw = fernet.decrypt(enc_pw).decode()
        except Exception:
            decrypted_pw = "[Decryption Error]"
        results.append((cred_id, service, username, decrypted_pw))
    return results


def delete_credential(cred_id: int):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
        conn.commit()