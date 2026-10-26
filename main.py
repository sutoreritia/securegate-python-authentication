"""SecureGate educational CLI: account registration, login and password recovery."""
import getpass
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from auth import (
    check_password,
    create_totp_secret,
    generate_recovery_codes,
    hash_password,
    hash_recovery_code,
    matching_totp_counter,
    verify_totp,
)

DATABASE = Path(__file__).with_name("securegate.db")
MAX_RESET_FAILURES = 5


@contextmanager
def connect_db():
    """Open a SQLite transaction and always close the connection."""
    connection = sqlite3.connect(DATABASE, timeout=10)
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def setup_db():
    with connect_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            last_reset_totp_counter INTEGER
        )""")
        # Upgrade databases created by the original version without deleting accounts.
        columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
        if "last_reset_totp_counter" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN last_reset_totp_counter INTEGER")

        db.execute("""CREATE TABLE IF NOT EXISTS login_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            outcome TEXT NOT NULL,
            occurred_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL UNIQUE,
            used_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )""")


def record_event(username: str, outcome: str):
    with connect_db() as db:
        db.execute("INSERT INTO login_events (username, outcome) VALUES (?, ?)",
                   (username, outcome))


def register():
    username = input("New username: ").strip()
    password = getpass.getpass("New password (at least 12 characters): ")
    if not username or len(password) < 12:
        print("Username cannot be empty; password must have at least 12 characters.")
        return
    salt, password_hash = hash_password(password)
    secret = create_totp_secret()
    codes = generate_recovery_codes()
    try:
        with connect_db() as db:
            cursor = db.execute(
                "INSERT INTO users (username, salt, password_hash, totp_secret) VALUES (?, ?, ?, ?)",
                (username, salt, password_hash, secret),
            )
            user_id = cursor.lastrowid
            db.executemany(
                "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
                [(user_id, hash_recovery_code(code)) for code in codes],
            )
    except sqlite3.IntegrityError:
        print("Username already exists.")
        return

    print("\nAccount created! Add this Base32 secret to your authenticator app:")
    print(secret)
    print("Select time-based (TOTP), six digits, 30-second interval.")
    print("\nOne-time recovery codes (SAVE OFFLINE; shown only once):")
    for code in codes:
        print("  " + code)
    print("Each code can reset your password only once. Do NOT share these codes.")
    print("Warning: this demo stores the TOTP secret unencrypted in SQLite.")


def login():
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    with connect_db() as db:
        row = db.execute(
            "SELECT salt, password_hash, totp_secret FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None or not check_password(password, row[0], row[1]):
        record_event(username, "password_failed")
        print("Login failed.")
        return
    code = input("6-digit authenticator code: ").strip()
    if not verify_totp(row[2], code):
        record_event(username, "totp_failed")
        print("Login failed.")
        return
    record_event(username, "success")
    print(f"Welcome, {username}! Authentication succeeded.")


def show_events():
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    with connect_db() as db:
        row = db.execute(
            "SELECT salt, password_hash, totp_secret FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    if row is None or not check_password(password, row[0], row[1]):
        print("Access denied.")
        return
    code = input("6-digit authenticator code: ").strip()
    if not verify_totp(row[2], code):
        print("Access denied.")
        return
    with connect_db() as db:
        events = db.execute(
            "SELECT outcome, occurred_at FROM login_events "
            "WHERE username = ? ORDER BY id DESC LIMIT 10",
            (username,),
        ).fetchall()
    if not events:
        print("No events yet.")
    for outcome, occurred_at in events:
        print(f"{occurred_at} | {outcome}")


def reset_user_password(username: str, method: str, proof: str,
                        new_password: str) -> tuple[bool, list[str]]:
    """Reset password after verifying TOTP or a single-use recovery code.

    Returns (success, replacement_codes). Fresh codes are shown after a TOTP
    reset, rotating any old backups. No codes are printed on failure.
    """
    if len(new_password) < 12 or method not in {"totp", "recovery"}:
        return False, []

    replacement_codes = []
    with connect_db() as db:
        # Serialize check and update, preventing two simultaneous uses of a code.
        db.execute("BEGIN IMMEDIATE")
        recent_failures = db.execute(
            """SELECT COUNT(*) FROM login_events
               WHERE username = ? AND outcome = 'password_reset_failed'
                 AND occurred_at >= datetime('now', '-15 minutes')""",
            (username,),
        ).fetchone()[0]
        if recent_failures >= MAX_RESET_FAILURES:
            return False, []

        row = db.execute(
            "SELECT id, totp_secret, last_reset_totp_counter "
            "FROM users WHERE username = ?", (username,),
        ).fetchone()
        valid = False
        if row is not None and method == "totp":
            counter = matching_totp_counter(row[1], proof)
            if counter is not None:
                updated = db.execute(
                    """UPDATE users SET last_reset_totp_counter = ?
                       WHERE id = ? AND (last_reset_totp_counter IS NULL
                                         OR last_reset_totp_counter < ?)""",
                    (counter, row[0], counter),
                )
                valid = updated.rowcount == 1
                if valid:
                    # TOTP reset also rotates backup codes to invalidate old ones.
                    replacement_codes = generate_recovery_codes()
                    db.execute("DELETE FROM recovery_codes WHERE user_id = ?", (row[0],))
                    db.executemany(
                        "INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)",
                        [(row[0], hash_recovery_code(code)) for code in replacement_codes],
                    )
        elif row is not None and method == "recovery":
            digest = hash_recovery_code(proof)
            if digest is not None:
                updated = db.execute(
                    """UPDATE recovery_codes SET used_at = CURRENT_TIMESTAMP
                       WHERE user_id = ? AND code_hash = ? AND used_at IS NULL""",
                    (row[0], digest),
                )
                valid = updated.rowcount == 1

        if valid:
            salt, password_hash = hash_password(new_password)
            db.execute("UPDATE users SET salt = ?, password_hash = ? WHERE id = ?",
                       (salt, password_hash, row[0]))
            db.execute("INSERT INTO login_events (username, outcome) VALUES (?, ?)",
                       (username, "password_reset_success"))
            return True, replacement_codes

        db.execute("INSERT INTO login_events (username, outcome) VALUES (?, ?)",
                   (username, "password_reset_failed"))
        return False, []


def forgot_password():
    print("\nForgot Password (offline demo; no email service)")
    print("1. Verify with your authenticator app")
    print("2. Use a saved one-time recovery code")
    choice = input("Method (1/2): ").strip()
    if choice not in {"1", "2"}:
        print("Please choose 1 or 2.")
        return

    username = input("Username: ").strip()
    if choice == "1":
        method = "totp"
        proof = input("Current 6-digit authenticator code: ").strip()
    else:
        method = "recovery"
        proof = getpass.getpass("Recovery code (input hidden): ").strip()

    new_password = getpass.getpass("New password (at least 12 characters): ")
    confirm = getpass.getpass("Confirm new password: ")
    if len(new_password) < 12 or new_password != confirm:
        print("Password must contain at least 12 characters and match confirmation.")
        return

    success, replacement_codes = reset_user_password(username, method, proof, new_password)
    if not success:
        print("Reset failed. Check the code, or retry later if rate-limited.")
        print("After five failed attempts, recovery is blocked for 15 minutes.")
        return

    print("Password reset successful! Log in using your new password.")
    if replacement_codes:
        print("Your NEW recovery codes (SAVE OFFLINE; old backup codes were revoked):")
        for code in replacement_codes:
            print("  " + code)
        print("These codes are shown only once. Do NOT share them.")


def main():
    setup_db()
    while True:
        print("\nSecureGate | 1 Register | 2 Login | 3 My events | "
              "4 Forgot password | 5 Exit")
        choice = input("Choose: ").strip()
        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            show_events()
        elif choice == "4":
            forgot_password()
        elif choice == "5":
            print("Goodbye!")
            break
        else:
            print("Please choose 1-5.")


if __name__ == "__main__":
    main()
