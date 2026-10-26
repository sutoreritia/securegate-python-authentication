# SecureGate v2 — Python Cloud Access Management Demo

An **independent educational portfolio project** inspired by cloud identity/access security. **Not affiliated with HENNGE**. A local CLI demo, **not a production authentication system**.

## What's new in v2
- **Forgot Password** added to menu option **4**; **Exit** moved to **5**.
- **Existing users** can use the authenticator app's current 6-digit TOTP code to reset a forgotten password (without deleting accounts).
- **New registrations** receive eight 128-bit, one-time backup recovery codes; only SHA-256 hashes are stored in SQLite.
- Recovery-code reset consumes that code permanently; TOTP reset rotates all recovery codes and shows eight fresh codes.
- After a reset, the password is stored as a **new salted PBKDF2-HMAC-SHA256 hash**, not plaintext. Prior password stops working.
- Recovery attempts recorded in the event history; five failed attempts per username in 15 minutes temporarily block further recovery attempts.
- Reuse of the **same TOTP time step for password recovery** is rejected.
- Existing `securegate.db` files are upgraded automatically; accounts and login history are preserved.
- Connections are now explicitly closed; integration tests were added.

## Requirements
- Python **3.10+**; no third-party pip packages needed.
- Authenticator app (Google Authenticator, Microsoft Authenticator, etc.) for TOTP.

## Windows quick start
Open a terminal inside the extracted `securegate_project` folder:

```powershell
python main.py
```

Menu:

```text
SecureGate | 1 Register | 2 Login | 3 My events | 4 Forgot password | 5 Exit
Choose:
```

### Create an account
1. Enter `1`, choose a username and a password with at least 12 characters.
2. Save the **Base32 secret** in an authenticator app: manual setup key, **time-based / 6 digits / 30 seconds**.
3. Safely save the **eight printed recovery codes** in a secure place. **They are shown only once.** Never share or commit them.
4. Enter `2` and sign in with username, password and the current six-digit code.

### Reset a forgotten password (existing account supported)
1. Enter `4` for `Forgot password`.
2. Choose method `1` for your current authenticator code, or method `2` for a saved one-time recovery code.
3. Enter your username, code, then new password twice. A new password must be at least 12 characters.
4. If successful, select `2` and log in with the new password and your existing authenticator app.
5. If you chose authenticator reset, **all old recovery codes are revoked**: save the eight newly displayed codes. A used recovery code cannot be reused.

**Previously registered users:** Keeping your original `securegate.db` lets the new program upgrade it in place. Old accounts won't have backup codes yet, but they can recover with their configured authenticator app, and successful recovery generates new backup codes.

**If you have lost both the password and the authenticator and have no valid recovery code, this demo cannot securely establish account ownership.** It cannot reset your password without proof. Do not delete your database expecting to preserve users. There is **no email reset** in this offline edition.

## Updating from v1 WITHOUT losing accounts
1. Stop the old program.
2. **Back up** your original `securegate.db` somewhere safe (not GitHub).
3. Replace only `main.py`, `auth.py` and other source files with files from this ZIP, **in the same folder as your existing `securegate.db`**. Don't overwrite the `.db` with an empty file, and don't copy it into a public repository.
4. Run `python main.py` normally: tables/columns will be created/migrated automatically.
5. `4` is now Forgot Password; `5` is Exit.

## Run tests
```powershell
python -m unittest discover -v
```

The tests use **temporary test databases**; they won't delete or modify the usual `securegate.db`.

## Files
- `main.py`: CLI, SQLite migration, registration, login, event history and password reset.
- `auth.py`: PBKDF2 password hashes, TOTP, cryptographic recovery codes.
- `test_auth.py`: basic authentication tests.
- `test_recovery.py`: migration, recovery, password-update and limit tests.
- `使用教學.md`: Traditional Chinese instructions and new Python syntax.
- `securegate.db`: generated locally at runtime; do not commit.

## Security notes / limitations
This is a **local learning project only**. It is NOT suitable for the internet or protecting real accounts. TOTP secrets are stored unencrypted; there is no hardened OTP provisioning, session system, server-side IP throttling, phishing-resistant MFA, guaranteed password entropy checks, alert delivery, or abuse-resistant identity proofing. Login verification itself still accepts a ±30-second TOTP window without replay tracking. Recovery checks have a five-failures/15-minute per-username limit (not a substitute for comprehensive anti-abuse controls). Recovery via TOTP alone is an intentional offline-demo shortcut and **not equivalent to a production-grade multi-factor account recovery design**. Do not use real service credentials or share secret keys or backup codes.

## Portfolio idea
After understanding this version, add recovery token e-mail delivery, verified account recovery, secure secret storage, integration testing, FastAPI endpoints, and deployment hardening.
