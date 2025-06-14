# OWASP Secure Banking App – From Vulnerable to Secure

This project demonstrates a transformation of a **deliberately insecure banking application** into a **secure, OWASP Top 10 (2021)-compliant** system using FastAPI.

> **Assignment Objective:**  
> Build a vulnerable web app → identify OWASP violations → apply security best practices to fix them.

---

## Tech Stack

- **Backend:** FastAPI (Python)
- **Database:** SQLAlchemy Core
- **Templating Engine:** Jinja2
- **Security Tools:** JWT, Passlib, SlowAPI, `python-magic`
- **Other:** dotenv, bcrypt, SSRF protections

---

## ❌ Insecure App Overview (Before fixes)

The original app intentionally violated multiple OWASP 2021 security guidelines:

| OWASP ID | Issue | Example |
|----------|-------|---------|
| A01      | Broken Access Control | No user role checks; dashboard accessible via query param |
| A02      | Cryptographic Failures | Plaintext password storage |
| A03      | Injection | Unsafe dynamic SQL using `text()` |
| A05      | Security Misconfiguration | Hardcoded credentials; no `.env` |
| A07      | Identification & Auth Failures | Brute-forceable login, missing JWT |
| A08      | Software/Data Integrity Failures | Arbitrary file uploads, no validation |
| A09      | Logging & Monitoring Failures | Minimal/no logs on auth actions |
| A10      | SSRF | Unchecked external avatar URL fetching |

---

## ✅ Secure App Modifications (After fixes)

The app was refactored to follow **best security practices** addressing all above issues:

### ✅ Authentication & Session Security

- Secure password hashing via `bcrypt` & `passlib`
- JWT-based authentication with short expiry tokens
- Secure cookie flags (`HttpOnly`, `SameSite`, `Secure`)
- Logout endpoint removes token safely

### ✅ Input Validation & Escaping

- All messages sanitized using `markupsafe.escape` and regex
- Avatar URLs checked for valid schemes, SSRF, and file types
- Message input limited to 1000 characters, safe HTML only

### ✅ File Upload Security

- Only safe extensions (`.png`, `.pdf`, `.jpg`, `.txt`) allowed
- MIME type validation using `python-magic`
- Filenames sanitized, uploads stored with UUID renaming

### ✅ Rate Limiting & Brute Force Prevention

- Brute-force defense using `slowapi` (rate limit: 5/min login attempts)

### ✅ Access Control & Role-Based Visibility

- User role (admin vs regular) enforced server-side
- User ID now extracted from JWT, not exposed via query string

### ✅ Secure Logging

- All auth and transaction events are logged with timestamp, IP, user-agent
- Logs include status and descriptive context

---

## 🚀 How to Run

1. **Clone the repo:**
   ```bash
   git clone https://github.com/mennatallah222/bank
   cd "bank - secure"
   ````

2. **Set up the virtual environment:**

   ```bash
   python -m venv env
   env\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Run the app:**

   ```bash
   uvicorn app.main:app --reload
   ```
