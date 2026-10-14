# Zero Trust Adaptive Authentication System (CARTA)

A locally deployable full-stack Continuous Adaptive Risk and Trust Assessment (CARTA) Zero Trust authentication system.

---

## 1. Quick Start

### Prerequisites
* Python 3.10+
* SQLite3

### Installation & Run
```bash
# 1. Install dependencies
python -m pip install flask bcrypt pyotp pyjwt

# 2. Run the server
python app.py

# 3. Access the dashboard
http://localhost:5000
```

---

## 2. Core Architecture

```
                  ┌────────────────────────────────────────────────────────┐
                  │                 Client / Web Browser                   │
                  │  (Single-Page SOC Dashboard + Anomaly / Risk Simulator) │
                  └───────────────────────────┬────────────────────────────┘
                                              │ HTTP Requests (Bearer JWT Token)
                                              ▼
                  ┌────────────────────────────────────────────────────────┐
                  │          Flask Policy Enforcement Point (PEP)          │
                  │                                                        │
                  │  1. JWT Validation (Session ID, User, Role)            │
                  │  2. Trust Half-Life Decay Calculation (t_half = 60m)   │
                  │  3. Context Evaluation (IP, Device FP, Velocity Burst) │
                  │  4. Policy Gate Check: Allow (200), Step-Up (401),     │
                  │     or Block / Terminate (403)                         │
                  └───────────────────────────┬────────────────────────────┘
                                              │ Parameterized SQL Queries
                                              ▼
                  ┌────────────────────────────────────────────────────────┐
                  │               SQLite Database (carta.db)               │
                  │                                                        │
                  │  • users          • login_history   • session_trust    │
                  │  • devices        • audit_log                          │
                  └────────────────────────────────────────────────────────┘
```

---

## 3. Policy Access Tiers & Dynamic Scoring

| Endpoint | Required Trust | Required Role | Purpose |
| :--- | :---: | :---: | :--- |
| **`/api/public`** | **$\ge 20$** | Any | Public campus announcements & general docs |
| **`/api/profile`** | **$\ge 40$** | Any | User identity & account profile |
| **`/api/payment`** | **$\ge 60$** | Any | Financial portal & balance disbursement |
| **`/api/admin`** | **$\ge 80$** | `admin` | Root infrastructure & security controls |

### Adaptive Trust Modifiers
* **Initial Trust:** Starts at `70 / 100` after password + TOTP MFA.
* **Time Decay:** Exponential decay with half-life $t_{half} = 60\text{ minutes}$.
* **Device Anomaly:** `-30` on unrecognized device fingerprint.
* **Network Anomaly:** `-25` on IP subnet switch.
* **Velocity Burst:** `-20` if request velocity exceeds 5 requests / 2 seconds.
* **Normal Recovery:** `+2` for consistent normal actions (up to 100).
* **Step-Up MFA:** `+35` upon submitting a fresh 6-digit TOTP code.
* **Critical Barrier:** If trust drops below `20`, the session is terminated.

---

## 4. API Endpoints

* `POST /register`: Register user with bcrypt password and pyotp TOTP secret generation.
* `POST /login`: Verify credentials and prompt for MFA (`mfa_required: true`).
* `POST /verify-otp`: Verify TOTP, assess initial context, create session trust record, and issue JWT.
* `POST /step-up-otp`: Re-elevate trust score via OTP challenge.
* `GET /api/public`, `/api/profile`, `/api/payment`, `/api/admin`: Protected resources.
* `GET /api/session-status`: Real-time session trust inspection.
* `GET /api/audit-logs`: Audit trail query.
