from datetime import datetime

import streamlit as st
import sqlite3
import hashlib
import re

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="ThreatScope — Login & Sign Up",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ============================================================
# SESSION STATE
# ============================================================
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "auth_mode" not in st.session_state:
    st.session_state.auth_mode = "login"
if "auth_error" not in st.session_state:
    st.session_state.auth_error = ""
if "auth_success" not in st.session_state:
    st.session_state.auth_success = ""
if "role" not in st.session_state:
    st.session_state.role = "analyst"

# ============================================================
# REDIRECT IF ALREADY LOGGED IN
# ============================================================
if st.session_state.authenticated:
    st.switch_page("pages/platform.py")

# ============================================================
# DATABASE
# ============================================================
AUTH_DB = "auth.db"


def init_auth_db():
    with sqlite3.connect(AUTH_DB) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                fullname      TEXT    NOT NULL,
                email         TEXT    UNIQUE NOT NULL,
                password_hash TEXT    NOT NULL,
                role          TEXT    DEFAULT 'analyst',
                created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            
        """
        )
        # This handles existing auth.db that don't have the role column yet
        try:
            conn.execute(
                "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'analyst'"
            )
        except:
            pass
        try:
            conn.execute(
                "ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0"
            )
        except:
            pass
        try:
            conn.execute(
                "ALTER TABLE users ADD COLUMN locked_until TIMESTAMP DEFAULT NULL"
            )
        except:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN last_login_ip TEXT DEFAULT NULL")
        except:
            pass
        # ADD THIS after the existing try/except blocks in init_auth_db()
        try:
            conn.execute(
                "ALTER TABLE users ADD COLUMN rate_limit_window_start TIMESTAMP DEFAULT NULL"
            )
        except:
            pass
        try:
            conn.execute(
                "ALTER TABLE users ADD COLUMN rate_limit_attempts INTEGER DEFAULT 0"
            )
        except:
            pass

        conn.commit()


def hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def is_valid_email(email: str) -> bool:
    """
    Checks that the email has a valid format:
    - Contains @ symbol
    - Has characters before the @
    - Has a domain with at least one dot
    - No spaces allowed
    - Example valid: user@company.com, john.doe@mail.co.uk
    """
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return re.match(pattern, email.strip()) is not None


def is_valid_password(password: str) -> tuple[bool, str]:
    """
    Enforces password strength standards:
    - Minimum 8 characters
    - At least one uppercase letter (A-Z)
    - At least one lowercase letter (a-z)
    - At least one digit (0-9)
    - At least one special character (!@#$%^&* etc.)
    - No spaces allowed
    Returns (is_valid: bool, error_message: str)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number (0-9)."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\[\]\/\\]", password):
        return (
            False,
            "Password must contain at least one special character (!@#$%^&* etc.).",
        )
    if " " in password:
        return False, "Password must not contain spaces."
    return True, ""


def create_user(fullname: str, email: str, password: str):
    try:
        with sqlite3.connect(AUTH_DB) as conn:
            # Check if any users exist — if not, first user = admin
            count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            role = (
                "admin" if count == 0 else "executive"
            )  # First user is admin, others are executives by default
            conn.execute(
                "INSERT INTO users (fullname, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (
                    fullname.strip(),
                    email.strip().lower(),
                    hash_password(password),
                    role,
                ),
            )
            conn.commit()
        return True, "Account created."
    except sqlite3.IntegrityError:
        return False, "Email already registered."
    except Exception as e:
        return False, str(e)


def verify_user(email: str, password: str):
    with sqlite3.connect(AUTH_DB) as conn:
        row = conn.execute(
            "SELECT fullname, role FROM users WHERE email=? AND password_hash=?",
            (email.strip().lower(), hash_password(password)),
        ).fetchone()
    return (
        (True, row[0], row[1]) if row else (False, "Invalid email or password.", None)
    )


def record_failed_attempt(email: str):
    with sqlite3.connect(AUTH_DB) as conn:
        conn.execute(
            """UPDATE users
               SET failed_attempts = failed_attempts + 1,
                   locked_until = CASE
                       WHEN failed_attempts + 1 >= 10
                       THEN datetime('now', '+15 minutes')
                       ELSE locked_until
                   END
               WHERE email=?""",
            (email.strip().lower(),),
        )
        conn.commit()


def check_account_locked(email: str):
    with sqlite3.connect(AUTH_DB) as conn:
        row = conn.execute(
            """SELECT failed_attempts, locked_until FROM users 
               WHERE email=?""",
            (email.strip().lower(),),
        ).fetchone()
    if not row:
        return False, 0
    failed, locked_until = row
    if locked_until:
        from datetime import datetime, timezone

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
        lock_time = datetime.strptime(locked_until, "%Y-%m-%d %H:%M:%S")
        if now_utc < lock_time:
            remaining = int((lock_time - now_utc).total_seconds() / 60) + 1
            return True, remaining
        else:
            # Lock expired — reset attempts
            with sqlite3.connect(AUTH_DB) as conn:
                conn.execute(
                    "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE email=?",
                    (email.strip().lower(),),
                )
                conn.commit()
    return False, 0


def reset_failed_attempts(email: str):
    with sqlite3.connect(AUTH_DB) as conn:
        conn.execute(
            "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE email=?",
            (email.strip().lower(),),
        )
        conn.commit()


def check_rate_limit(email: str):
    """
    Returns (is_blocked: bool, minutes_remaining: int).
    Allows max 5 attempts per 5-minute window per email.
    """
    with sqlite3.connect(AUTH_DB) as conn:
        row = conn.execute(
            "SELECT rate_limit_attempts, rate_limit_window_start FROM users WHERE email=?",
            (email.strip().lower(),),
        ).fetchone()

    if not row:
        return False, 0  # Email doesn't exist yet — let login handle that

    attempts, window_start = row

    if window_start is None:
        return False, 0  # No window started yet, allow login

    from datetime import datetime, timezone

    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)
    window_time = datetime.strptime(window_start, "%Y-%m-%d %H:%M:%S")
    elapsed_seconds = (now_utc - window_time).total_seconds()

    if elapsed_seconds >= 300:
        # 5-minute window has expired — reset the counter automatically
        with sqlite3.connect(AUTH_DB) as conn:
            conn.execute(
                "UPDATE users SET rate_limit_attempts=0, rate_limit_window_start=NULL WHERE email=?",
                (email.strip().lower(),),
            )
            conn.commit()
        return False, 0

    # Window is still active — check if attempts exceeded
    if attempts >= 5:
        remaining = int((300 - elapsed_seconds) / 60) + 1
        return True, remaining

    return False, 0


def record_rate_limit_attempt(email: str):
    """
    Increments the rolling 5-minute attempt counter.
    Starts the window timer on the first attempt.
    """
    with sqlite3.connect(AUTH_DB) as conn:
        row = conn.execute(
            "SELECT rate_limit_attempts, rate_limit_window_start FROM users WHERE email=?",
            (email.strip().lower(),),
        ).fetchone()

        if not row:
            return  # User doesn't exist, nothing to track

        attempts, window_start = row

        from datetime import datetime, timezone

        now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

        if window_start is None:
            # First attempt — start the window now
            conn.execute(
                """UPDATE users
                   SET rate_limit_attempts=1,
                       rate_limit_window_start=datetime('now')
                   WHERE email=?""",
                (email.strip().lower(),),
            )
        else:
            window_time = datetime.strptime(window_start, "%Y-%m-%d %H:%M:%S")
            elapsed = (now_utc - window_time).total_seconds()

            if elapsed >= 300:
                # Old window expired — start a fresh one
                conn.execute(
                    """UPDATE users
                       SET rate_limit_attempts=1,
                           rate_limit_window_start=datetime('now')
                       WHERE email=?""",
                    (email.strip().lower(),),
                )
            else:
                # Still inside the window — just increment
                conn.execute(
                    "UPDATE users SET rate_limit_attempts=rate_limit_attempts+1 WHERE email=?",
                    (email.strip().lower(),),
                )
        conn.commit()


def get_client_ip():
    try:
        import socket

        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        return ip
    except:
        return "Unknown"


def save_login_ip(email: str, ip: str):
    with sqlite3.connect(AUTH_DB) as conn:
        conn.execute(
            "UPDATE users SET last_login_ip=? WHERE email=?",
            (ip, email.strip().lower()),
        )
        conn.commit()


init_auth_db()

mode = st.session_state.auth_mode

# ============================================================
# GLOBAL CSS
# ============================================================
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@400;600;700;800&display=swap');
@import url('https://fonts.googleapis.com/icon?family=Material+Icons+Outlined');

/* ── Hide ALL streamlit chrome ── */
#MainMenu, footer, header,
[data-testid="stHeader"],
[data-testid="stToolbar"],
[data-testid="stSidebar"],
[data-testid="stStatusWidget"],
[data-testid="stDecoration"],
.stDeployButton { display:none !important; visibility:hidden !important; }

/* ── Constrain layout to card width, centered ── */
.block-container {
    padding: 0 24px !important;
    max-width: 540px !important;
    margin-left: auto !important;
    margin-right: auto !important;
}
section[data-testid="stMain"] > div:first-child { padding-top:0 !important; }
div[data-testid="stVerticalBlock"] { gap:0 !important; }

/* ── Background + grid + scanline ── */
.stApp, body { background-color:#080c10 !important; font-family:'Syne',sans-serif; }
.stApp::before {
    content:''; position:fixed; inset:0;
    background-image:
        linear-gradient(rgba(56,189,248,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(56,189,248,0.03) 1px, transparent 1px);
    background-size:40px 40px; pointer-events:none; z-index:0;
}
.stApp::after {
    content:''; position:fixed; inset:0;
    background:repeating-linear-gradient(
        0deg, transparent, transparent 2px,
        rgba(0,0,0,0.04) 2px, rgba(0,0,0,0.04) 4px
    );
    pointer-events:none; z-index:1;
}

/* ── Inputs ── */
.stTextInput > div > div > input {
    background-color:#080c10 !important;
    border:1px solid #1e2d3d !important;
    border-radius:8px !important;
    color:#e2e8f0 !important;
    font-family:'JetBrains Mono',monospace !important;
    font-size:13px !important;
    padding:12px 16px !important;
    transition:border-color 0.2s, box-shadow 0.2s !important;
}
.stTextInput > div > div > input:focus {
    border-color:#38bdf8 !important;
    box-shadow:0 0 0 1px rgba(56,189,248,0.25) !important;
}
.stTextInput > div > div > input::placeholder { color:#334155 !important; }
.stTextInput > label { display:none !important; }

/* ── Submit button ── */
.stButton > button {
    width:100% !important; height:48px !important;
    background:linear-gradient(135deg,#0369a1,#1d4ed8) !important;
    color:#fff !important; border:none !important;
    border-radius:8px !important;
    font-family:'JetBrains Mono',monospace !important;
    font-weight:700 !important; font-size:12px !important;
    letter-spacing:1.5px !important; text-transform:uppercase !important;
    transition:all 0.2s !important; margin-top:4px !important;
}
.stButton > button:hover {
    transform:translateY(-2px) !important;
    box-shadow:0 8px 24px rgba(56,189,248,0.25) !important;
    background:linear-gradient(135deg,#0284c7,#2563eb) !important;
}
.stButton > button:active { transform:scale(0.98) !important; }

/* ── Tab buttons: invisible & overlaid on HTML tab row ── */
div[data-testid="stHorizontalBlock"] {
    margin-top:-52px !important;
    margin-bottom:0 !important;
    gap:8px !important;
    padding:0 !important;
    position:relative; z-index:20;
}
div[data-testid="stHorizontalBlock"] .stButton > button {
    height:40px !important;
    background:transparent !important;
    border:none !important;
    box-shadow:none !important;
    color:transparent !important;
    font-size:0 !important;
    cursor:pointer !important;
    margin-top:0 !important;
    border-radius:7px !important;
}
div[data-testid="stHorizontalBlock"] .stButton > button:hover {
    background:rgba(255,255,255,0.04) !important;
    transform:none !important; box-shadow:none !important;
}

/* ── Alerts ── */
.stAlert, [data-baseweb="notification"] {
    background-color:#0d1520 !important;
    border:1px solid #1e2d3d !important;
    border-radius:8px !important;
    font-family:'JetBrains Mono',monospace !important;
    font-size:12px !important;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width:4px; }
::-webkit-scrollbar-track { background:#080c10; }
::-webkit-scrollbar-thumb { background:#1e2d3d; border-radius:4px; }

/* ── Custom label ── */
.ts-label {
    display:block;
    font-family:'JetBrains Mono',monospace;
    font-size:10px; font-weight:700;
    color:#475569; text-transform:uppercase;
    letter-spacing:0.15em; margin:12px 0 4px 2px;
}


</style>
""",
    unsafe_allow_html=True,
)

# ============================================================
# HEADER
# ============================================================
st.markdown(
    """
<div style="position:fixed;top:0;left:0;right:0;height:80px;
            display:flex;align-items:center;justify-content:space-between;
            padding:0 32px; border-bottom:1px solid #1a2535;
            background:rgba(8,12,16,0.92); backdrop-filter:blur(12px); z-index:999;">
    <div style="display:flex;align-items:center;gap:12px;">
        <div style="width:40px;height:40px;border-radius:8px;display:flex;align-items:center;
                    justify-content:center;background:rgba(56,189,248,0.08);
                    border:1px solid rgba(56,189,248,0.3);">
            <span style="color:#38bdf8;font-size:20px;font-family:'Material Icons Outlined';">radar</span>
        </div>
        <div>
            <div style="font-family:'Syne',sans-serif;font-weight:800;font-size:16px;
                        color:#f1f5f9;letter-spacing:-0.3px;">
                THREAT<span style="color:#38bdf8;">SCOPE</span>
            </div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:8px;color:#475569;
                        letter-spacing:2px;text-transform:uppercase;">Transport CTI</div>
        </div>
    </div>
    <button style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#64748b;
                   letter-spacing:1px;padding:8px 16px;border:1px solid #1e2d3d;
                   border-radius:6px;background:transparent;cursor:pointer;
                   text-transform:uppercase;transition:all 0.2s;"
            onmouseover="this.style.color='#94a3b8';this.style.borderColor='#334155';"
            onmouseout="this.style.color='#64748b';this.style.borderColor='#1e2d3d';">
        About Us
    </button>
</div>
<div style="height:80px;"></div>
""",
    unsafe_allow_html=True,
)

# ============================================================
# GLOW BLOBS
# ============================================================
st.markdown(
    """
<div style="position:fixed;top:25%;left:-80px;width:300px;height:300px;
            background:rgba(56,189,248,0.04);border-radius:50%;
            filter:blur(100px);pointer-events:none;z-index:0;"></div>
<div style="position:fixed;bottom:25%;right:-80px;width:300px;height:300px;
            background:rgba(129,140,248,0.04);border-radius:50%;
            filter:blur(100px);pointer-events:none;z-index:0;"></div>
""",
    unsafe_allow_html=True,
)

# ============================================================
# HERO TEXT
# ============================================================
st.markdown(
    """
<div style="text-align:center;margin:40px 0 28px 0;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#38bdf8;
                letter-spacing:4px;text-transform:uppercase;margin-bottom:10px;opacity:0.8;">
        ◈ TRANSPORT SECTOR CTI ◈
    </div>
    <h1 style="font-family:'Syne',sans-serif;font-weight:800;font-size:32px;
               color:#f1f5f9;letter-spacing:-0.5px;line-height:1.15;margin:0 0 12px 0;">
        Intelligence that<br/>
        <span style="background:linear-gradient(90deg,#38bdf8,#818cf8);
                     -webkit-background-clip:text;-webkit-text-fill-color:transparent;
                     background-clip:text;">Strengthens CyberDefense</span>
    </h1>
    <p style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#475569;
              line-height:1.7;max-width:300px;margin:0 auto;letter-spacing:0.3px;">
        Cyber Threat Intelligence platform designed to enhance the protection of
        transport-critical Operational Technology systems.
    </p>
    <div style="width:60px;height:2px;background:linear-gradient(90deg,#38bdf8,#818cf8);
                margin:18px auto 0 auto;border-radius:2px;"></div>
</div>
""",
    unsafe_allow_html=True,
)

# ── Center column: all interactive elements live here ──
st.markdown("<div style='height:50px'></div>", unsafe_allow_html=True)
_pad_l, _center, _pad_r = st.columns([1, 4, 1])
with _center:

    # ============================================================
    # AUTH CARD — outer shell
    # ============================================================
    st.markdown(
        """
    <div style="margin:0 auto;
                background:linear-gradient(135deg,#0d1520 0%,#111827 100%);
                border:1px solid #1e2d3d; border-radius:16px; padding:8px;
                position:relative; box-shadow:0 24px 64px rgba(0,0,0,0.6); overflow:hidden;">
        <div style="position:absolute;top:0;left:0;right:0;height:2px;
                    background:linear-gradient(90deg,#38bdf8,#818cf8);
                    border-radius:16px 16px 0 0;"></div>
    """,
        unsafe_allow_html=True,
    )

    # ── Tab row (HTML visual) ──
    login_style = (
        "background:rgba(56,189,248,0.08);color:#38bdf8;border:1px solid rgba(56,189,248,0.3);"
        if mode == "login"
        else "color:#475569;border:1px solid transparent;"
    )
    signup_style = (
        "background:rgba(56,189,248,0.08);color:#38bdf8;border:1px solid rgba(56,189,248,0.3);"
        if mode == "signup"
        else "color:#475569;border:1px solid transparent;"
    )

    st.markdown(
        f"""
    <div style="display:flex;padding:4px;background:#080c10;border-radius:10px;
                margin-bottom:8px;border:1px solid #1e2d3d;">
        <div style="flex:1;text-align:center;padding:10px 0;font-size:12px;font-weight:700;
                    font-family:'JetBrains Mono',monospace;letter-spacing:1px;text-transform:uppercase;
                    border-radius:7px;transition:all 0.2s;{login_style}">Login</div>
        <div style="flex:1;text-align:center;padding:10px 0;font-size:12px;font-weight:700;
                    font-family:'JetBrains Mono',monospace;letter-spacing:1px;text-transform:uppercase;
                    border-radius:7px;transition:all 0.2s;{signup_style}">Sign Up</div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # ── Invisible Streamlit buttons overlaid on the tab row ──
    c1, c2 = st.columns(2)
    with c1:
        if st.button("Login", key="tab_login", use_container_width=True):
            st.session_state.auth_mode = "login"
            st.session_state.auth_error = ""
            st.session_state.auth_success = ""
            st.rerun()
    with c2:
        if st.button("Sign Up", key="tab_signup", use_container_width=True):
            st.session_state.auth_mode = "signup"
            st.session_state.auth_error = ""
            st.session_state.auth_success = ""
            st.rerun()

    # ── Form padding ──
    st.markdown('<div style="padding:4px 16px 20px 16px;">', unsafe_allow_html=True)

# ── Persistent messages ──
if st.session_state.auth_error:
    st.error(f"⚠️ {st.session_state.auth_error}")
if st.session_state.auth_success:
    st.success(st.session_state.auth_success)

# ============================================================
# LOGIN FORM
# ============================================================
if mode == "login":
    st.markdown(
        """
    <div style="margin:8px 0 20px 0;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:9px;color:#475569;
                    text-transform:uppercase;letter-spacing:2px;margin-bottom:4px;">Authenticate</div>
        <div style="font-family:'Syne',sans-serif;font-size:18px;font-weight:700;color:#f1f5f9;">
            Sign in to continue</div>
    </div>""",
        unsafe_allow_html=True,
    )

    st.markdown("<span class='ts-label'>Email Address</span>", unsafe_allow_html=True)
    login_email = st.text_input(
        "e",
        placeholder="name@company.com",
        key="login_email",
        label_visibility="collapsed",
    )

    st.markdown("<span class='ts-label'>Password</span>", unsafe_allow_html=True)
    login_password = st.text_input(
        "p",
        placeholder="••••••••",
        type="password",
        key="login_password",
        label_visibility="collapsed",
    )

    st.markdown(
        "<div style='border-top:1px solid #1e2d3d;margin:20px 0 8px 0;'></div>",
        unsafe_allow_html=True,
    )

    if st.button("🔐   Login to Dashboard", key="login_submit"):
        if not login_email or not login_password:
            st.session_state.auth_error = "Please fill in all fields."
            st.rerun()
        elif not is_valid_email(login_email):  # ← ADD THIS
            st.session_state.auth_error = "Please enter a valid email address (e.g. name@company.com)."  # ← ADD THIS
            st.rerun()
        else:
            # ── Check 1: 5-minute rate limit (5 attempts per window) ──
            is_rate_limited, rl_minutes = check_rate_limit(login_email)
            if is_rate_limited:
                st.session_state.auth_error = (
                    f"Too many login attempts. Try again in {rl_minutes} minute(s)."
                )
                st.rerun()

            # ── Check 2: Hard account lockout (3 consecutive failures) ──
            is_locked, lock_minutes = check_account_locked(login_email)
            if is_locked:
                st.session_state.auth_error = (
                    f"Account locked due to too many failed attempts. "
                    f"Try again in {lock_minutes} minute(s)."
                )
                st.rerun()

            # ── Attempt login ──
            ok, result, role = verify_user(login_email, login_password)
            if ok:
                reset_failed_attempts(login_email)
                with sqlite3.connect(AUTH_DB) as conn:
                    conn.execute(
                        "UPDATE users SET rate_limit_attempts=0, rate_limit_window_start=NULL WHERE email=?",
                        (login_email.strip().lower(),),
                    )
                    conn.commit()
                ip = get_client_ip()
                save_login_ip(login_email, ip)
                st.session_state.authenticated = True
                st.session_state.username = result
                st.session_state.role = role
                st.session_state.user_email = login_email.strip().lower()
                st.session_state.last_login_ip = ip
                st.session_state.login_time = datetime.now()
                st.session_state.auth_error = ""
                st.switch_page("pages/platform.py")
            else:
                record_rate_limit_attempt(login_email)
                record_failed_attempt(login_email)
                with sqlite3.connect(AUTH_DB) as conn:
                    row = conn.execute(
                        "SELECT failed_attempts FROM users WHERE email=?",
                        (login_email.strip().lower(),),
                    ).fetchone()
                if row:
                    attempts_left = max(0, 3 - row[0])
                    if attempts_left == 0:
                        st.session_state.auth_error = "Account locked for 15 minutes due to too many failed attempts."
                    else:
                        st.session_state.auth_error = f"Invalid email or password. {attempts_left} attempt(s) remaining."
                else:
                    st.session_state.auth_error = result
                st.rerun()

# ============================================================
# SIGNUP FORM
# ============================================================
else:
    st.markdown(
        """
    <div style="margin:8px 0 20px 0;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:9px;color:#475569;
                    text-transform:uppercase;letter-spacing:2px;margin-bottom:4px;">Create Account</div>
        <div style="font-family:'Syne',sans-serif;font-size:18px;font-weight:700;color:#f1f5f9;">
            Join ThreatScope</div>
    </div>""",
        unsafe_allow_html=True,
    )

    st.markdown("<span class='ts-label'>Full Name</span>", unsafe_allow_html=True)
    signup_fullname = st.text_input(
        "fn",
        placeholder="John Doe",
        key="signup_fullname",
        label_visibility="collapsed",
    )

    st.markdown("<span class='ts-label'>Email Address</span>", unsafe_allow_html=True)
    signup_email = st.text_input(
        "em",
        placeholder="name@company.com",
        key="signup_email",
        label_visibility="collapsed",
    )

    st.markdown("<span class='ts-label'>Password</span>", unsafe_allow_html=True)
    signup_password = st.text_input(
        "pw",
        placeholder="Min. 8 characters",
        type="password",
        key="signup_password",
        label_visibility="collapsed",
    )
    st.markdown(
        """
    <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#334155;
                line-height:1.8;margin:4px 0 0 2px;">
        Must contain: &nbsp;
        <span style="color:#475569;">A–Z</span> · 
        <span style="color:#475569;">a–z</span> · 
        <span style="color:#475569;">0–9</span> · 
        <span style="color:#475569;">special char (!@#$...)</span> · 
        <span style="color:#475569;">min 8 chars</span>
    </div>
    """,
        unsafe_allow_html=True,
    )

    st.markdown(
        "<span class='ts-label'>Confirm Password</span>", unsafe_allow_html=True
    )
    signup_confirm = st.text_input(
        "cp",
        placeholder="••••••••",
        type="password",
        key="signup_confirm",
        label_visibility="collapsed",
    )

    st.markdown(
        "<div style='border-top:1px solid #1e2d3d;margin:20px 0 8px 0;'></div>",
        unsafe_allow_html=True,
    )

    if st.button("🛡️   Create Account", key="signup_submit"):
        if not all([signup_fullname, signup_email, signup_password, signup_confirm]):
            st.session_state.auth_error = "Please fill in all fields."
            st.rerun()
        elif not is_valid_email(signup_email):
            st.session_state.auth_error = (
                "Please enter a valid email address (e.g. name@company.com)."
            )
            st.rerun()
        else:
            pw_valid, pw_error = is_valid_password(signup_password)
            if not pw_valid:
                st.session_state.auth_error = pw_error
                st.rerun()
            elif signup_password != signup_confirm:
                st.session_state.auth_error = "Passwords do not match."
                st.rerun()
            else:
                ok, msg = create_user(signup_fullname, signup_email, signup_password)
                if ok:
                    ok2, fullname, role = verify_user(signup_email, signup_password)
                    st.session_state.authenticated = True
                    st.session_state.username = signup_fullname
                    st.session_state.role = role if ok2 else "executive"
                    st.session_state.user_email = signup_email.strip().lower()
                    st.session_state.auth_error = ""
                    st.switch_page("pages/ma.py")
                else:
                    st.session_state.auth_error = msg
                    st.rerun()

# ── Close form padding + card ──
st.markdown("</div></div>", unsafe_allow_html=True)

# ============================================================
# FOOTER
# ============================================================
st.markdown(
    """
<div style="text-align:center;padding:28px 0 48px 0;">
    <div style="font-family:'JetBrains Mono',monospace;font-size:9px;color:#1e2d3d;
                letter-spacing:2px;text-transform:uppercase;">
        THREATSCOPE · TRANSPORT CTI · SECURED
    </div>
    <div style="display:flex;justify-content:center;gap:20px;margin-top:10px;">
        <span style="font-family:'JetBrains Mono',monospace;font-size:9px;color:#1e2d3d;">◈ ENCRYPTED</span>
        <span style="font-family:'JetBrains Mono',monospace;font-size:9px;color:#1e2d3d;">◈ ROLE-BASED ACCESS</span>
        <span style="font-family:'JetBrains Mono',monospace;font-size:9px;color:#1e2d3d;">◈ AUDIT LOGGED</span>
    </div>
</div>
""",
    unsafe_allow_html=True,
)
