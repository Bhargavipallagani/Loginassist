import sqlite3
from datetime import datetime, timedelta
from flask import Flask, request, redirect, session
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-secret"
DB = "app.db"
LOCK_AFTER = 5       # failed attempts in a row
LOCK_SECONDS = 60    # how long the account stays locked
RISK_WINDOW_MIN = 30  # risk looks at attempts from the last 30 minutes
ADMIN_EMAIL = "admin@test.com"   # only this account can open /admin

COUNTDOWN = ("<script>var s=document.getElementById('t'),n=parseInt(s.textContent);"
             "var i=setInterval(function(){n--;if(n<=0){clearInterval(i);"
             "s.parentNode.textContent='You can try again now.';}else{s.textContent=n;}},1000);</script>")

CSS = """
*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI",system-ui,sans-serif;background:#eef2f7;color:#0f172a;line-height:1.5}
header{background:linear-gradient(135deg,#0f172a,#1e3a5f)}
.bar{max-width:880px;margin:0 auto;padding:14px 20px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
.brand{color:#fff;font-weight:700;font-size:20px;letter-spacing:.3px}
nav a{color:#cbd5e1;text-decoration:none;margin-left:16px;font-size:14px}
nav a:hover{color:#5eead4}
main{max-width:880px;margin:28px auto;padding:0 16px}
.card{background:#fff;border-radius:14px;padding:28px;box-shadow:0 6px 24px rgba(15,23,42,.08)}
h1{margin:0 0 16px;font-size:26px}
h3{margin:22px 0 8px;font-size:17px;color:#1e3a5f}
input{width:100%;max-width:340px;padding:11px 13px;border:1px solid #cbd5e1;border-radius:8px;font-size:15px;margin-bottom:12px;display:block}
input:focus{outline:none;border-color:#0f766e;box-shadow:0 0 0 3px rgba(15,118,110,.18)}
button{background:#0f766e;color:#fff;border:0;border-radius:8px;padding:11px 20px;font-size:15px;font-weight:600;cursor:pointer}
button:hover{background:#115e59}
.inline{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-start}
.inline input{margin-bottom:0}
.alert{background:#fee2e2;color:#991b1b;border-radius:8px;padding:11px 14px;margin-bottom:16px}
.alert.ok{background:#dcfce7;color:#166534}
.muted{color:#64748b;font-size:14px}
.pill{display:inline-block;padding:3px 12px;border-radius:999px;font-weight:600;font-size:14px}
.Low{background:#dcfce7;color:#166534}
.Medium{background:#fef3c7;color:#92400e}
.High{background:#fee2e2;color:#991b1b}
.risk{background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:14px;margin:6px 0 16px}
.wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}
th{background:#f1f5f9;text-align:left;color:#475569}
th,td{padding:10px 12px;border-bottom:1px solid #e2e8f0}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px}
.stat{background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:16px;text-align:center}
.stat b{display:block;font-size:28px;color:#0f766e}
.stat span{font-size:13px;color:#64748b}
.row{margin:12px 0}
.track{background:#e2e8f0;border-radius:6px;height:14px;margin-top:4px}
.fill{height:14px;border-radius:6px;background:linear-gradient(90deg,#0f766e,#14b8a6)}
ol{padding-left:22px}
li{margin:6px 0}
.hint{margin-top:18px}
.hint a{color:#0f766e}
"""


def form(button):
    return ("<form method=post><input name=email placeholder='Email address' required>"
            "<input name=pw type=password placeholder='Password' required>"
            f"<button>{button}</button></form>")


def nav():
    email = session.get("email")
    links = [("/welcome", "Home"), ("/logs", "My attempts")] if email else [("/", "Log in"), ("/signup", "Sign up")]
    links.append(("/help", "Help"))
    if email == ADMIN_EMAIL:
        links.append(("/admin", "Admin"))
    if email:
        links.append(("/logout", "Logout"))
    return "".join(f"<a href='{u}'>{n}</a>" for u, n in links)


def page(title, msg, body, ok=False):
    cls = "alert ok" if ok else "alert"
    note = f"<div class='{cls}'>{msg}</div>" if msg else ""
    return ("<!doctype html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1'>"
            f"<title>{title} | LoginAssist</title><style>{CSS}</style></head><body>"
            f"<header><div class='bar'><span class='brand'>LoginAssist</span><nav>{nav()}</nav></div></header>"
            f"<main><div class='card'><h1>{title}</h1>{note}{body}</div></main></body></html>")


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init():
    c = db()
    c.execute("CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY, pw TEXT)")
    c.execute("""CREATE TABLE IF NOT EXISTS attempts(
        id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT, time TEXT,
        ok INTEGER, reason TEXT, device TEXT)""")
    c.commit()
    c.close()


def log(email, ok, reason):
    c = db()
    c.execute("INSERT INTO attempts(email,time,ok,reason,device) VALUES(?,?,?,?,?)",
              (email, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), int(ok), reason,
               request.headers.get("User-Agent", "")[:50]))
    c.commit()
    c.close()


def locked_seconds_left(email):
    """Seconds left on the lock, or 0 if the account is not locked."""
    c = db()
    rows = c.execute(
        "SELECT ok,time FROM attempts WHERE email=? AND reason!='Account locked' "
        "ORDER BY id DESC LIMIT ?", (email, LOCK_AFTER)).fetchall()
    c.close()
    if len(rows) < LOCK_AFTER or any(r["ok"] for r in rows):
        return 0
    last = datetime.strptime(rows[0]["time"], "%Y-%m-%d %H:%M:%S")
    left = LOCK_SECONDS - (datetime.now() - last).total_seconds()
    return int(left) + 1 if left > 0 else 0


def risk_for(email):
    """Return (level, reasons) from the recent attempts of this email."""
    since = (datetime.now() - timedelta(minutes=RISK_WINDOW_MIN)).strftime("%Y-%m-%d %H:%M:%S")
    c = db()
    rows = c.execute("SELECT ok,reason FROM attempts WHERE email=? AND time>=?",
                     (email, since)).fetchall()
    c.close()
    fails = sum(1 for r in rows if not r["ok"])
    locked = any(r["reason"] == "Account locked" for r in rows)
    if locked or fails >= 5:
        level = "High"
    elif fails >= 3:
        level = "Medium"
    else:
        level = "Low"
    reasons = [f"{fails} failed attempt(s) in the last {RISK_WINDOW_MIN} minutes"]
    if locked:
        reasons.append("The account was locked")
    return level, reasons


def risk_badge(email):
    level, reasons = risk_for(email)
    why = "<br>".join(escape(r) for r in reasons)
    return (f"<div class='risk'>Risk level: <span class='pill {level}'>{level}</span>"
            f"<div class='muted'>{why}</div></div>")


def diagnose(email):
    """Explain in plain words what happened, and what the user should do."""
    c = db()
    user = c.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone()
    since = (datetime.now() - timedelta(minutes=RISK_WINDOW_MIN)).strftime("%Y-%m-%d %H:%M:%S")
    rows = c.execute("SELECT ok,reason FROM attempts WHERE email=? AND time>=? ORDER BY id DESC",
                     (email, since)).fetchall()
    c.close()
    wrong = 0   # wrong passwords since the last successful login
    for r in rows:   # rows are newest first
        if r["ok"]:
            break
        if r["reason"] == "Wrong password":
            wrong += 1
    left = locked_seconds_left(email) if user else 0
    if not user:
        return ("No account was found with this email.",
                ["Check the spelling and remove extra spaces.",
                 "Try the other email addresses you may have used.",
                 "If you never registered, use Sign up to create an account."])
    if left:
        return (f"Your account is locked for about {left} more seconds, "
                "because of too many wrong passwords in a row.",
                ["Wait until the timer ends.",
                 "Then enter your password slowly and check that Caps Lock is off.",
                 "If you do not remember the password, ask the admin to reset it."])
    if wrong >= 3:
        return (f"You entered a wrong password {wrong} times recently.",
                ["Check that Caps Lock is off and the keyboard language is correct.",
                 "Type the password in Notepad first, then copy it into the box.",
                 "If you do not remember it, ask the admin to reset it.",
                 "If these attempts were not you, someone may be guessing your "
                 "password. Change it as soon as you can."])
    if wrong >= 1:
        return (f"You entered a wrong password {wrong} time(s) recently. "
                "This is usually a typing mistake.",
                ["Try again carefully.",
                 "Check Caps Lock and the keyboard language."])
    if rows and rows[0]["ok"]:
        return ("Your recent logins worked, and no problems were found.",
                ["If a page does not load, refresh with Ctrl+F5.",
                 "Try another browser or a private window."])
    return ("No recent login attempts were found for this email.",
            ["Try logging in once, then come back here for a diagnosis."])


@app.route("/signup", methods=["GET", "POST"])
def signup():
    msg = ""
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        try:
            c = db()
            c.execute("INSERT INTO users VALUES(?,?)",
                      (email, generate_password_hash(request.form["pw"])))
            c.commit()
            c.close()
            return redirect("/?created=1")
        except sqlite3.IntegrityError:
            msg = "This email is already registered. Try logging in."
    hint = "<p class='muted hint'>Already have an account? <a href='/'>Log in</a></p>"
    return page("Create your account", msg, form("Create account") + hint)


@app.route("/", methods=["GET", "POST"])
def login():
    msg = ""
    extra = ""
    ok = False
    if request.method == "GET" and request.args.get("created"):
        msg, ok = "Account created. Please log in.", True
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        c = db()
        user = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        c.close()
        left = locked_seconds_left(email) if user else 0
        if not user:
            log(email, False, "Email not found")
            msg = "No account with this email. Check spelling or sign up."
        elif left:
            log(email, False, "Account locked")
            msg = f"Account locked: too many failed attempts. Try again in <span id='t'>{left}</span> seconds."
            extra = COUNTDOWN
        elif not check_password_hash(user["pw"], request.form["pw"]):
            log(email, False, "Wrong password")
            msg = "Wrong password. Check Caps Lock and try again."
        else:
            log(email, True, "")
            session["email"] = email
            return redirect("/welcome")
    hint = ("<p class='muted hint'>New here? <a href='/signup'>Create an account</a> "
            "&nbsp;|&nbsp; <a href='/help'>Need help logging in?</a></p>")
    return page("Log in", msg, form("Log in") + extra + hint, ok)


@app.route("/welcome")
def welcome():
    email = session.get("email")
    if not email:
        return redirect("/")
    body = f"<p>You are logged in as <b>{escape(email)}</b>.</p>" + risk_badge(email)
    return page("Welcome back", "", body)


@app.route("/logs")
def logs():
    email = session.get("email")
    if not email:
        return redirect("/")
    c = db()
    rows = c.execute("SELECT * FROM attempts WHERE email=? ORDER BY id DESC LIMIT 15",
                     (email,)).fetchall()
    c.close()
    fails = sum(1 for r in rows if not r["ok"])
    table = ("<div class='wrap'><table><tr><th>Time</th><th>Result</th>"
             "<th>Reason</th><th>Device</th></tr>")
    for r in rows:
        pill = "<span class='pill Low'>Success</span>" if r["ok"] else "<span class='pill High'>Failed</span>"
        table += (f"<tr><td>{r['time']}</td><td>{pill}</td>"
                  f"<td>{escape(r['reason'])}</td><td class='muted'>{escape(r['device'])}</td></tr>")
    table += "</table></div>"
    body = f"{risk_badge(email)}<p class='muted'>Failed attempts (last 15): <b>{fails}</b></p>{table}"
    return page("My login attempts", "", body)


@app.route("/help", methods=["GET", "POST"])
def help_page():
    email = session.get("email", "")
    result = ""
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        headline, steps = diagnose(email)
        items = "".join(f"<li>{escape(s)}</li>" for s in steps)
        result = f"<h3>{escape(headline)}</h3><p class='muted'>What to do:</p><ol>{items}</ol>"
    form_html = (f'<form method=post class="inline"><input name=email placeholder="Your email" '
                 f'value="{escape(email)}" required><button>Diagnose my problem</button></form>')
    return page("Why can't I log in?", "", form_html + result)


@app.route("/admin")
def admin():
    if session.get("email") != ADMIN_EMAIL:
        return page("Admin only", "This page is only for the admin account.",
                    "<p class='muted'>Log in as the admin to see the dashboard.</p>")
    c = db()
    users = c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
    total = c.execute("SELECT COUNT(*) n FROM attempts").fetchone()["n"]
    ok = c.execute("SELECT COUNT(*) n FROM attempts WHERE ok=1").fetchone()["n"]
    reasons = c.execute("SELECT reason, COUNT(*) n FROM attempts WHERE ok=0 "
                        "GROUP BY reason ORDER BY n DESC").fetchall()
    emails = [r["email"] for r in c.execute("SELECT DISTINCT email FROM attempts").fetchall()]
    c.close()
    fails = total - ok
    rate = round(100 * ok / total) if total else 0
    cards = "".join(f"<div class='stat'><b>{v}</b><span>{k}</span></div>"
                    for k, v in [("Users", users), ("Attempts", total), ("Failed", fails),
                                 ("Success rate", f"{rate}%")])
    top = reasons[0]["n"] if reasons else 1
    bars = "".join(
        f"<div class='row'>{escape(r['reason'])}: <b>{r['n']}</b>"
        f"<div class='track'><div class='fill' style='width:{int(r['n'] / top * 100)}%'></div></div></div>"
        for r in reasons) or "<p class='muted'>No failed attempts yet.</p>"
    rows = ""
    for e in emails:
        level, why = risk_for(e)
        if level != "Low":
            rows += (f"<tr><td>{escape(e)}</td><td><span class='pill {level}'>{level}</span></td>"
                     f"<td>{escape(why[0])}</td></tr>")
    risk_table = ("<div class='wrap'><table><tr><th>Email</th><th>Risk</th><th>Why</th></tr>"
                  + rows + "</table></div>") if rows else "<p class='muted'>No accounts at risk right now.</p>"
    body = (f"<div class='stats'>{cards}</div><h3>Why logins fail</h3>{bars}"
            f"<h3>Accounts at risk (last {RISK_WINDOW_MIN} min)</h3>{risk_table}")
    return page("Admin dashboard", "", body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init()
    app.run(debug=True)