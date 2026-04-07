"""
Uptime Service — Dashboard Server v4
Flask + SQLite — Auth multi-utente + 2FA TOTP + persistenza completa
"""
from flask import Flask, request, jsonify, abort, Response, redirect
from flask_cors import CORS
import os, hashlib, threading, secrets, base64, time, hmac, struct, sqlite3
from datetime import datetime, timedelta
from functools import wraps
import urllib.parse

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "uptime-rmm-secret-key-2025")
CORS(app)
API_KEY = os.environ.get("UPTIME_API_KEY", "uptime-sos-2025")

DB_PATH = os.environ.get("DB_PATH", "dashboard.db")
_lock = threading.Lock()

# ── Database ──────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with get_db() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            totp_secret TEXT NOT NULL,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            uid TEXT NOT NULL,
            created_at TEXT NOT NULL,
            totp_verified INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS orgs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            color TEXT NOT NULL DEFAULT '#00d4aa',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sites (
            id TEXT PRIMARY KEY,
            oid TEXT NOT NULL,
            name TEXT NOT NULL,
            address TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS depts (
            id TEXT PRIMARY KEY,
            sid TEXT NOT NULL,
            oid TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS machines (
            id TEXT PRIMARY KEY,
            pc_name TEXT NOT NULL,
            username TEXT DEFAULT '',
            domain TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            os TEXT DEFAULT '',
            rustdesk_id TEXT DEFAULT '',
            last_seen TEXT NOT NULL,
            status TEXT DEFAULT 'offline',
            cpu INTEGER DEFAULT 0,
            ram INTEGER DEFAULT 0,
            disk INTEGER DEFAULT 0,
            oid TEXT,
            sid TEXT,
            did TEXT
        );
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_id TEXT NOT NULL,
            pc_name TEXT NOT NULL,
            username TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            rustdesk_id TEXT DEFAULT '',
            description TEXT DEFAULT '',
            screenshot TEXT DEFAULT '',
            status TEXT DEFAULT 'open',
            priority TEXT DEFAULT 'normal',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            note TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS doc_apps (
            id TEXT PRIMARY KEY,
            oid TEXT NOT NULL,
            name TEXT NOT NULL,
            category TEXT DEFAULT 'Software',
            version TEXT DEFAULT '',
            license_type TEXT DEFAULT '',
            license_count INTEGER DEFAULT 0,
            license_expiry TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS doc_kb (
            id TEXT PRIMARY KEY,
            oid TEXT NOT NULL,
            title TEXT NOT NULL,
            category TEXT DEFAULT 'Generale',
            content TEXT DEFAULT '',
            tags TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS doc_checklists (
            id TEXT PRIMARY KEY,
            oid TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS doc_checklist_items (
            id TEXT PRIMARY KEY,
            checklist_id TEXT NOT NULL,
            text TEXT NOT NULL,
            checked INTEGER NOT NULL DEFAULT 0,
            sort_order INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS doc_wiki (
            id TEXT PRIMARY KEY,
            oid TEXT NOT NULL,
            title TEXT NOT NULL,
            content TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """)
        if not db.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            uid = _new_uid()
            db.execute(
                "INSERT INTO users VALUES (?,?,?,?,?,?,?)",
                (uid, "admin", _hash("admin"), "admin", _totp_secret(), 0, _now())
            )
        db.commit()


def _row(r):
    return dict(r) if r else None

def _rows(rs):
    return [dict(r) for r in rs]

def _new_uid():
    return secrets.token_hex(8)

# ── Helpers ───────────────────────────────────────────────────
def _now(): return datetime.now().isoformat()
def _hash(s): return hashlib.sha256(s.encode()).hexdigest()

# ── TOTP (RFC 6238) ───────────────────────────────────────────
def _totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode()

def _totp_code(secret, t=None):
    if t is None: t = int(time.time()) // 30
    key = base64.b32decode(secret.upper())
    msg = struct.pack('>Q', t)
    h   = hmac.new(key, msg, 'sha1').digest()
    o   = h[-1] & 0x0f
    code = (struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff) % 1000000
    return f"{code:06d}"

def _totp_verify(secret, code):
    for delta in [-1, 0, 1]:
        if _totp_code(secret, int(time.time())//30 + delta) == code:
            return True
    return False

def _totp_uri(secret, username):
    label = urllib.parse.quote(f"Uptime RMM:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer=UptimeRMM&algorithm=SHA1&digits=6&period=30"

# ── Session helpers ───────────────────────────────────────────
def _create_session(uid):
    token = secrets.token_hex(32)
    with get_db() as db:
        # Pulisci sessioni vecchie dello stesso utente
        cutoff = (datetime.now() - timedelta(hours=8)).isoformat()
        db.execute("DELETE FROM sessions WHERE uid=? OR created_at<?", (uid, cutoff))
        db.execute("INSERT INTO sessions VALUES (?,?,?,?)", (token, uid, _now(), 0))
        db.commit()
    return token

def _get_session(token):
    if not token: return None
    with get_db() as db:
        s = _row(db.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone())
    if not s: return None
    created = datetime.fromisoformat(s["created_at"])
    if datetime.now() - created > timedelta(hours=8):
        with get_db() as db:
            db.execute("DELETE FROM sessions WHERE token=?", (token,))
            db.commit()
        return None
    return s

def _set_totp_verified(token):
    with get_db() as db:
        db.execute("UPDATE sessions SET totp_verified=1 WHERE token=?", (token,))
        db.commit()

def _current_user():
    token = request.cookies.get("uptime_token") or request.headers.get("X-Session-Token")
    if not token: return None, None
    s = _get_session(token)
    if not s: return None, None
    with get_db() as db:
        u = _row(db.execute("SELECT * FROM users WHERE id=?", (s["uid"],)).fetchone())
    return u, s

# ── Auth decorators ───────────────────────────────────────────
def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        u, s = _current_user()
        if not u: return redirect('/login')
        if u.get("totp_enabled") and not s.get("totp_verified"):
            return redirect('/login/2fa')
        return f(*args, **kwargs)
    return decorated

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if key == API_KEY:
            return f(*args, **kwargs)
        u, s = _current_user()
        if u and (not u.get("totp_enabled") or s.get("totp_verified")):
            return f(*args, **kwargs)
        abort(401)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        u, s = _current_user()
        if not u or u.get("role") != "admin":
            # controlla anche API key + admin
            key = request.headers.get("X-API-Key") or request.args.get("api_key")
            if key != API_KEY:
                abort(403)
        return f(*args, **kwargs)
    return decorated

# ── Login routes ──────────────────────────────────────────────
@app.route("/login", methods=["GET"])
def login_page():
    return Response(LOGIN_HTML, mimetype="text/html")

@app.route("/login/2fa", methods=["GET"])
def totp_page():
    return Response(TOTP_HTML, mimetype="text/html")

@app.route("/api/auth/login", methods=["POST"])
def do_login():
    d = request.json or {}
    username = d.get("username","").strip().lower()
    password = d.get("password","")
    with get_db() as db:
        user = _row(db.execute(
            "SELECT * FROM users WHERE LOWER(username)=?", (username,)
        ).fetchone())
    if not user or user["password_hash"] != _hash(password):
        return jsonify({"ok": False, "error": "Credenziali non valide"}), 401
    token = _create_session(user["id"])
    resp = jsonify({"ok": True, "needs_2fa": bool(user["totp_enabled"]), "token": token})
    resp.set_cookie("uptime_token", token, httponly=True, samesite="Lax", max_age=28800)
    return resp

@app.route("/api/auth/verify2fa", methods=["POST"])
def verify_2fa():
    d = request.json or {}
    code = d.get("code","").replace(" ","")
    token = request.cookies.get("uptime_token") or request.headers.get("X-Session-Token")
    s = _get_session(token)
    if not s: return jsonify({"ok": False, "error": "Sessione non valida"}), 401
    with get_db() as db:
        u = _row(db.execute("SELECT * FROM users WHERE id=?", (s["uid"],)).fetchone())
    if not u: return jsonify({"ok": False, "error": "Utente non trovato"}), 401
    if not _totp_verify(u["totp_secret"], code):
        return jsonify({"ok": False, "error": "Codice 2FA non valido"}), 401
    _set_totp_verified(token)
    return jsonify({"ok": True})

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    token = request.cookies.get("uptime_token")
    if token:
        with get_db() as db:
            db.execute("DELETE FROM sessions WHERE token=?", (token,))
            db.commit()
    resp = jsonify({"ok": True})
    resp.delete_cookie("uptime_token")
    return resp

@app.route("/api/auth/me")
def auth_me():
    u, s = _current_user()
    if not u: return jsonify({"ok": False}), 401
    return jsonify({"ok": True, "user": {
        "id": u["id"], "username": u["username"], "role": u["role"],
        "totp_enabled": bool(u["totp_enabled"])
    }})

# ── User management ───────────────────────────────────────────
@app.route("/api/users", methods=["GET"])
@require_api_key
@require_admin
def get_users():
    with get_db() as db:
        rows = _rows(db.execute("SELECT id,username,role,totp_enabled,created_at FROM users").fetchall())
    return jsonify(rows)

@app.route("/api/users", methods=["POST"])
@require_api_key
@require_admin
def create_user():
    d = request.json or {}
    username = d.get("username","").strip()
    password = d.get("password","")
    role     = d.get("role","viewer")
    if not username or not password:
        return jsonify({"error":"Username e password obbligatori"}), 400
    uid = _new_uid()
    ts  = _totp_secret()
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO users VALUES (?,?,?,?,?,?,?)",
                (uid, username, _hash(password), role, ts, 0, _now())
            )
            db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error":"Username già esistente"}), 409
    return jsonify({"id":uid,"username":username,"role":role,"totp_enabled":False,"created_at":_now()})

@app.route("/api/users/<uid>", methods=["PATCH"])
@require_api_key
@require_admin
def update_user(uid):
    d = request.json or {}
    with get_db() as db:
        if not db.execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone(): abort(404)
        if "role"     in d: db.execute("UPDATE users SET role=? WHERE id=?", (d["role"], uid))
        if "password" in d: db.execute("UPDATE users SET password_hash=? WHERE id=?", (_hash(d["password"]), uid))
        db.commit()
    return jsonify({"ok": True})

@app.route("/api/users/<uid>", methods=["DELETE"])
@require_api_key
@require_admin
def delete_user(uid):
    with get_db() as db:
        if not db.execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone(): abort(404)
        admins = db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        role   = db.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()[0]
        if role == "admin" and admins <= 1:
            return jsonify({"error":"Non puoi eliminare l'unico admin"}), 400
        db.execute("DELETE FROM users WHERE id=?", (uid,))
        db.execute("DELETE FROM sessions WHERE uid=?", (uid,))
        db.commit()
    return jsonify({"ok": True})

# ── 2FA ───────────────────────────────────────────────────────
@app.route("/api/auth/2fa/setup", methods=["GET"])
@require_api_key
def totp_setup():
    u, _ = _current_user()
    uid_param = request.args.get("uid")
    if uid_param:
        with get_db() as db:
            u = _row(db.execute("SELECT * FROM users WHERE id=?", (uid_param,)).fetchone())
    if not u:
        with get_db() as db:
            u = _row(db.execute("SELECT * FROM users WHERE role='admin' LIMIT 1").fetchone())
    if not u: abort(401)
    uri = _totp_uri(u["totp_secret"], u["username"])
    return jsonify({"secret": u["totp_secret"], "uri": uri, "username": u["username"]})

@app.route("/api/auth/2fa/enable", methods=["POST"])
@require_api_key
def totp_enable():
    d = request.json or {}
    uid = d.get("uid")
    code = d.get("code","").replace(" ","")
    with get_db() as db:
        target = _row(db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()) if uid else None
        if not target:
            u, _ = _current_user()
            target = u
        if not target: abort(404)
        if not _totp_verify(target["totp_secret"], code):
            return jsonify({"ok": False, "error": "Codice non valido"}), 400
        db.execute("UPDATE users SET totp_enabled=1 WHERE id=?", (target["id"],))
        db.commit()
    return jsonify({"ok": True})

@app.route("/api/auth/2fa/disable", methods=["POST"])
@require_api_key
@require_admin
def totp_disable():
    d = request.json or {}
    uid = d.get("uid")
    with get_db() as db:
        if not db.execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone(): abort(404)
        new_secret = _totp_secret()
        db.execute("UPDATE users SET totp_enabled=0, totp_secret=? WHERE id=?", (new_secret, uid))
        db.commit()
    return jsonify({"ok": True})

# ── Org API ───────────────────────────────────────────────────
@app.route("/api/orgs", methods=["GET"])
@require_api_key
def get_orgs():
    with get_db() as db:
        return jsonify(_rows(db.execute("SELECT * FROM orgs ORDER BY name").fetchall()))

@app.route("/api/orgs", methods=["POST"])
@require_api_key
def create_org():
    d = request.json or {}
    oid = _new_uid()
    row = {"id":oid,"name":d.get("name","Nuova Org"),"color":d.get("color","#00d4aa"),"created_at":_now()}
    with get_db() as db:
        db.execute("INSERT INTO orgs VALUES (?,?,?,?)", (row["id"],row["name"],row["color"],row["created_at"]))
        db.commit()
    return jsonify(row)

@app.route("/api/orgs/<oid>", methods=["PATCH"])
@require_api_key
def update_org(oid):
    d = request.json or {}
    with get_db() as db:
        if not db.execute("SELECT 1 FROM orgs WHERE id=?", (oid,)).fetchone(): abort(404)
        if "name"  in d: db.execute("UPDATE orgs SET name=?  WHERE id=?", (d["name"],  oid))
        if "color" in d: db.execute("UPDATE orgs SET color=? WHERE id=?", (d["color"], oid))
        db.commit()
        return jsonify(_row(db.execute("SELECT * FROM orgs WHERE id=?", (oid,)).fetchone()))

@app.route("/api/orgs/<oid>", methods=["DELETE"])
@require_api_key
def delete_org(oid):
    with get_db() as db:
        sids = [r[0] for r in db.execute("SELECT id FROM sites WHERE oid=?", (oid,)).fetchall()]
        for sid in sids:
            db.execute("DELETE FROM depts WHERE sid=?", (sid,))
        db.execute("DELETE FROM sites WHERE oid=?", (oid,))
        db.execute("UPDATE machines SET oid=NULL,sid=NULL,did=NULL WHERE oid=?", (oid,))
        db.execute("DELETE FROM orgs WHERE id=?", (oid,))
        db.commit()
    return jsonify({"ok":True})

# ── Sites API ─────────────────────────────────────────────────
@app.route("/api/sites", methods=["GET"])
@require_api_key
def get_sites():
    oid = request.args.get("oid")
    with get_db() as db:
        if oid:
            rows = _rows(db.execute("SELECT * FROM sites WHERE oid=? ORDER BY name", (oid,)).fetchall())
        else:
            rows = _rows(db.execute("SELECT * FROM sites ORDER BY name").fetchall())
    return jsonify(rows)

@app.route("/api/sites", methods=["POST"])
@require_api_key
def create_site():
    d = request.json or {}
    sid = _new_uid()
    row = {"id":sid,"oid":d.get("oid",""),"name":d.get("name","Nuova Sede"),"address":d.get("address",""),"created_at":_now()}
    with get_db() as db:
        db.execute("INSERT INTO sites VALUES (?,?,?,?,?)", (row["id"],row["oid"],row["name"],row["address"],row["created_at"]))
        db.commit()
    return jsonify(row)

@app.route("/api/sites/<sid>", methods=["PATCH"])
@require_api_key
def update_site(sid):
    d = request.json or {}
    with get_db() as db:
        if not db.execute("SELECT 1 FROM sites WHERE id=?", (sid,)).fetchone(): abort(404)
        for k,col in [("name","name"),("address","address"),("oid","oid")]:
            if k in d: db.execute(f"UPDATE sites SET {col}=? WHERE id=?", (d[k], sid))
        db.commit()
        return jsonify(_row(db.execute("SELECT * FROM sites WHERE id=?", (sid,)).fetchone()))

@app.route("/api/sites/<sid>", methods=["DELETE"])
@require_api_key
def delete_site(sid):
    with get_db() as db:
        db.execute("DELETE FROM depts WHERE sid=?", (sid,))
        db.execute("UPDATE machines SET sid=NULL,did=NULL WHERE sid=?", (sid,))
        db.execute("DELETE FROM sites WHERE id=?", (sid,))
        db.commit()
    return jsonify({"ok":True})

# ── Depts API ─────────────────────────────────────────────────
@app.route("/api/depts", methods=["GET"])
@require_api_key
def get_depts():
    sid = request.args.get("sid")
    with get_db() as db:
        if sid:
            rows = _rows(db.execute("SELECT * FROM depts WHERE sid=? ORDER BY name", (sid,)).fetchall())
        else:
            rows = _rows(db.execute("SELECT * FROM depts ORDER BY name").fetchall())
    return jsonify(rows)

@app.route("/api/depts", methods=["POST"])
@require_api_key
def create_dept():
    d = request.json or {}
    did = _new_uid()
    row = {"id":did,"sid":d.get("sid",""),"oid":d.get("oid",""),"name":d.get("name","Nuovo Reparto"),"created_at":_now()}
    with get_db() as db:
        db.execute("INSERT INTO depts VALUES (?,?,?,?,?)", (row["id"],row["sid"],row["oid"],row["name"],row["created_at"]))
        db.commit()
    return jsonify(row)

@app.route("/api/depts/<did>", methods=["PATCH"])
@require_api_key
def update_dept(did):
    d = request.json or {}
    with get_db() as db:
        if not db.execute("SELECT 1 FROM depts WHERE id=?", (did,)).fetchone(): abort(404)
        for k in ["name","sid","oid"]:
            if k in d: db.execute(f"UPDATE depts SET {k}=? WHERE id=?", (d[k], did))
        db.commit()
        return jsonify(_row(db.execute("SELECT * FROM depts WHERE id=?", (did,)).fetchone()))

@app.route("/api/depts/<did>", methods=["DELETE"])
@require_api_key
def delete_dept(did):
    with get_db() as db:
        db.execute("UPDATE machines SET did=NULL WHERE did=?", (did,))
        db.execute("DELETE FROM depts WHERE id=?", (did,))
        db.commit()
    return jsonify({"ok":True})

# ── Machine assign ────────────────────────────────────────────
@app.route("/api/machines/<mid>/assign", methods=["PATCH"])
@require_api_key
def assign_machine(mid):
    d = request.json or {}
    with get_db() as db:
        if not db.execute("SELECT 1 FROM machines WHERE id=?", (mid,)).fetchone(): abort(404)
        db.execute("UPDATE machines SET oid=?,sid=?,did=? WHERE id=?",
                   (d.get("oid"), d.get("sid"), d.get("did"), mid))
        db.commit()
    return jsonify({"ok":True})

# ── Ticket / Heartbeat / Machines API ─────────────────────────
def _upsert_machine(db, mid, pc, domain, data, now):
    existing = db.execute("SELECT * FROM machines WHERE id=?", (mid,)).fetchone()
    if existing:
        db.execute("""UPDATE machines SET
            username=COALESCE(NULLIF(?,''),(SELECT username FROM machines WHERE id=?)),
            ip=COALESCE(NULLIF(?,''),(SELECT ip FROM machines WHERE id=?)),
            rustdesk_id=COALESCE(NULLIF(?,''),(SELECT rustdesk_id FROM machines WHERE id=?)),
            last_seen=?, status='online',
            cpu=?, ram=?, disk=?
            WHERE id=?""", (
            data.get("user",""), mid,
            data.get("ip",""),   mid,
            data.get("rustdesk_id",""), mid,
            now,
            data.get("cpu",0), data.get("ram",0), data.get("disk",0),
            mid))
    else:
        db.execute("""INSERT INTO machines
            (id,pc_name,username,domain,ip,os,rustdesk_id,last_seen,status,cpu,ram,disk,oid,sid,did)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            mid, pc,
            data.get("user",""), domain,
            data.get("ip",""), data.get("os",""),
            data.get("rustdesk_id",""),
            now, "online",
            data.get("cpu",0), data.get("ram",0), data.get("disk",0),
            None, None, None))

@app.route("/api/ticket", methods=["POST"])
@require_api_key
def create_ticket():
    data = request.json or {}
    pc = data.get("pc_name","N/D"); domain = data.get("domain","N/D")
    mid = hashlib.md5(f"{pc}{domain}".encode()).hexdigest()[:12]
    now = _now()
    with _lock:
        with get_db() as db:
            _upsert_machine(db, mid, pc, domain, data, now)
            db.execute("""INSERT INTO tickets
                (machine_id,pc_name,username,ip,rustdesk_id,description,screenshot,status,priority,created_at,updated_at,note)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (
                mid, pc,
                data.get("user",""), data.get("ip",""),
                data.get("rustdesk_id",""), data.get("description",""),
                data.get("screenshot",""), "open",
                data.get("priority","normal"), now, now, ""))
            tid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            db.commit()
    return jsonify({"ok":True,"ticket_id":tid,"machine_id":mid})

@app.route("/api/heartbeat", methods=["POST"])
@require_api_key
def heartbeat():
    data = request.json or {}
    pc = data.get("pc_name","N/D"); domain = data.get("domain","N/D")
    mid = hashlib.md5(f"{pc}{domain}".encode()).hexdigest()[:12]
    now = _now()
    with _lock:
        with get_db() as db:
            _upsert_machine(db, mid, pc, domain, data, now)
            db.commit()
    return jsonify({"ok":True})

@app.route("/api/machines")
@require_api_key
def get_machines():
    threshold = (datetime.now()-timedelta(minutes=5)).isoformat()
    with get_db() as db:
        db.execute("UPDATE machines SET status='offline' WHERE last_seen<?", (threshold,))
        db.commit()
        rows = _rows(db.execute("SELECT * FROM machines ORDER BY pc_name").fetchall())
    # rinomina username -> user per compatibilità frontend
    for r in rows:
        r["user"] = r.pop("username", "")
    return jsonify(rows)

@app.route("/api/tickets")
@require_api_key
def get_tickets():
    status = request.args.get("status","all")
    with get_db() as db:
        if status == "all":
            rows = _rows(db.execute("SELECT * FROM tickets ORDER BY id DESC").fetchall())
        else:
            rows = _rows(db.execute("SELECT * FROM tickets WHERE status=? ORDER BY id DESC", (status,)).fetchall())
    for r in rows:
        r.pop("screenshot", None)
        r["user"] = r.pop("username", "")
    return jsonify(rows)

@app.route("/api/ticket/<int:tid>")
@require_api_key
def get_ticket(tid):
    with get_db() as db:
        row = _row(db.execute("SELECT * FROM tickets WHERE id=?", (tid,)).fetchone())
    if not row: abort(404)
    row["user"] = row.pop("username", "")
    return jsonify(row)

@app.route("/api/ticket/<int:tid>", methods=["PATCH"])
@require_api_key
def update_ticket(tid):
    data = request.json or {}
    with get_db() as db:
        if not db.execute("SELECT 1 FROM tickets WHERE id=?", (tid,)).fetchone(): abort(404)
        for k in ["status","priority","note"]:
            if k in data: db.execute(f"UPDATE tickets SET {k}=? WHERE id=?", (data[k], tid))
        db.execute("UPDATE tickets SET updated_at=? WHERE id=?", (_now(), tid))
        db.commit()
    return jsonify({"ok":True})

@app.route("/api/stats")
@require_api_key
def get_stats():
    threshold = (datetime.now()-timedelta(minutes=5)).isoformat()
    with get_db() as db:
        total   = db.execute("SELECT COUNT(*) FROM machines").fetchone()[0]
        online  = db.execute("SELECT COUNT(*) FROM machines WHERE last_seen>=?", (threshold,)).fetchone()[0]
        t_open  = db.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0]
        t_close = db.execute("SELECT COUNT(*) FROM tickets WHERE status='closed'").fetchone()[0]
        urgent  = db.execute("SELECT COUNT(*) FROM tickets WHERE status='open' AND priority='urgent'").fetchone()[0]
        norgs   = db.execute("SELECT COUNT(*) FROM orgs").fetchone()[0]
    return jsonify({"total_machines":total,"online_machines":online,"offline_machines":total-online,
                    "open_tickets":t_open,"closed_tickets":t_close,"urgent_tickets":urgent,"total_orgs":norgs})

@app.route("/api/demo", methods=["POST"])
def demo_data():
    now = _now()
    with _lock:
        with get_db() as db:
            # Orgs
            db.execute("DELETE FROM orgs WHERE id IN ('d1','d2')")
            db.execute("INSERT OR REPLACE INTO orgs VALUES ('d1','Emotion Design Srl','#00d4aa',?)", (now,))
            db.execute("INSERT OR REPLACE INTO orgs VALUES ('d2','Cliente Rossi Spa','#0091ff',?)", (now,))
            # Sites
            db.execute("INSERT OR REPLACE INTO sites VALUES ('s1','d1','Sede Milano','Via Roma 1, Milano',?)", (now,))
            db.execute("INSERT OR REPLACE INTO sites VALUES ('s2','d1','Sede Roma','Via Veneto 10, Roma',?)", (now,))
            db.execute("INSERT OR REPLACE INTO sites VALUES ('s3','d2','Sede Principale','Corso Italia 5, Torino',?)", (now,))
            # Depts
            db.execute("INSERT OR REPLACE INTO depts VALUES ('dp1','s1','d1','Amministrazione',?)", (now,))
            db.execute("INSERT OR REPLACE INTO depts VALUES ('dp2','s1','d1','IT',?)", (now,))
            db.execute("INSERT OR REPLACE INTO depts VALUES ('dp3','s2','d1','Commerciale',?)", (now,))
            # Machines
            ms = [
                ("abc001","DESKTOP-MARIO","mario.rossi","EMOTIONDESIGN","192.168.1.10","Windows 11 Pro","123 456 789",now,"online",45,62,78,"d1","s1","dp1"),
                ("abc002","LAPTOP-GIULIA","giulia.bianchi","EMOTIONDESIGN","192.168.1.11","Windows 10 Pro","987 654 321",now,"online",12,34,45,"d1","s1","dp2"),
                ("abc003","PC-CONTABILITA","admin","WORKGROUP","192.168.1.20","Windows 10 Home","","2020-01-01","offline",0,0,0,"d1","s2","dp3"),
                ("abc004","SERVER-FILE","Administrator","EMOTIONDESIGN","192.168.1.1","Windows Server 2022","111 222 333",now,"online",78,88,92,"d2","s3",None),
            ]
            for m in ms:
                db.execute("""INSERT OR REPLACE INTO machines
                    (id,pc_name,username,domain,ip,os,rustdesk_id,last_seen,status,cpu,ram,disk,oid,sid,did)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", m)
            # Tickets
            ts = [
                ("abc001","DESKTOP-MARIO","mario.rossi","192.168.1.10","123 456 789","Il PC va lento, non riesco ad aprire Excel","urgent"),
                ("abc002","LAPTOP-GIULIA","giulia.bianchi","192.168.1.11","987 654 321","Stampante non trovata in rete","normal"),
                ("abc004","SERVER-FILE","Administrator","192.168.1.1","111 222 333","Disco quasi pieno 92%","urgent"),
            ]
            for t in ts:
                existing = db.execute("SELECT 1 FROM tickets WHERE machine_id=? AND description=?", (t[0],t[5])).fetchone()
                if not existing:
                    db.execute("""INSERT INTO tickets
                        (machine_id,pc_name,username,ip,rustdesk_id,description,screenshot,status,priority,created_at,updated_at,note)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (t[0],t[1],t[2],t[3],t[4],t[5],"","open",t[6],now,now,""))
            db.commit()
    return jsonify({"ok":True})

# ═══════════════════════════════════════════════════════════════

# ── Documentation API ─────────────────────────────────────────
# Tabelle: doc_apps, doc_kb, doc_checklists, doc_checklist_items, doc_wiki

# ── App e Servizi ─────────────────────────────────────────────
@app.route("/api/orgs/<oid>/docs/apps", methods=["GET"])
@require_api_key
def get_doc_apps(oid):
    with get_db() as db:
        rows = _rows(db.execute("SELECT * FROM doc_apps WHERE oid=? ORDER BY name", (oid,)).fetchall())
    return jsonify(rows)

@app.route("/api/orgs/<oid>/docs/apps", methods=["POST"])
@require_api_key
def create_doc_app(oid):
    d = request.json or {}
    aid = _new_uid()
    row = {"id":aid,"oid":oid,"name":d.get("name",""),"category":d.get("category","Software"),
           "version":d.get("version",""),"license_type":d.get("license_type",""),
           "license_count":d.get("license_count",0),"license_expiry":d.get("license_expiry",""),
           "notes":d.get("notes",""),"created_at":_now()}
    with get_db() as db:
        db.execute("INSERT INTO doc_apps VALUES (?,?,?,?,?,?,?,?,?,?)",
            (row["id"],row["oid"],row["name"],row["category"],row["version"],
             row["license_type"],row["license_count"],row["license_expiry"],row["notes"],row["created_at"]))
        db.commit()
    return jsonify(row)

@app.route("/api/orgs/<oid>/docs/apps/<aid>", methods=["PATCH"])
@require_api_key
def update_doc_app(oid, aid):
    d = request.json or {}
    with get_db() as db:
        if not db.execute("SELECT 1 FROM doc_apps WHERE id=? AND oid=?", (aid,oid)).fetchone(): abort(404)
        for k in ["name","category","version","license_type","license_count","license_expiry","notes"]:
            if k in d: db.execute(f"UPDATE doc_apps SET {k}=? WHERE id=?", (d[k], aid))
        db.commit()
        return jsonify(_row(db.execute("SELECT * FROM doc_apps WHERE id=?", (aid,)).fetchone()))

@app.route("/api/orgs/<oid>/docs/apps/<aid>", methods=["DELETE"])
@require_api_key
def delete_doc_app(oid, aid):
    with get_db() as db:
        db.execute("DELETE FROM doc_apps WHERE id=? AND oid=?", (aid, oid))
        db.commit()
    return jsonify({"ok":True})

# ── Knowledge Base ────────────────────────────────────────────
@app.route("/api/orgs/<oid>/docs/kb", methods=["GET"])
@require_api_key
def get_doc_kb(oid):
    with get_db() as db:
        rows = _rows(db.execute("SELECT * FROM doc_kb WHERE oid=? ORDER BY created_at DESC", (oid,)).fetchall())
    return jsonify(rows)

@app.route("/api/orgs/<oid>/docs/kb", methods=["POST"])
@require_api_key
def create_doc_kb(oid):
    d = request.json or {}
    kid = _new_uid()
    now = _now()
    row = {"id":kid,"oid":oid,"title":d.get("title","Nuovo articolo"),
           "category":d.get("category","Generale"),"content":d.get("content",""),
           "tags":d.get("tags",""),"created_at":now,"updated_at":now}
    with get_db() as db:
        db.execute("INSERT INTO doc_kb VALUES (?,?,?,?,?,?,?,?)",
            (row["id"],row["oid"],row["title"],row["category"],row["content"],row["tags"],row["created_at"],row["updated_at"]))
        db.commit()
    return jsonify(row)

@app.route("/api/orgs/<oid>/docs/kb/<kid>", methods=["PATCH"])
@require_api_key
def update_doc_kb(oid, kid):
    d = request.json or {}
    with get_db() as db:
        if not db.execute("SELECT 1 FROM doc_kb WHERE id=? AND oid=?", (kid,oid)).fetchone(): abort(404)
        for k in ["title","category","content","tags"]:
            if k in d: db.execute(f"UPDATE doc_kb SET {k}=? WHERE id=?", (d[k], kid))
        db.execute("UPDATE doc_kb SET updated_at=? WHERE id=?", (_now(), kid))
        db.commit()
        return jsonify(_row(db.execute("SELECT * FROM doc_kb WHERE id=?", (kid,)).fetchone()))

@app.route("/api/orgs/<oid>/docs/kb/<kid>", methods=["DELETE"])
@require_api_key
def delete_doc_kb(oid, kid):
    with get_db() as db:
        db.execute("DELETE FROM doc_kb WHERE id=? AND oid=?", (kid, oid))
        db.commit()
    return jsonify({"ok":True})

# ── Checklist ─────────────────────────────────────────────────
@app.route("/api/orgs/<oid>/docs/checklists", methods=["GET"])
@require_api_key
def get_doc_checklists(oid):
    with get_db() as db:
        cls = _rows(db.execute("SELECT * FROM doc_checklists WHERE oid=? ORDER BY created_at DESC", (oid,)).fetchall())
        for cl in cls:
            items = _rows(db.execute("SELECT * FROM doc_checklist_items WHERE checklist_id=? ORDER BY sort_order", (cl["id"],)).fetchall())
            cl["items"] = items
    return jsonify(cls)

@app.route("/api/orgs/<oid>/docs/checklists", methods=["POST"])
@require_api_key
def create_doc_checklist(oid):
    d = request.json or {}
    cid = _new_uid()
    row = {"id":cid,"oid":oid,"name":d.get("name","Nuova checklist"),"description":d.get("description",""),"created_at":_now()}
    with get_db() as db:
        db.execute("INSERT INTO doc_checklists VALUES (?,?,?,?,?)",
            (row["id"],row["oid"],row["name"],row["description"],row["created_at"]))
        db.commit()
    row["items"] = []
    return jsonify(row)

@app.route("/api/orgs/<oid>/docs/checklists/<cid>", methods=["PATCH"])
@require_api_key
def update_doc_checklist(oid, cid):
    d = request.json or {}
    with get_db() as db:
        if not db.execute("SELECT 1 FROM doc_checklists WHERE id=? AND oid=?", (cid,oid)).fetchone(): abort(404)
        for k in ["name","description"]:
            if k in d: db.execute(f"UPDATE doc_checklists SET {k}=? WHERE id=?", (d[k], cid))
        db.commit()
    return jsonify({"ok":True})

@app.route("/api/orgs/<oid>/docs/checklists/<cid>", methods=["DELETE"])
@require_api_key
def delete_doc_checklist(oid, cid):
    with get_db() as db:
        db.execute("DELETE FROM doc_checklist_items WHERE checklist_id=?", (cid,))
        db.execute("DELETE FROM doc_checklists WHERE id=? AND oid=?", (cid, oid))
        db.commit()
    return jsonify({"ok":True})

@app.route("/api/orgs/<oid>/docs/checklists/<cid>/items", methods=["POST"])
@require_api_key
def create_checklist_item(oid, cid):
    d = request.json or {}
    iid = _new_uid()
    with get_db() as db:
        cnt = db.execute("SELECT COUNT(*) FROM doc_checklist_items WHERE checklist_id=?", (cid,)).fetchone()[0]
        db.execute("INSERT INTO doc_checklist_items VALUES (?,?,?,?,?)",
            (iid, cid, d.get("text","Nuovo elemento"), 0, cnt))
        db.commit()
        return jsonify(_row(db.execute("SELECT * FROM doc_checklist_items WHERE id=?", (iid,)).fetchone()))

@app.route("/api/orgs/<oid>/docs/checklists/<cid>/items/<iid>", methods=["PATCH"])
@require_api_key
def update_checklist_item(oid, cid, iid):
    d = request.json or {}
    with get_db() as db:
        if "text"    in d: db.execute("UPDATE doc_checklist_items SET text=?    WHERE id=?", (d["text"], iid))
        if "checked" in d: db.execute("UPDATE doc_checklist_items SET checked=? WHERE id=?", (1 if d["checked"] else 0, iid))
        db.commit()
    return jsonify({"ok":True})

@app.route("/api/orgs/<oid>/docs/checklists/<cid>/items/<iid>", methods=["DELETE"])
@require_api_key
def delete_checklist_item(oid, cid, iid):
    with get_db() as db:
        db.execute("DELETE FROM doc_checklist_items WHERE id=?", (iid,))
        db.commit()
    return jsonify({"ok":True})

# ── Wiki / Note libere ────────────────────────────────────────
@app.route("/api/orgs/<oid>/docs/wiki", methods=["GET"])
@require_api_key
def get_doc_wiki(oid):
    with get_db() as db:
        rows = _rows(db.execute("SELECT * FROM doc_wiki WHERE oid=? ORDER BY updated_at DESC", (oid,)).fetchall())
    return jsonify(rows)

@app.route("/api/orgs/<oid>/docs/wiki", methods=["POST"])
@require_api_key
def create_doc_wiki(oid):
    d = request.json or {}
    wid = _new_uid()
    now = _now()
    row = {"id":wid,"oid":oid,"title":d.get("title","Nuova nota"),"content":d.get("content",""),"created_at":now,"updated_at":now}
    with get_db() as db:
        db.execute("INSERT INTO doc_wiki VALUES (?,?,?,?,?,?)",
            (row["id"],row["oid"],row["title"],row["content"],row["created_at"],row["updated_at"]))
        db.commit()
    return jsonify(row)

@app.route("/api/orgs/<oid>/docs/wiki/<wid>", methods=["PATCH"])
@require_api_key
def update_doc_wiki(oid, wid):
    d = request.json or {}
    with get_db() as db:
        if not db.execute("SELECT 1 FROM doc_wiki WHERE id=? AND oid=?", (wid,oid)).fetchone(): abort(404)
        for k in ["title","content"]:
            if k in d: db.execute(f"UPDATE doc_wiki SET {k}=? WHERE id=?", (d[k], wid))
        db.execute("UPDATE doc_wiki SET updated_at=? WHERE id=?", (_now(), wid))
        db.commit()
    return jsonify({"ok":True})

@app.route("/api/orgs/<oid>/docs/wiki/<wid>", methods=["DELETE"])
@require_api_key
def delete_doc_wiki(oid, wid):
    with get_db() as db:
        db.execute("DELETE FROM doc_wiki WHERE id=? AND oid=?", (wid, oid))
        db.commit()
    return jsonify({"ok":True})

# HTML TEMPLATES
# ═══════════════════════════════════════════════════════════════

LOGIN_HTML = """<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login — Uptime RMM</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Syne',sans-serif;background:#090c10;color:#e6edf3;display:flex;align-items:center;justify-content:center;min-height:100vh}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.03) 2px,rgba(0,0,0,.03) 4px);pointer-events:none}
.box{background:#0d1117;border:1px solid #2a3547;border-radius:16px;padding:40px;width:400px;max-width:95vw;position:relative;overflow:hidden}
.box::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#00d4aa,#0091ff)}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:32px;justify-content:center}
.logo-icon{width:40px;height:40px;background:linear-gradient(135deg,#00d4aa,#0091ff);border-radius:10px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:18px;color:#000}
.logo-text{font-size:18px;font-weight:800}
.logo-sub{font-size:9px;color:#00d4aa;letter-spacing:3px;font-family:'JetBrains Mono',monospace}
h2{font-size:20px;font-weight:800;margin-bottom:6px}
.sub{font-size:12px;color:#8b949e;margin-bottom:28px;font-family:'JetBrains Mono',monospace}
.form-row{margin-bottom:16px}
label{display:block;font-size:10px;color:#8b949e;letter-spacing:2px;text-transform:uppercase;font-family:'JetBrains Mono',monospace;margin-bottom:6px}
input{width:100%;background:#161b22;border:1px solid #2a3547;border-radius:8px;padding:11px 14px;color:#e6edf3;font-size:13px;font-family:'Syne',sans-serif;transition:border-color .2s}
input:focus{outline:none;border-color:#00d4aa}
.btn{width:100%;padding:12px;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer;border:none;font-family:'Syne',sans-serif;transition:all .2s;margin-top:4px}
.btn-p{background:#00d4aa;color:#000}.btn-p:hover{background:#00f0c0}
.err{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);border-radius:7px;padding:10px 14px;font-size:12px;color:#ff4757;margin-bottom:16px;display:none}
.hint{text-align:center;font-size:10px;color:#4a5568;margin-top:20px;font-family:'JetBrains Mono',monospace}
.hint span{color:#00d4aa}
</style>
</head>
<body>
<div class="box">
  <div class="logo" style="justify-content:center;margin-bottom:32px">
    <img src="data:image/png;base64,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" style="height:50px;width:auto;object-fit:contain" alt="Uptime Service">
  </div>
  <h2>Accedi</h2>
  <p class="sub">Inserisci le tue credenziali</p>
  <div class="err" id="err"></div>
  <div class="form-row"><label>Username</label><input id="usr" type="text" placeholder="admin" autocomplete="username"></div>
  <div class="form-row"><label>Password</label><input id="pwd" type="password" placeholder="••••••••" autocomplete="current-password"></div>
  <button class="btn btn-p" onclick="doLogin()">Accedi →</button>
  <p class="hint">Default: <span>admin</span> / <span>admin</span></p>
</div>
<script>
document.addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});
async function doLogin(){
  const usr=document.getElementById('usr').value.trim();
  const pwd=document.getElementById('pwd').value;
  if(!usr||!pwd){showErr('Inserisci username e password');return}
  const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:usr,password:pwd})});
  const d=await r.json();
  if(!d.ok){showErr(d.error||'Credenziali non valide');return}
  if(d.needs_2fa){window.location='/login/2fa'}else{window.location='/'}
}
function showErr(msg){const e=document.getElementById('err');e.textContent=msg;e.style.display='block'}
</script>
</body>
</html>"""

TOTP_HTML = """<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>2FA — Uptime RMM</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Syne',sans-serif;background:#090c10;color:#e6edf3;display:flex;align-items:center;justify-content:center;min-height:100vh}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.03) 2px,rgba(0,0,0,.03) 4px);pointer-events:none}
.box{background:#0d1117;border:1px solid #2a3547;border-radius:16px;padding:40px;width:400px;max-width:95vw;position:relative;overflow:hidden;text-align:center}
.box::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#00d4aa,#0091ff)}
.icon{font-size:48px;margin-bottom:16px}
h2{font-size:20px;font-weight:800;margin-bottom:6px}
.sub{font-size:12px;color:#8b949e;margin-bottom:28px;font-family:'JetBrains Mono',monospace}
.otp-inputs{display:flex;gap:8px;justify-content:center;margin-bottom:24px}
.otp-inputs input{width:44px;height:52px;background:#161b22;border:1px solid #2a3547;border-radius:8px;color:#00d4aa;font-size:22px;font-weight:700;font-family:'JetBrains Mono',monospace;text-align:center;transition:border-color .2s}
.otp-inputs input:focus{outline:none;border-color:#00d4aa;box-shadow:0 0 0 2px rgba(0,212,170,.15)}
.btn{width:100%;padding:12px;border-radius:8px;font-size:13px;font-weight:700;cursor:pointer;border:none;font-family:'Syne',sans-serif;transition:all .2s}
.btn-p{background:#00d4aa;color:#000}.btn-p:hover{background:#00f0c0}
.err{background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.3);border-radius:7px;padding:10px 14px;font-size:12px;color:#ff4757;margin-bottom:16px;display:none}
.back{font-size:11px;color:#4a5568;margin-top:18px;cursor:pointer;font-family:'JetBrains Mono',monospace}
.back:hover{color:#8b949e}
</style>
</head>
<body>
<div class="box">
  <div class="icon">🔐</div>
  <h2>Verifica 2FA</h2>
  <p class="sub">Inserisci il codice dall'app Authenticator</p>
  <div class="err" id="err"></div>
  <div class="otp-inputs" id="otp-wrap">
    <input type="text" maxlength="1" id="o0" oninput="otpNext(0)" onkeydown="otpBack(event,0)">
    <input type="text" maxlength="1" id="o1" oninput="otpNext(1)" onkeydown="otpBack(event,1)">
    <input type="text" maxlength="1" id="o2" oninput="otpNext(2)" onkeydown="otpBack(event,2)">
    <input type="text" maxlength="1" id="o3" oninput="otpNext(3)" onkeydown="otpBack(event,3)">
    <input type="text" maxlength="1" id="o4" oninput="otpNext(4)" onkeydown="otpBack(event,4)">
    <input type="text" maxlength="1" id="o5" oninput="otpNext(5)" onkeydown="otpBack(event,5)">
  </div>
  <button class="btn btn-p" onclick="verify()">Verifica →</button>
  <p class="back" onclick="window.location='/login'">← Torna al login</p>
</div>
<script>
document.getElementById('o0').focus();
function otpNext(i){
  const v=document.getElementById('o'+i).value;
  if(v&&i<5)document.getElementById('o'+(i+1)).focus();
  if(i===5&&v)verify();
}
function otpBack(e,i){
  if(e.key==='Backspace'&&!document.getElementById('o'+i).value&&i>0)
    document.getElementById('o'+(i-1)).focus();
}
function getCode(){return [0,1,2,3,4,5].map(i=>document.getElementById('o'+i).value).join('')}
async function verify(){
  const code=getCode();
  if(code.length<6){showErr('Inserisci tutti e 6 i digits');return}
  const r=await fetch('/api/auth/verify2fa',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code})});
  const d=await r.json();
  if(d.ok){window.location='/'}else{showErr(d.error||'Codice non valido');[0,1,2,3,4,5].forEach(i=>document.getElementById('o'+i).value='');document.getElementById('o0').focus()}
}
function showErr(msg){const e=document.getElementById('err');e.textContent=msg;e.style.display='block'}
</script>
</body>
</html>"""


DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Uptime Service RMM</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root{
  --bg0:#090c10;--bg1:#0d1117;--bg2:#161b22;--bg3:#1c2333;--bg4:#243044;
  --border:#2a3547;--accent:#00d4aa;--accent2:#0091ff;
  --red:#ff4757;--orange:#ffa502;--green:#00d4aa;--purple:#a78bfa;
  --text:#e6edf3;--text2:#8b949e;--text3:#4a5568;
  --glow:0 0 20px rgba(0,212,170,.12);
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Syne',sans-serif;background:var(--bg0);color:var(--text);display:flex;height:100vh;overflow:hidden}
body::before{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.025) 2px,rgba(0,0,0,.025) 4px);pointer-events:none;z-index:9999}

.sidebar{width:230px;background:var(--bg1);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;overflow:hidden}
.logo{padding:20px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;flex-shrink:0}
.logo-icon{width:32px;height:32px;background:linear-gradient(135deg,var(--accent),var(--accent2));border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:15px;color:#000;box-shadow:var(--glow)}
.logo-name{font-size:13px;font-weight:800;letter-spacing:.5px}
.logo-sub{font-size:9px;color:var(--accent);letter-spacing:2px;font-family:'JetBrains Mono',monospace}
.nav{flex:1;padding:12px 10px;overflow-y:auto}
.nav-sec{font-size:9px;color:var(--text3);letter-spacing:2px;padding:14px 8px 6px;font-family:'JetBrains Mono',monospace}
.nav-item{display:flex;align-items:center;gap:9px;padding:9px 10px;border-radius:7px;font-size:12px;font-weight:600;color:var(--text2);cursor:pointer;transition:all .2s;margin-bottom:2px;user-select:none}
.nav-item:hover{background:var(--bg2);color:var(--text)}
.nav-item.active{background:rgba(0,212,170,.1);color:var(--accent);box-shadow:inset 3px 0 0 var(--accent)}
.nav-badge{margin-left:auto;background:var(--red);color:#fff;font-size:9px;font-weight:700;padding:2px 6px;border-radius:8px;font-family:'JetBrains Mono',monospace}
.nav-badge.g{background:var(--accent);color:#000}
.sb-foot{padding:14px;border-top:1px solid var(--border);font-size:10px;color:var(--text3);font-family:'JetBrains Mono',monospace;flex-shrink:0}
.dot{display:inline-block;width:6px;height:6px;border-radius:50%;background:var(--accent);margin-right:5px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}

.org-tree{padding:4px 0}
.tree-org{margin-bottom:2px}
.tree-org-header{display:flex;align-items:center;gap:7px;padding:7px 10px;border-radius:7px;cursor:pointer;transition:all .2s;font-size:12px;font-weight:700}
.tree-org-header:hover{background:var(--bg3)}
.tree-org-header.active{background:rgba(0,212,170,.08);color:var(--accent)}
.tree-org-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.tree-chevron{margin-left:auto;font-size:10px;transition:transform .2s;color:var(--text3)}
.tree-chevron.open{transform:rotate(90deg)}
.tree-children{display:none;padding-left:18px}
.tree-children.open{display:block}
.tree-site{margin-bottom:1px}
.tree-site-header{display:flex;align-items:center;gap:7px;padding:6px 10px;border-radius:6px;cursor:pointer;transition:all .2s;font-size:11px;font-weight:600;color:var(--text2)}
.tree-site-header:hover{background:var(--bg3);color:var(--text)}
.tree-dept{display:flex;align-items:center;gap:7px;padding:5px 10px 5px 26px;border-radius:6px;cursor:pointer;font-size:11px;color:var(--text3);transition:all .2s}
.tree-dept:hover{background:var(--bg3);color:var(--text2)}
.tree-count{margin-left:auto;font-size:9px;color:var(--text3);font-family:'JetBrains Mono',monospace}

.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.topbar{padding:14px 24px;background:var(--bg1);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.topbar-left{display:flex;align-items:center;gap:12px}
.topbar-title{font-size:17px;font-weight:800}
.topbar-title span{color:var(--accent)}
.breadcrumb{font-size:11px;color:var(--text2);font-family:'JetBrains Mono',monospace}
.topbar-right{display:flex;align-items:center;gap:10px}
.btn{padding:7px 14px;border-radius:7px;font-size:11px;font-weight:700;cursor:pointer;border:none;transition:all .2s;font-family:'Syne',sans-serif}
.btn-p{background:var(--accent);color:#000}.btn-p:hover{background:#00f0c0}
.btn-g{background:var(--bg3);color:var(--text2);border:1px solid var(--border)}.btn-g:hover{background:var(--bg4);color:var(--text)}
.btn-d{background:rgba(255,71,87,.12);color:var(--red);border:1px solid rgba(255,71,87,.25)}.btn-d:hover{background:rgba(255,71,87,.22)}
.btn-b{background:rgba(0,145,255,.12);color:var(--accent2);border:1px solid rgba(0,145,255,.25)}.btn-b:hover{background:rgba(0,145,255,.22)}
.content{flex:1;overflow-y:auto;padding:22px 24px}

.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:22px}
.scard{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px;position:relative;overflow:hidden;transition:all .2s;animation:up .4s ease both}
.scard:hover{border-color:var(--accent);transform:translateY(-2px)}
.scard::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,var(--accent),var(--accent2));opacity:0;transition:.3s}
.scard:hover::before{opacity:1}
.slabel{font-size:9px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;font-family:'JetBrains Mono',monospace;margin-bottom:8px}
.sval{font-size:30px;font-weight:800;line-height:1;margin-bottom:4px}
.ssub{font-size:10px;color:var(--text2)}
.c-g .sval{color:var(--green)}.c-r .sval{color:var(--red)}.c-o .sval{color:var(--orange)}.c-b .sval{color:var(--accent2)}.c-p .sval{color:var(--purple)}
@keyframes up{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}

.org-cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:18px;margin-bottom:22px}
.org-card{background:var(--bg2);border:1px solid var(--border);border-radius:12px;overflow:hidden;transition:all .2s;animation:up .4s ease both;cursor:pointer}
.org-card:hover{border-color:var(--accent);box-shadow:var(--glow)}
.org-card-header{padding:16px 18px;display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--border)}
.org-color-bar{width:4px;border-radius:4px;height:36px;flex-shrink:0}
.org-name{font-size:14px;font-weight:800}
.org-meta{font-size:10px;color:var(--text2);font-family:'JetBrains Mono',monospace;margin-top:2px}
.org-actions{margin-left:auto;display:flex;gap:6px}
.org-body{padding:14px 18px}
.org-sites{display:flex;flex-direction:column;gap:8px}
.site-row{background:var(--bg3);border-radius:8px;padding:10px 12px}
.site-name{font-size:12px;font-weight:700;margin-bottom:6px;display:flex;align-items:center;gap:6px}
.site-depts{display:flex;flex-wrap:wrap;gap:5px}
.dept-pill{font-size:10px;background:var(--bg4);color:var(--text2);padding:3px 8px;border-radius:5px;display:flex;align-items:center;gap:4px}
.dept-pill .dev-count{color:var(--accent);font-family:'JetBrains Mono',monospace}

.panel{background:var(--bg2);border:1px solid var(--border);border-radius:10px;overflow:hidden;animation:up .5s ease both}
.ph{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.ptitle{font-size:12px;font-weight:700;display:flex;align-items:center;gap:7px}
.pdot{width:7px;height:7px;border-radius:50%;background:var(--accent);box-shadow:0 0 7px var(--accent)}

.dev-table{width:100%;border-collapse:collapse}
.dev-table th{font-size:9px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;font-family:'JetBrains Mono',monospace;padding:10px 16px;text-align:left;border-bottom:1px solid var(--border);background:var(--bg1)}
.dev-table td{padding:11px 16px;border-bottom:1px solid rgba(42,53,71,.4);font-size:12px;vertical-align:middle}
.dev-table tr:last-child td{border-bottom:none}
.dev-table tr:hover td{background:var(--bg3)}
.dev-status{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:6px}
.son{background:var(--green);box-shadow:0 0 6px var(--green);animation:pulse 2s infinite}
.sof{background:var(--text3)}
.dev-name{font-weight:700;color:var(--text)}
.dev-user{font-size:10px;color:var(--text2);font-family:'JetBrains Mono',monospace}
.tag{font-size:9px;padding:2px 7px;border-radius:5px;font-weight:700;letter-spacing:.5px}
.tag-org{background:rgba(0,212,170,.12);color:var(--accent);border:1px solid rgba(0,212,170,.2)}
.tag-site{background:rgba(0,145,255,.12);color:var(--accent2);border:1px solid rgba(0,145,255,.2)}
.tag-dept{background:rgba(167,139,250,.12);color:var(--purple);border:1px solid rgba(167,139,250,.2)}
.tag-none{background:var(--bg4);color:var(--text3);border:1px solid var(--border)}
.mini-bar{width:50px;height:4px;background:var(--bg4);border-radius:3px;overflow:hidden;display:inline-block}
.mf{height:100%;border-radius:3px}.fo{background:var(--green)}.fw{background:var(--orange)}.fd{background:var(--red)}

.titem{display:flex;align-items:flex-start;gap:12px;padding:13px 18px;border-bottom:1px solid rgba(42,53,71,.4);cursor:pointer;transition:background .2s}
.titem:hover{background:var(--bg3)}
.titem:last-child{border-bottom:none}
.tpri{width:3px;border-radius:3px;align-self:stretch;flex-shrink:0}
.pu{background:var(--red)}.pn{background:var(--accent2)}.pl{background:var(--text3)}
.ttitle{font-size:12px;font-weight:600;margin-bottom:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tmeta{display:flex;gap:8px;flex-wrap:wrap}
.tmeta span{font-size:10px;color:var(--text2);font-family:'JetBrains Mono',monospace}
.tbadge{font-size:9px;font-weight:700;padding:2px 7px;border-radius:5px;text-transform:uppercase;letter-spacing:.5px}
.bo{background:rgba(0,145,255,.15);color:var(--accent2);border:1px solid rgba(0,145,255,.3)}
.bc{background:rgba(74,85,104,.2);color:var(--text3);border:1px solid var(--border)}
.bu{background:rgba(255,71,87,.15);color:var(--red);border:1px solid rgba(255,71,87,.3)}

/* Users table */
.user-row{display:flex;align-items:center;gap:12px;padding:12px 18px;border-bottom:1px solid rgba(42,53,71,.4)}
.user-row:last-child{border-bottom:none}
.user-avatar{width:32px;height:32px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-weight:800;font-size:14px;color:#000;flex-shrink:0}
.role-badge{font-size:9px;font-weight:700;padding:2px 8px;border-radius:5px;text-transform:uppercase;letter-spacing:.5px}
.role-admin{background:rgba(0,212,170,.15);color:var(--accent);border:1px solid rgba(0,212,170,.3)}
.role-viewer{background:rgba(0,145,255,.15);color:var(--accent2);border:1px solid rgba(0,145,255,.3)}
.totp-on{font-size:9px;background:rgba(0,212,170,.1);color:var(--accent);padding:2px 7px;border-radius:5px;border:1px solid rgba(0,212,170,.25)}
.totp-off{font-size:9px;background:var(--bg4);color:var(--text3);padding:2px 7px;border-radius:5px;border:1px solid var(--border)}

/* QR modal */
.qr-box{text-align:center;padding:10px 0}
.qr-box canvas{border-radius:8px}
.secret-box{background:var(--bg3);border-radius:7px;padding:12px;font-family:'JetBrains Mono',monospace;font-size:13px;letter-spacing:3px;color:var(--accent);text-align:center;margin:12px 0;word-break:break-all}

.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.72);backdrop-filter:blur(4px);z-index:200;align-items:center;justify-content:center}
.overlay.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--border);border-radius:14px;width:560px;max-width:95vw;max-height:90vh;overflow-y:auto;animation:min .3s cubic-bezier(.34,1.56,.64,1)}
@keyframes min{from{opacity:0;transform:scale(.9)}to{opacity:1;transform:scale(1)}}
.mh{padding:18px 22px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;background:var(--bg2);z-index:1}
.mh-title{font-size:14px;font-weight:800}
.mclose{width:28px;height:28px;border-radius:7px;background:var(--bg3);border:none;color:var(--text2);cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center;transition:all .2s}
.mclose:hover{background:var(--red);color:#fff}
.mb{padding:20px 22px}
.form-row{margin-bottom:14px}
.form-label{font-size:10px;color:var(--text2);letter-spacing:1px;text-transform:uppercase;font-family:'JetBrains Mono',monospace;margin-bottom:5px;display:block}
.form-input,.form-select{width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:9px 12px;color:var(--text);font-size:13px;font-family:'Syne',sans-serif;transition:border-color .2s}
.form-input:focus,.form-select:focus{outline:none;border-color:var(--accent)}
.form-select option{background:var(--bg2)}
.form-actions{display:flex;gap:8px;margin-top:18px}
.igrid{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px}
.iitem{background:var(--bg3);border-radius:7px;padding:10px}
.ilabel{font-size:9px;color:var(--text3);letter-spacing:2px;text-transform:uppercase;font-family:'JetBrains Mono',monospace;margin-bottom:3px}
.ivalue{font-size:12px;font-weight:600;color:var(--text);font-family:'JetBrains Mono',monospace;word-break:break-all}
.rdbox{background:rgba(0,212,170,.06);border:1px solid rgba(0,212,170,.2);border-radius:9px;padding:14px;margin-bottom:16px;display:flex;align-items:center;justify-content:space-between}
.rdid{font-size:20px;font-weight:800;letter-spacing:3px;color:var(--accent);font-family:'JetBrains Mono',monospace}
.note-area{width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:10px;color:var(--text);font-size:12px;font-family:'Syne',sans-serif;resize:vertical;min-height:70px;margin-bottom:14px}
.note-area:focus{outline:none;border-color:var(--accent)}

#toasts{position:fixed;bottom:20px;right:20px;z-index:9000;display:flex;flex-direction:column;gap:7px}
.toast{background:var(--bg2);border:1px solid rgba(0,212,170,.3);border-radius:9px;padding:10px 14px;font-size:12px;color:var(--text);display:flex;align-items:center;gap:9px;min-width:240px;box-shadow:0 8px 24px rgba(0,0,0,.4);animation:tin .3s ease}
@keyframes tin{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:translateX(0)}}

.filter-bar{display:flex;gap:10px;margin-bottom:18px;flex-wrap:wrap;align-items:center}
.search-input{flex:1;min-width:180px;background:var(--bg2);border:1px solid var(--border);border-radius:7px;padding:8px 12px;color:var(--text);font-size:12px;font-family:'Syne',sans-serif}
.search-input:focus{outline:none;border-color:var(--accent)}
.search-input::placeholder{color:var(--text3)}
.tabs{display:flex;gap:4px}
.tab{padding:7px 14px;border-radius:7px;font-size:11px;font-weight:700;cursor:pointer;background:var(--bg2);color:var(--text2);border:1px solid var(--border);transition:all .2s;font-family:'Syne',sans-serif}
.tab.active{background:rgba(0,212,170,.1);color:var(--accent);border-color:rgba(0,212,170,.3)}
.user-chip{display:flex;align-items:center;gap:7px;padding:5px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:20px;font-size:11px;color:var(--text2);cursor:pointer;transition:all .2s}
.user-chip:hover{border-color:var(--accent);color:var(--text)}

::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:var(--bg0)}::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.view{display:none}.view.active{display:block}
.grid2{display:grid;grid-template-columns:1fr 360px;gap:18px}
.empty{padding:50px 20px;text-align:center;color:var(--text3);font-size:12px;font-family:'JetBrains Mono',monospace}
.empty-icon{font-size:36px;margin-bottom:10px;opacity:.25}
.color-swatches{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
.swatch{width:24px;height:24px;border-radius:6px;cursor:pointer;border:2px solid transparent;transition:all .2s}
.swatch.sel{border-color:#fff;transform:scale(1.15)}
.otp-verify-inputs{display:flex;gap:6px;margin:10px 0}
.otp-verify-inputs input{width:38px;height:44px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--accent);font-size:20px;font-weight:700;font-family:'JetBrains Mono',monospace;text-align:center;transition:border-color .2s}
.otp-verify-inputs input:focus{outline:none;border-color:var(--accent)}
</style>
</head>
<body>

<!-- SIDEBAR -->
<nav class="sidebar">
  <div class="logo" style="padding:14px 16px;justify-content:center">
    <img src="data:image/png;base64,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" style="height:38px;width:auto;object-fit:contain" alt="Uptime Service">
  </div>
  <div class="nav">
    <div class="nav-sec">NAVIGAZIONE</div>
    <div class="nav-item active" onclick="showView('overview',this)">⬡ &nbsp;Overview</div>
    <div class="nav-item" onclick="showView('orgs',this)">🏢 &nbsp;Organizzazioni <span class="nav-badge g" id="nb-orgs">0</span></div>
    <div class="nav-item" onclick="showView('devices',this)">◉ &nbsp;Tutti i Device <span class="nav-badge g" id="nb-dev">0</span></div>
    <div class="nav-item" onclick="showView('tickets',this)">◈ &nbsp;Ticket <span class="nav-badge" id="nb-t">0</span></div>
    <div class="nav-item admin-only" onclick="showView('users',this)">👤 &nbsp;Utenti</div>
    <div class="nav-sec">ORGANIZZAZIONI</div>
    <div class="org-tree" id="org-tree"></div>
    <div class="nav-sec">SISTEMA</div>
    <div class="nav-item" onclick="openNewOrg()">+ &nbsp;Nuova Org</div>
    <div class="nav-item" onclick="loadDemo()">◎ &nbsp;Carica Demo</div>
    <div class="nav-item" onclick="refreshAll()">↺ &nbsp;Aggiorna</div>
  </div>
  <div class="sb-foot"><span class="dot"></span>LIVE <span id="clk" style="float:right">--:--</span></div>
</nav>

<!-- MAIN -->
<div class="main">
  <div class="topbar">
    <div class="topbar-left">
      <div class="topbar-title">Uptime <span>Dashboard</span></div>
      <div class="breadcrumb" id="breadcrumb"></div>
    </div>
    <div class="topbar-right">
      <div class="user-chip" id="user-chip" onclick="openMyProfile()">
        <span id="user-avatar" style="width:20px;height:20px;border-radius:5px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:800;color:#000">?</span>
        <span id="user-name">—</span>
        <span id="user-role-badge"></span>
      </div>
      <button class="btn btn-g" onclick="doLogout()" style="font-size:10px;padding:6px 10px">↩ Esci</button>
      <button class="btn btn-p" onclick="refreshAll()">↺ Refresh</button>
    </div>
  </div>

  <div class="content">

    <!-- OVERVIEW -->
    <div id="view-overview" class="view active">
      <div class="stats" id="stats-grid">
        <div class="scard c-p"><div class="slabel">Organizzazioni</div><div class="sval" id="s-orgs">—</div><div class="ssub">gestite</div></div>
        <div class="scard c-b"><div class="slabel">Device Totali</div><div class="sval" id="s-total">—</div><div class="ssub">monitorati</div></div>
        <div class="scard c-g"><div class="slabel">Online</div><div class="sval" id="s-online">—</div><div class="ssub">connessi ora</div></div>
        <div class="scard c-r"><div class="slabel">Offline</div><div class="sval" id="s-offline">—</div><div class="ssub">non raggiungibili</div></div>
        <div class="scard c-o"><div class="slabel">Ticket Aperti</div><div class="sval" id="s-open">—</div><div class="ssub">da gestire</div></div>
        <div class="scard c-r"><div class="slabel">Urgenti</div><div class="sval" id="s-urgent">—</div><div class="ssub">priorità alta</div></div>
      </div>
      <div class="grid2">
        <div class="panel">
          <div class="ph"><div class="ptitle"><span class="pdot"></span>Ultimi Ticket</div><button class="btn btn-g" style="font-size:10px;padding:5px 10px" onclick="showView('tickets',null)">Vedi tutti →</button></div>
          <div id="ov-tickets"></div>
        </div>
        <div class="panel">
          <div class="ph"><div class="ptitle"><span class="pdot"></span>Device recenti</div><button class="btn btn-g" style="font-size:10px;padding:5px 10px" onclick="showView('devices',null)">Vedi tutti →</button></div>
          <div id="ov-devices"></div>
        </div>
      </div>
    </div>

    <!-- ORGANIZZAZIONI -->
    <div id="view-orgs" class="view">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px">
        <div style="font-size:14px;font-weight:700">🏢 Organizzazioni</div>
        <button class="btn btn-p" onclick="openNewOrg()">+ Nuova Organizzazione</button>
      </div>
      <div class="org-cards" id="org-cards"></div>
    </div>

    <!-- ORG DETAIL -->
    <div id="view-org-detail" class="view">
      <div id="org-detail-content"></div>
    </div>

    <!-- DEVICES -->
    <div id="view-devices" class="view">
      <div class="filter-bar">
        <input class="search-input" id="dev-search" placeholder="Cerca device..." oninput="renderDevices()">
        <div class="tabs">
          <div class="tab active" onclick="setDevFilter('all',this)">Tutti</div>
          <div class="tab" onclick="setDevFilter('online',this)">Online</div>
          <div class="tab" onclick="setDevFilter('offline',this)">Offline</div>
        </div>
        <button class="btn btn-b" onclick="openAssignModal()">⬡ Assegna Device</button>
      </div>
      <div class="panel">
        <table class="dev-table">
          <thead><tr>
            <th>Device</th><th>Organizzazione</th><th>Sede</th><th>Reparto</th><th>Risorse</th><th>RustDesk</th>
          </tr></thead>
          <tbody id="dev-tbody"></tbody>
        </table>
      </div>
    </div>

    <!-- TICKETS -->
    <div id="view-tickets" class="view">
      <div class="filter-bar">
        <input class="search-input" id="t-search" placeholder="Cerca ticket..." oninput="renderTickets()">
        <div class="tabs">
          <div class="tab active" onclick="setTFilter('all',this)">Tutti</div>
          <div class="tab" onclick="setTFilter('open',this)">Aperti</div>
          <div class="tab" onclick="setTFilter('closed',this)">Chiusi</div>
        </div>
      </div>
      <div class="panel"><div id="t-list"></div></div>
    </div>

    <!-- USERS (admin only) -->
    <div id="view-users" class="view">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px">
        <div style="font-size:14px;font-weight:700">👤 Gestione Utenti</div>
        <button class="btn btn-p" onclick="openNewUser()">+ Nuovo Utente</button>
      </div>
      <div class="panel">
        <div class="ph"><div class="ptitle"><span class="pdot"></span>Utenti registrati</div></div>
        <div id="users-list"></div>
      </div>
    </div>


    <!-- DOCUMENTAZIONE ORG -->
    <div id="view-org-docs" class="view">
      <div id="doc-org-title"></div>
      <div id="doc-content"></div>
    </div>

  </div>
</div>

<!-- MODALS -->
<div class="overlay" id="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="mh"><div class="mh-title" id="modal-title">—</div><button class="mclose" onclick="closeModal()">✕</button></div>
    <div class="mb" id="modal-body"></div>
  </div>
</div>

<div id="toasts"></div>

<!-- QRCode lib -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>

<script>
const H = {"Content-Type":"application/json"};
let allOrgs=[], allSites=[], allDepts=[], allMachines=[], allTickets=[], allUsers=[];
let devFilter='all', tFilter='all';
let selColor='#00d4aa';
let currentUser = null;

async function api(path,opts={}){
  const r=await fetch(path,{headers:H,...opts});
  if(r.status===401){window.location='/login';throw new Error('401')}
  if(!r.ok) throw new Error(r.status);
  return r.json();
}

// ── AUTH ──────────────────────────────────────────────────────
async function initAuth(){
  try{
    const d=await api('/api/auth/me');
    if(!d.ok){window.location='/login';return}
    currentUser=d.user;
    document.getElementById('user-name').textContent=d.user.username;
    document.getElementById('user-avatar').textContent=d.user.username[0].toUpperCase();
    const rb=document.getElementById('user-role-badge');
    rb.className='role-badge '+(d.user.role==='admin'?'role-admin':'role-viewer');
    rb.textContent=d.user.role;
    // mostra/nascondi elementi admin
    document.querySelectorAll('.admin-only').forEach(el=>{
      el.style.display=d.user.role==='admin'?'flex':'none';
    });
  }catch(e){window.location='/login'}
}

async function doLogout(){
  await fetch('/api/auth/logout',{method:'POST',headers:H});
  window.location='/login';
}

// ── PROFILE MODAL ─────────────────────────────────────────────
async function openMyProfile(){
  if(!currentUser) return;
  const d = await api('/api/auth/2fa/setup');
  showModal(`Il mio profilo — ${currentUser.username}`, `
    <div style="display:flex;align-items:center;gap:14px;margin-bottom:20px">
      <div style="width:48px;height:48px;border-radius:12px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:800;color:#000">${currentUser.username[0].toUpperCase()}</div>
      <div>
        <div style="font-size:16px;font-weight:800">${currentUser.username}</div>
        <span class="role-badge ${currentUser.role==='admin'?'role-admin':'role-viewer'}">${currentUser.role}</span>
      </div>
    </div>
    <div style="background:var(--bg3);border-radius:9px;padding:16px;margin-bottom:16px">
      <div style="font-size:11px;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:7px">
        🔐 Autenticazione a due fattori
        <span class="${currentUser.totp_enabled?'totp-on':'totp-off'}">${currentUser.totp_enabled?'ATTIVO':'NON ATTIVO'}</span>
      </div>
      ${!currentUser.totp_enabled ? `
        <p style="font-size:11px;color:var(--text2);margin-bottom:14px">Scansiona il QR con Google Authenticator o Authy, poi inserisci il codice per attivare.</p>
        <div class="qr-box"><div id="qr-canvas"></div></div>
        <div class="secret-box">${d.secret}</div>
        <div style="font-size:10px;color:var(--text3);text-align:center;margin-bottom:14px;font-family:monospace">Oppure inserisci il codice manualmente nell'app</div>
        <div style="font-size:10px;color:var(--text2);margin-bottom:6px">Codice di verifica</div>
        <div class="otp-verify-inputs" id="en-otp">
          ${[0,1,2,3,4,5].map(i=>`<input type="text" maxlength="1" id="eo${i}" oninput="eotpNext(${i})" onkeydown="eotpBack(event,${i})">`).join('')}
        </div>
        <button class="btn btn-p" style="margin-top:8px" onclick="enable2fa()">Attiva 2FA</button>
      ` : `
        <p style="font-size:11px;color:var(--text2);margin-bottom:14px">Il 2FA è attivo. Ad ogni login verrà richiesto il codice dall'app.</p>
        <button class="btn btn-d" onclick="disable2faMe()">Disattiva 2FA</button>
      `}
    </div>
    <div style="background:var(--bg3);border-radius:9px;padding:16px">
      <div style="font-size:11px;font-weight:700;margin-bottom:12px">🔑 Cambia Password</div>
      <div class="form-row"><label class="form-label">Nuova password</label><input class="form-input" id="new-pwd" type="password" placeholder="min. 6 caratteri"></div>
      <button class="btn btn-g" onclick="changeMyPassword()">Aggiorna Password</button>
    </div>
  `);
  // Genera QR
  if(!currentUser.totp_enabled){
    setTimeout(()=>{
      try{new QRCode(document.getElementById('qr-canvas'),{text:d.uri,width:180,height:180,colorDark:'#00d4aa',colorLight:'#161b22'})}catch(e){}
    },100);
  }
}

function eotpNext(i){const v=document.getElementById('eo'+i).value;if(v&&i<5)document.getElementById('eo'+(i+1)).focus()}
function eotpBack(e,i){if(e.key==='Backspace'&&!document.getElementById('eo'+i).value&&i>0)document.getElementById('eo'+(i-1)).focus()}

async function enable2fa(){
  const code=[0,1,2,3,4,5].map(i=>document.getElementById('eo'+i).value).join('');
  if(code.length<6){toast('Inserisci il codice completo','err');return}
  const r=await api('/api/auth/2fa/enable',{method:'POST',body:JSON.stringify({uid:currentUser.id,code})});
  if(r.ok){toast('2FA attivato!');currentUser.totp_enabled=true;closeModal();openMyProfile()}
  else toast(r.error||'Codice non valido','err');
}

async function disable2faMe(){
  if(!confirm('Disattivare il 2FA?')) return;
  await api('/api/auth/2fa/disable',{method:'POST',body:JSON.stringify({uid:currentUser.id})});
  toast('2FA disattivato');currentUser.totp_enabled=false;closeModal();openMyProfile();
}

async function changeMyPassword(){
  const p=document.getElementById('new-pwd').value;
  if(p.length<6){toast('Password troppo corta','err');return}
  await api(`/api/users/${currentUser.id}`,{method:'PATCH',body:JSON.stringify({password:p})});
  toast('Password aggiornata!');closeModal();
}

// ── LOAD ─────────────────────────────────────────────────────
async function refreshAll(){
  try{
    await Promise.all([loadStats(),loadOrgs(),loadSites(),loadDepts(),loadMachines(),loadTickets()]);
    if(currentUser?.role==='admin') await loadUsers();
    renderTree(); renderOrgCards(); renderDevices(); renderTickets(); renderOverview(); renderUsers();
    document.getElementById('clk').textContent=new Date().toLocaleTimeString('it-IT',{hour:'2-digit',minute:'2-digit'});
  }catch(e){}
}

async function loadStats(){
  const s=await api('/api/stats');
  document.getElementById('s-orgs').textContent=s.total_orgs||allOrgs.length;
  document.getElementById('s-total').textContent=s.total_machines;
  document.getElementById('s-online').textContent=s.online_machines;
  document.getElementById('s-offline').textContent=s.offline_machines;
  document.getElementById('s-open').textContent=s.open_tickets;
  document.getElementById('s-urgent').textContent=s.urgent_tickets;
  document.getElementById('nb-t').textContent=s.open_tickets;
  document.getElementById('nb-dev').textContent=s.total_machines;
}
async function loadOrgs(){allOrgs=await api('/api/orgs');document.getElementById('nb-orgs').textContent=allOrgs.length}
async function loadSites(){allSites=await api('/api/sites')}
async function loadDepts(){allDepts=await api('/api/depts')}
async function loadMachines(){allMachines=await api('/api/machines')}
async function loadTickets(){allTickets=await api('/api/tickets')}
async function loadUsers(){try{allUsers=await api('/api/users')}catch(e){allUsers=[]}}

// ── USERS VIEW ────────────────────────────────────────────────
function renderUsers(){
  const el=document.getElementById('users-list');
  if(!el)return;
  if(!allUsers.length){el.innerHTML=`<div class="empty"><div class="empty-icon">👤</div>Nessun utente</div>`;return}
  el.innerHTML=allUsers.map(u=>`
    <div class="user-row">
      <div class="user-avatar">${u.username[0].toUpperCase()}</div>
      <div style="flex:1">
        <div style="font-size:13px;font-weight:700">${u.username}</div>
        <div style="font-size:10px;color:var(--text2);font-family:monospace">${u.created_at?.slice(0,10)||'—'}</div>
      </div>
      <span class="role-badge ${u.role==='admin'?'role-admin':'role-viewer'}">${u.role}</span>
      <span class="${u.totp_enabled?'totp-on':'totp-off'}">${u.totp_enabled?'🔐 2FA':'2FA off'}</span>
      ${u.id!==currentUser?.id?`
        <button class="btn btn-b" style="font-size:10px;padding:5px 9px" onclick="openEditUser('${u.id}')">✏</button>
        ${!u.totp_enabled?`<button class="btn btn-g" style="font-size:10px;padding:5px 9px" onclick="setup2faForUser('${u.id}','${u.username}')">🔐 Setup 2FA</button>`:`<button class="btn btn-d" style="font-size:10px;padding:5px 9px" onclick="disable2faAdmin('${u.id}')">Disattiva 2FA</button>`}
        <button class="btn btn-d" style="font-size:10px;padding:5px 9px" onclick="deleteUser('${u.id}')">✕</button>
      `:`<span style="font-size:10px;color:var(--text3);font-family:monospace">(tu)</span>`}
    </div>`).join('');
}

function openNewUser(){
  showModal('Nuovo Utente',`
    <div class="form-row"><label class="form-label">Username</label><input class="form-input" id="f-uname" placeholder="mario.rossi"></div>
    <div class="form-row"><label class="form-label">Password</label><input class="form-input" id="f-upwd" type="password" placeholder="min. 6 caratteri"></div>
    <div class="form-row"><label class="form-label">Ruolo</label>
      <select class="form-select" id="f-urole">
        <option value="viewer">Viewer — solo lettura</option>
        <option value="admin">Admin — accesso completo</option>
      </select>
    </div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="saveNewUser()">Crea Utente</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}
async function saveNewUser(){
  const username=document.getElementById('f-uname').value.trim();
  const password=document.getElementById('f-upwd').value;
  const role=document.getElementById('f-urole').value;
  if(!username||!password){toast('Compila tutti i campi','err');return}
  if(password.length<6){toast('Password troppo corta','err');return}
  const r=await api('/api/users',{method:'POST',body:JSON.stringify({username,password,role})});
  if(r.error){toast(r.error,'err');return}
  closeModal(); toast('Utente creato!'); await loadUsers(); renderUsers();
}

function openEditUser(uid){
  const u=allUsers.find(x=>x.id===uid);if(!u)return;
  showModal(`Modifica — ${u.username}`,`
    <div class="form-row"><label class="form-label">Ruolo</label>
      <select class="form-select" id="f-erole">
        <option value="viewer"${u.role==='viewer'?' selected':''}>Viewer</option>
        <option value="admin"${u.role==='admin'?' selected':''}>Admin</option>
      </select>
    </div>
    <div class="form-row"><label class="form-label">Nuova password (opzionale)</label><input class="form-input" id="f-epwd" type="password" placeholder="lascia vuoto per non cambiare"></div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="saveEditUser('${uid}')">Salva</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}
async function saveEditUser(uid){
  const role=document.getElementById('f-erole').value;
  const pwd=document.getElementById('f-epwd').value;
  const body={role};if(pwd)body.password=pwd;
  await api(`/api/users/${uid}`,{method:'PATCH',body:JSON.stringify(body)});
  closeModal(); toast('Utente aggiornato'); await loadUsers(); renderUsers();
}
async function deleteUser(uid){
  if(!confirm('Eliminare questo utente?'))return;
  const r=await api(`/api/users/${uid}`,{method:'DELETE'});
  if(r.error){toast(r.error,'err');return}
  toast('Utente eliminato'); await loadUsers(); renderUsers();
}

async function setup2faForUser(uid, username){
  const d=await api('/api/auth/2fa/setup');  // ottieni secret per questo utente (admin può vedere)
  // per altri utenti mostra istruzioni
  showModal(`Setup 2FA — ${username}`,`
    <p style="font-size:12px;color:var(--text2);margin-bottom:16px">L'utente deve scansionare questo QR con Google Authenticator / Authy, poi inserire il codice per attivare.</p>
    <div class="qr-box"><div id="qr-admin-canvas"></div></div>
    <div class="secret-box" id="admin-secret-display" style="cursor:pointer" onclick="navigator.clipboard.writeText(this.textContent);toast('Copiato!')">caricamento...</div>
    <div style="font-size:11px;color:var(--text2);margin-bottom:10px">Codice di verifica dall'app</div>
    <div class="otp-verify-inputs">
      ${[0,1,2,3,4,5].map(i=>`<input type="text" maxlength="1" id="ao${i}" oninput="aotpNext(${i})" onkeydown="aotpBack(event,${i})">`).join('')}
    </div>
    <div class="form-actions" style="margin-top:12px">
      <button class="btn btn-p" onclick="enable2faAdmin('${uid}')">Attiva 2FA</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
  // carica secret specifico per utente (usa admin API)
  try{
    const r=await fetch(`/api/auth/2fa/setup?uid=${uid}`,{headers:H});
    const ud=await r.json();
    document.getElementById('admin-secret-display').textContent=ud.secret;
    new QRCode(document.getElementById('qr-admin-canvas'),{text:ud.uri,width:180,height:180,colorDark:'#00d4aa',colorLight:'#161b22'});
  }catch(e){document.getElementById('admin-secret-display').textContent=d.secret}
}
function aotpNext(i){const v=document.getElementById('ao'+i).value;if(v&&i<5)document.getElementById('ao'+(i+1)).focus()}
function aotpBack(e,i){if(e.key==='Backspace'&&!document.getElementById('ao'+i).value&&i>0)document.getElementById('ao'+(i-1)).focus()}
async function enable2faAdmin(uid){
  const code=[0,1,2,3,4,5].map(i=>document.getElementById('ao'+i).value).join('');
  if(code.length<6){toast('Inserisci il codice','err');return}
  const r=await api('/api/auth/2fa/enable',{method:'POST',body:JSON.stringify({uid,code})});
  if(r.ok){toast('2FA attivato!');closeModal();await loadUsers();renderUsers()}
  else toast(r.error||'Codice non valido','err');
}
async function disable2faAdmin(uid){
  if(!confirm('Disattivare il 2FA per questo utente?'))return;
  await api('/api/auth/2fa/disable',{method:'POST',body:JSON.stringify({uid})});
  toast('2FA disattivato');await loadUsers();renderUsers();
}

// ── ORG TREE ─────────────────────────────────────────────────
function renderTree(){
  const el=document.getElementById('org-tree');
  if(!allOrgs.length){el.innerHTML='<div style="font-size:10px;color:var(--text3);padding:4px 8px;font-family:monospace">Nessuna org</div>';return}
  el.innerHTML=allOrgs.map(o=>{
    const oSites=allSites.filter(s=>s.oid===o.id);
    return`<div class="tree-org">
      <div class="tree-org-header" onclick="toggleTreeOrg('to${o.id}',this);showOrgDetail('${o.id}')">
        <div class="tree-org-dot" style="background:${o.color}"></div>
        <span>${o.name}</span>
        ${oSites.length?`<span class="tree-chevron" id="chev${o.id}">▶</span>`:''}
      </div>
      <div class="tree-children" id="to${o.id}">
        ${oSites.map(s=>{
          const sDepts=allDepts.filter(d=>d.sid===s.id);
          return`<div class="tree-site">
            <div class="tree-site-header" onclick="event.stopPropagation();toggleTreeSite('ts${s.id}');showOrgDetail('${o.id}','${s.id}')">
              📍 ${s.name}
              ${sDepts.length?`<span class="tree-chevron">▶</span>`:''}
            </div>
            <div class="tree-children" id="ts${s.id}">
              ${sDepts.map(d=>{
                const cnt=allMachines.filter(m=>m.did===d.id).length;
                return`<div class="tree-dept" onclick="event.stopPropagation();showOrgDetail('${o.id}','${s.id}','${d.id}')">
                  ⬡ ${d.name}<span class="tree-count">${cnt}</span>
                </div>`}).join('')}
            </div>
          </div>`}).join('')}
      </div>
    </div>`}).join('');
}
function toggleTreeOrg(id){const c=document.getElementById(id);if(c)c.classList.toggle('open')}
function toggleTreeSite(id){const c=document.getElementById(id);if(c)c.classList.toggle('open')}

// ── ORG CARDS ─────────────────────────────────────────────────
function renderOrgCards(){
  const el=document.getElementById('org-cards');
  if(!allOrgs.length){el.innerHTML=`<div class="empty"><div class="empty-icon">🏢</div>Nessuna organizzazione.<br>Crea la prima cliccando "+ Nuova Organizzazione"</div>`;return}
  el.innerHTML=allOrgs.map((o,i)=>{
    const oSites=allSites.filter(s=>s.oid===o.id);
    const devCount=allMachines.filter(m=>m.oid===o.id).length;
    const onlineCount=allMachines.filter(m=>m.oid===o.id&&m.status==='online').length;
    return`<div class="org-card" style="animation-delay:${i*.07}s" onclick="showOrgDetail('${o.id}')">
      <div class="org-card-header">
        <div class="org-color-bar" style="background:${o.color}"></div>
        <div>
          <div class="org-name">${o.name}</div>
          <div class="org-meta">${devCount} device · ${onlineCount} online · ${oSites.length} sedi</div>
        </div>
        <div class="org-actions" onclick="event.stopPropagation()">
          <button class="btn btn-p" style="padding:5px 9px;font-size:10px" onclick="event.stopPropagation();showDocumentation('${o.id}')">&#128196;</button>
          <button class="btn btn-b" style="padding:5px 9px;font-size:10px" onclick="openNewSite('${o.id}')">+ Sede</button>
          <button class="btn btn-g" style="padding:5px 9px;font-size:10px" onclick="openEditOrg('${o.id}')">✏</button>
          <button class="btn btn-d" style="padding:5px 9px;font-size:10px" onclick="deleteOrg('${o.id}')">✕</button>
        </div>
      </div>
      <div class="org-body">
        ${oSites.length?`<div class="org-sites">${oSites.map(s=>{
          const sDepts=allDepts.filter(d=>d.sid===s.id);
          const sDevs=allMachines.filter(m=>m.sid===s.id).length;
          return`<div class="site-row">
            <div class="site-name">📍 ${s.name} <span style="font-size:10px;color:var(--text2);font-weight:400;font-family:monospace">${sDevs} device</span>
              <div style="margin-left:auto;display:flex;gap:5px">
                <button class="btn btn-b" style="padding:3px 7px;font-size:9px" onclick="event.stopPropagation();openNewDept('${s.id}','${o.id}')">+ Reparto</button>
                <button class="btn btn-g" style="padding:3px 7px;font-size:9px" onclick="event.stopPropagation();openEditSite('${s.id}')">✏</button>
                <button class="btn btn-d" style="padding:3px 7px;font-size:9px" onclick="event.stopPropagation();deleteSite('${s.id}')">✕</button>
              </div>
            </div>
            <div class="site-depts">
              ${sDepts.length?sDepts.map(d=>{
                const dDevs=allMachines.filter(m=>m.did===d.id).length;
                return`<div class="dept-pill">⬡ ${d.name} <span class="dev-count">${dDevs}</span>
                  <span onclick="event.stopPropagation();deleteDept('${d.id}')" style="cursor:pointer;color:var(--red);margin-left:3px">×</span>
                </div>`}).join(''):`<span style="font-size:10px;color:var(--text3)">Nessun reparto</span>`}
            </div>
          </div>`}).join('')}</div>`:`<div style="font-size:11px;color:var(--text3);padding:8px 0">Nessuna sede configurata</div>`}
      </div>
    </div>`}).join('');
}

// ── ORG DETAIL ────────────────────────────────────────────────
function showOrgDetail(oid, sid=null, did=null){
  const org=allOrgs.find(o=>o.id===oid);if(!org)return;
  const oSites=allSites.filter(s=>s.oid===oid);
  let filteredMachines=allMachines.filter(m=>m.oid===oid);
  let bc2=`<span style="color:var(--accent)">${org.name}</span>`;
  if(sid){filteredMachines=filteredMachines.filter(m=>m.sid===sid);const s=allSites.find(x=>x.id===sid);if(s)bc2+=` / ${s.name}`}
  if(did){filteredMachines=filteredMachines.filter(m=>m.did===did);const d=allDepts.find(x=>x.id===did);if(d)bc2+=` / ${d.name}`}
  document.getElementById('breadcrumb').innerHTML='&nbsp;/&nbsp;'+bc2;
  document.getElementById('org-detail-content').innerHTML=`
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
      <div style="width:12px;height:12px;border-radius:50%;background:${org.color}"></div>
      <div style="font-size:16px;font-weight:800">${org.name}</div>
      <div style="margin-left:auto;display:flex;gap:8px">
        <button class="btn btn-p" onclick="showDocumentation('${oid}')">&#128196; Documentazione</button>
        <button class="btn btn-b" onclick="openNewSite('${oid}')">+ Sede</button>
        <button class="btn btn-g" onclick="openEditOrg('${oid}')">✏ Modifica</button>
      </div>
    </div>
    ${!sid?`<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:20px">
      ${oSites.map(s=>`<div style="background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:10px 14px;cursor:pointer;transition:all .2s" onclick="showOrgDetail('${oid}','${s.id}')" onmouseover="this.style.borderColor='var(--accent2)'" onmouseout="this.style.borderColor='var(--border)'">
        <div style="font-size:12px;font-weight:700">📍 ${s.name}</div>
        <div style="font-size:10px;color:var(--text2);font-family:monospace;margin-top:2px">${s.address||'—'}</div>
        <div style="font-size:10px;color:var(--text3);margin-top:4px">${allMachines.filter(m=>m.sid===s.id).length} device</div>
      </div>`).join('')}
    </div>`:''}
    <div class="panel">
      <div class="ph"><div class="ptitle"><span class="pdot"></span>Device (${filteredMachines.length})</div>
        <button class="btn btn-b" onclick="openAssignModal('${oid}')">+ Assegna Device</button>
      </div>
      <table class="dev-table"><thead><tr>
        <th>Device</th><th>Sede</th><th>Reparto</th><th>Risorse</th><th>RustDesk</th><th></th>
      </tr></thead><tbody>
      ${filteredMachines.length?filteredMachines.map(m=>devRow(m,true)).join(''):`<tr><td colspan="6"><div class="empty"><div class="empty-icon">◉</div>Nessun device assegnato</div></td></tr>`}
      </tbody></table>
    </div>`;
  showView('org-detail',null);
}

// ── DEVICES ───────────────────────────────────────────────────
function bc(v){return v>=85?'fd':v>=60?'fw':'fo'}
function devRow(m, inOrg=false){
  const org=allOrgs.find(o=>o.id===m.oid);
  const site=allSites.find(s=>s.id===m.sid);
  const dept=allDepts.find(d=>d.id===m.did);
  return`<tr>
    <td><span class="dev-status ${m.status==='online'?'son':'sof'}"></span>
      <span class="dev-name">${m.pc_name}</span><br>
      <span class="dev-user">${m.user} · ${m.ip}</span>
    </td>
    ${!inOrg?`<td>${org?`<span class="tag tag-org" style="background:${org.color}22;color:${org.color};border-color:${org.color}44">${org.name}</span>`:`<span class="tag tag-none">—</span>`}</td>`:''}
    <td>${site?`<span class="tag tag-site">${site.name}</span>`:`<span class="tag tag-none">—</span>`}</td>
    <td>${dept?`<span class="tag tag-dept">${dept.name}</span>`:`<span class="tag tag-none">—</span>`}</td>
    <td>
      <div style="display:flex;flex-direction:column;gap:3px">
        <div style="display:flex;align-items:center;gap:5px"><span style="font-size:9px;color:var(--text3);width:28px;font-family:monospace">CPU</span><div class="mini-bar"><div class="mf ${bc(m.cpu)}" style="width:${m.cpu}%"></div></div><span style="font-size:9px;color:var(--text2);font-family:monospace">${m.cpu}%</span></div>
        <div style="display:flex;align-items:center;gap:5px"><span style="font-size:9px;color:var(--text3);width:28px;font-family:monospace">RAM</span><div class="mini-bar"><div class="mf ${bc(m.ram)}" style="width:${m.ram}%"></div></div><span style="font-size:9px;color:var(--text2);font-family:monospace">${m.ram}%</span></div>
        <div style="display:flex;align-items:center;gap:5px"><span style="font-size:9px;color:var(--text3);width:28px;font-family:monospace">DSK</span><div class="mini-bar"><div class="mf ${bc(m.disk)}" style="width:${m.disk}%"></div></div><span style="font-size:9px;color:var(--text2);font-family:monospace">${m.disk}%</span></div>
      </div>
    </td>
    <td>${m.rustdesk_id?`<button class="btn btn-p" style="font-size:10px;padding:4px 9px" onclick="connectRD('${m.rustdesk_id}')">⬡ ${m.rustdesk_id}</button>`:`<span style="font-size:10px;color:var(--text3)">N/D</span>`}</td>
    ${inOrg?`<td><button class="btn btn-g" style="font-size:10px;padding:4px 9px" onclick="openAssignDevice('${m.id}')">✏ Sposta</button></td>`:''}
  </tr>`;
}
function renderDevices(){
  const q=document.getElementById('dev-search').value.toLowerCase();
  const list=allMachines.filter(m=>{
    if(devFilter==='online'&&m.status!=='online')return false;
    if(devFilter==='offline'&&m.status!=='offline')return false;
    return !q||`${m.pc_name} ${m.user} ${m.ip}`.toLowerCase().includes(q);
  });
  document.getElementById('dev-tbody').innerHTML=list.length?list.map(m=>devRow(m)).join(''):`<tr><td colspan="6"><div class="empty"><div class="empty-icon">◉</div>Nessun device trovato</div></td></tr>`;
}
function setDevFilter(f,el){devFilter=f;document.querySelectorAll('#view-devices .tab').forEach(t=>t.classList.remove('active'));el.classList.add('active');renderDevices()}

// ── TICKETS ───────────────────────────────────────────────────
function timeAgo(iso){const d=Date.now()-new Date(iso);const m=Math.floor(d/60000);if(m<1)return'Adesso';if(m<60)return`${m}m fa`;const h=Math.floor(m/60);if(h<24)return`${h}h fa`;return`${Math.floor(h/24)}g fa`}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function ticketHTML(t){
  const pc=t.priority==='urgent'&&t.status==='open'?'pu':t.priority==='low'?'pl':'pn';
  const badge=t.priority==='urgent'&&t.status==='open'?`<span class="tbadge bu">URGENTE</span>`:t.status==='open'?`<span class="tbadge bo">APERTO</span>`:`<span class="tbadge bc">CHIUSO</span>`;
  return`<div class="titem" onclick="openTicket(${t.id})">
    <div class="tpri ${pc}"></div>
    <div style="flex:1;min-width:0">
      <div class="ttitle">${esc(t.description)}</div>
      <div class="tmeta"><span>🖥 ${t.pc_name}</span><span>👤 ${t.user}</span>${t.rustdesk_id?`<span style="color:var(--accent)">⬡ ${t.rustdesk_id}</span>`:''}<span>📡 ${t.ip}</span></div>
    </div>
    <div style="display:flex;flex-direction:column;align-items:flex-end;gap:5px">${badge}<span style="font-size:10px;color:var(--text3);font-family:monospace">${timeAgo(t.created_at)}</span></div>
  </div>`;
}
function renderTickets(){
  const q=document.getElementById('t-search').value.toLowerCase();
  const list=allTickets.filter(t=>{
    if(tFilter==='open'&&t.status!=='open')return false;
    if(tFilter==='closed'&&t.status!=='closed')return false;
    return !q||`${t.pc_name} ${t.user} ${t.description}`.toLowerCase().includes(q);
  });
  document.getElementById('t-list').innerHTML=list.length?list.map(ticketHTML).join(''):`<div class="empty"><div class="empty-icon">◈</div>Nessun ticket trovato</div>`;
}
function setTFilter(f,el){tFilter=f;document.querySelectorAll('#view-tickets .tab').forEach(t=>t.classList.remove('active'));el.classList.add('active');renderTickets()}
function renderOverview(){
  document.getElementById('ov-tickets').innerHTML=allTickets.slice(0,6).map(ticketHTML).join('')||`<div class="empty"><div class="empty-icon">◈</div>Nessun ticket</div>`;
  document.getElementById('ov-devices').innerHTML=allMachines.slice(0,6).map(m=>`
    <div style="display:flex;align-items:center;gap:10px;padding:10px 16px;border-bottom:1px solid rgba(42,53,71,.4);cursor:pointer;transition:background .2s" onclick="showView('devices',null)" onmouseover="this.style.background='var(--bg3)'" onmouseout="this.style.background=''">
      <div class="dev-status ${m.status==='online'?'son':'sof'}"></div>
      <div style="flex:1"><div class="dev-name" style="font-size:12px">${m.pc_name}</div><div class="dev-user">${m.user}</div></div>
      <div style="display:flex;gap:4px">${['cpu','ram','disk'].map(k=>`<div class="mini-bar"><div class="mf ${bc(m[k])}" style="width:${m[k]}%"></div></div>`).join('')}</div>
    </div>`).join('')||`<div class="empty"><div class="empty-icon">◉</div>Nessun device</div>`;
}

// ── MODALS ────────────────────────────────────────────────────
function showModal(title,body){document.getElementById('modal-title').textContent=title;document.getElementById('modal-body').innerHTML=body;document.getElementById('modal').classList.add('open')}
function closeModal(){document.getElementById('modal').classList.remove('open')}

const COLORS=['#00d4aa','#0091ff','#ffa502','#ff4757','#a78bfa','#ffd32a','#2ed573','#ff6b81','#eccc68','#1e90ff'];
function colorSwatches(sel){return`<div class="color-swatches">${COLORS.map(c=>`<div class="swatch${c===sel?' sel':''}" style="background:${c}" onclick="selColor='${c}';document.querySelectorAll('.swatch').forEach(s=>s.classList.remove('sel'));this.classList.add('sel')"></div>`).join('')}</div>`}

function openNewOrg(){selColor='#00d4aa';showModal('Nuova Organizzazione',`<div class="form-row"><label class="form-label">Nome</label><input class="form-input" id="f-org-name" placeholder="Es. Emotion Design Srl"></div><div class="form-row"><label class="form-label">Colore</label>${colorSwatches('#00d4aa')}</div><div class="form-actions"><button class="btn btn-p" onclick="saveOrg()">Crea</button><button class="btn btn-g" onclick="closeModal()">Annulla</button></div>`)}
async function saveOrg(){const name=document.getElementById('f-org-name').value.trim();if(!name){toast('Inserisci il nome','err');return}await api('/api/orgs',{method:'POST',body:JSON.stringify({name,color:selColor})});closeModal();toast('Organizzazione creata!');refreshAll()}
function openEditOrg(oid){const o=allOrgs.find(x=>x.id===oid);if(!o)return;selColor=o.color;showModal(`Modifica — ${o.name}`,`<div class="form-row"><label class="form-label">Nome</label><input class="form-input" id="f-org-name" value="${o.name}"></div><div class="form-row"><label class="form-label">Colore</label>${colorSwatches(o.color)}</div><div class="form-actions"><button class="btn btn-p" onclick="updateOrg('${oid}')">Salva</button><button class="btn btn-g" onclick="closeModal()">Annulla</button></div>`)}
async function updateOrg(oid){const name=document.getElementById('f-org-name').value.trim();await api(`/api/orgs/${oid}`,{method:'PATCH',body:JSON.stringify({name,color:selColor})});closeModal();toast('Salvato!');refreshAll()}
async function deleteOrg(oid){if(!confirm('Eliminare questa organizzazione?'))return;await api(`/api/orgs/${oid}`,{method:'DELETE'});toast('Organizzazione eliminata');refreshAll()}

function openNewSite(oid){showModal('Nuova Sede',`<div class="form-row"><label class="form-label">Nome sede</label><input class="form-input" id="f-site-name" placeholder="Es. Sede Milano"></div><div class="form-row"><label class="form-label">Indirizzo</label><input class="form-input" id="f-site-addr" placeholder="Via Roma 1, Milano"></div><div class="form-actions"><button class="btn btn-p" onclick="saveSite('${oid}')">Crea</button><button class="btn btn-g" onclick="closeModal()">Annulla</button></div>`)}
async function saveSite(oid){const name=document.getElementById('f-site-name').value.trim();const address=document.getElementById('f-site-addr').value.trim();if(!name){toast('Inserisci il nome','err');return}await api('/api/sites',{method:'POST',body:JSON.stringify({oid,name,address})});closeModal();toast('Sede creata!');refreshAll()}
function openEditSite(sid){const s=allSites.find(x=>x.id===sid);if(!s)return;showModal(`Modifica Sede — ${s.name}`,`<div class="form-row"><label class="form-label">Nome</label><input class="form-input" id="f-site-name" value="${s.name}"></div><div class="form-row"><label class="form-label">Indirizzo</label><input class="form-input" id="f-site-addr" value="${s.address||''}"></div><div class="form-actions"><button class="btn btn-p" onclick="updateSite('${sid}')">Salva</button><button class="btn btn-g" onclick="closeModal()">Annulla</button></div>`)}
async function updateSite(sid){const name=document.getElementById('f-site-name').value.trim();const address=document.getElementById('f-site-addr').value.trim();await api(`/api/sites/${sid}`,{method:'PATCH',body:JSON.stringify({name,address})});closeModal();toast('Sede aggiornata!');refreshAll()}
async function deleteSite(sid){if(!confirm('Eliminare questa sede?'))return;await api(`/api/sites/${sid}`,{method:'DELETE'});toast('Sede eliminata');refreshAll()}

function openNewDept(sid,oid){showModal('Nuovo Reparto',`<div class="form-row"><label class="form-label">Nome reparto</label><input class="form-input" id="f-dept-name" placeholder="Es. Amministrazione"></div><div class="form-actions"><button class="btn btn-p" onclick="saveDept('${sid}','${oid}')">Crea</button><button class="btn btn-g" onclick="closeModal()">Annulla</button></div>`)}
async function saveDept(sid,oid){const name=document.getElementById('f-dept-name').value.trim();if(!name){toast('Inserisci il nome','err');return}await api('/api/depts',{method:'POST',body:JSON.stringify({sid,oid,name})});closeModal();toast('Reparto creato!');refreshAll()}
async function deleteDept(did){if(!confirm('Eliminare questo reparto?'))return;await api(`/api/depts/${did}`,{method:'DELETE'});toast('Reparto eliminato');refreshAll()}

function openAssignModal(preOid){
  if(!allMachines.length){toast('Nessun device disponibile','err');return}
  showModal('Assegna Device',`
    <div class="form-row"><label class="form-label">Device</label><select class="form-select" id="f-mid">${allMachines.map(m=>`<option value="${m.id}">${m.pc_name} (${m.user})</option>`).join('')}</select></div>
    <div class="form-row"><label class="form-label">Organizzazione</label><select class="form-select" id="f-aoid" onchange="updateSiteSelect()"><option value="">— Non assegnato —</option>${allOrgs.map(o=>`<option value="${o.id}"${o.id===preOid?' selected':''}>${o.name}</option>`).join('')}</select></div>
    <div class="form-row"><label class="form-label">Sede</label><select class="form-select" id="f-asid" onchange="updateDeptSelect()"><option value="">— Nessuna sede —</option></select></div>
    <div class="form-row"><label class="form-label">Reparto</label><select class="form-select" id="f-adid"><option value="">— Nessun reparto —</option></select></div>
    <div class="form-actions"><button class="btn btn-p" onclick="saveAssign()">Assegna</button><button class="btn btn-g" onclick="closeModal()">Annulla</button></div>`);
  if(preOid)updateSiteSelect();
}
function openAssignDevice(mid){openAssignModal();setTimeout(()=>{const s=document.getElementById('f-mid');if(s)s.value=mid},50)}
function updateSiteSelect(){const oid=document.getElementById('f-aoid').value;const filtered=allSites.filter(s=>s.oid===oid);document.getElementById('f-asid').innerHTML=`<option value="">— Nessuna sede —</option>${filtered.map(s=>`<option value="${s.id}">${s.name}</option>`).join('')}`;document.getElementById('f-adid').innerHTML=`<option value="">— Nessun reparto —</option>`}
function updateDeptSelect(){const sid=document.getElementById('f-asid').value;const filtered=allDepts.filter(d=>d.sid===sid);document.getElementById('f-adid').innerHTML=`<option value="">— Nessun reparto —</option>${filtered.map(d=>`<option value="${d.id}">${d.name}</option>`).join('')}`}
async function saveAssign(){const mid=document.getElementById('f-mid').value;const oid=document.getElementById('f-aoid').value||null;const sid=document.getElementById('f-asid').value||null;const did=document.getElementById('f-adid').value||null;await api(`/api/machines/${mid}/assign`,{method:'PATCH',body:JSON.stringify({oid,sid,did})});closeModal();toast('Device assegnato!');refreshAll()}

async function openTicket(id){
  const t=await api(`/api/ticket/${id}`);
  const badge=t.priority==='urgent'&&t.status==='open'?`<span class="tbadge bu">URGENTE</span>`:t.status==='open'?`<span class="tbadge bo">APERTO</span>`:`<span class="tbadge bc">CHIUSO</span>`;
  showModal(`Ticket #${t.id} — ${t.pc_name}`,`
    <div class="igrid">
      <div class="iitem"><div class="ilabel">Nome PC</div><div class="ivalue">${t.pc_name}</div></div>
      <div class="iitem"><div class="ilabel">Utente</div><div class="ivalue">${t.user}</div></div>
      <div class="iitem"><div class="ilabel">IP</div><div class="ivalue">${t.ip}</div></div>
      <div class="iitem"><div class="ilabel">Stato</div><div class="ivalue">${badge}</div></div>
    </div>
    ${t.rustdesk_id?`<div class="rdbox"><div><div style="font-size:9px;color:var(--text2);margin-bottom:3px;letter-spacing:1px">RUSTDESK ID</div><div class="rdid">${t.rustdesk_id}</div></div><button class="btn btn-p" onclick="connectRD('${t.rustdesk_id}')">⬡ Connetti</button></div>`:''}
    <div style="font-size:10px;color:var(--text2);margin-bottom:6px;letter-spacing:1px;text-transform:uppercase;font-family:monospace">Descrizione</div>
    <div style="background:var(--bg3);border-radius:7px;padding:12px;font-size:12px;line-height:1.6;margin-bottom:16px;white-space:pre-wrap">${esc(t.description)}</div>
    ${t.screenshot?`<div style="background:var(--bg0);border-radius:7px;overflow:hidden;border:1px solid var(--border);margin-bottom:16px"><img src="data:image/png;base64,${t.screenshot}" style="max-width:100%;max-height:300px;display:block;margin:auto"></div>`:''}
    <textarea class="note-area" id="note-inp" placeholder="Note tecnico...">${t.note||''}</textarea>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      ${t.status==='open'?`<button class="btn btn-p" onclick="updTicket(${t.id},'status','closed')">✓ Chiudi</button><button class="btn btn-d" onclick="updTicket(${t.id},'priority','urgent')">⚠ Urgente</button>`:`<button class="btn btn-g" onclick="updTicket(${t.id},'status','open')">↺ Riapri</button>`}
      <button class="btn btn-g" onclick="saveNote(${t.id})">💾 Salva Note</button>
      <button class="btn btn-g" onclick="closeModal()">Chiudi</button>
    </div>`);
}
async function updTicket(id,f,v){await api(`/api/ticket/${id}`,{method:'PATCH',body:JSON.stringify({[f]:v})});closeModal();toast('Ticket aggiornato');refreshAll()}
async function saveNote(id){await api(`/api/ticket/${id}`,{method:'PATCH',body:JSON.stringify({note:document.getElementById('note-inp').value})});toast('Note salvate')}
function connectRD(id){window.open(`rustdesk://${id}`,'_blank');toast(`Connessione RustDesk → ${id}`)}

function showView(name,el){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.getElementById(`view-${name}`).classList.add('active');
  if(el){document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));el.classList.add('active')}
  if(name!=='org-detail')document.getElementById('breadcrumb').innerHTML='';
}

async function loadDemo(){await api('/api/demo',{method:'POST'});toast('Demo caricata!');refreshAll()}
function toast(msg,type='ok'){const el=document.createElement('div');el.className='toast';el.style.borderColor=type==='err'?'rgba(255,71,87,.4)':'rgba(0,212,170,.3)';el.innerHTML=`<span style="color:${type==='err'?'var(--red)':'var(--accent)'}">${type==='err'?'✕':'✓'}</span> ${msg}`;document.getElementById('toasts').appendChild(el);setTimeout(()=>el.remove(),3200)}
function clock(){document.getElementById('clk').textContent=new Date().toLocaleTimeString('it-IT',{hour:'2-digit',minute:'2-digit'})}


// ── DOCUMENTATION ─────────────────────────────────────────────
let currentDocOrg = null;
let currentDocTab = 'apps';
let docApps=[], docKb=[], docChecklists=[], docWiki=[];

async function showDocumentation(oid) {
  currentDocOrg = oid;
  const org = allOrgs.find(o=>o.id===oid);
  document.getElementById('breadcrumb').innerHTML = `&nbsp;/&nbsp;<span style="color:var(--accent)">${org?.name||'—'}</span> / Documentazione`;
  await loadAllDocs(oid);
  renderDocView();
  showView('org-docs', null);
}

async function loadAllDocs(oid) {
  [docApps, docKb, docChecklists, docWiki] = await Promise.all([
    api(`/api/orgs/${oid}/docs/apps`),
    api(`/api/orgs/${oid}/docs/kb`),
    api(`/api/orgs/${oid}/docs/checklists`),
    api(`/api/orgs/${oid}/docs/wiki`),
  ]);
}

function setDocTab(tab) {
  currentDocTab = tab;
  document.querySelectorAll('.doc-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('dtab-'+tab).classList.add('active');
  renderDocContent();
}

function renderDocView() {
  const org = allOrgs.find(o=>o.id===currentDocOrg);
  document.getElementById('doc-org-title').innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px">
      <div style="width:10px;height:10px;border-radius:50%;background:${org?.color||'#00d4aa'}"></div>
      <div style="font-size:16px;font-weight:800">${org?.name||'—'}</div>
      <div style="font-size:11px;color:var(--text3);background:var(--bg3);padding:3px 10px;border-radius:20px;font-family:monospace">Documentazione</div>
      <div style="margin-left:auto">
        <button class="btn btn-g" style="font-size:11px" onclick="showOrgDetail('${currentDocOrg}')">← Torna all'org</button>
      </div>
    </div>
    <div style="display:flex;gap:6px;margin-bottom:20px;border-bottom:1px solid var(--border);padding-bottom:0">
      <button class="tab doc-tab active" id="dtab-apps"    onclick="setDocTab('apps')">🖥 App e Servizi</button>
      <button class="tab doc-tab"        id="dtab-kb"      onclick="setDocTab('kb')">📚 Knowledge Base</button>
      <button class="tab doc-tab"        id="dtab-checks"  onclick="setDocTab('checks')">✅ Checklist</button>
      <button class="tab doc-tab"        id="dtab-wiki"    onclick="setDocTab('wiki')">📝 Wiki / Note</button>
    </div>`;
  renderDocContent();
}

function renderDocContent() {
  const el = document.getElementById('doc-content');
  if (currentDocTab === 'apps')   el.innerHTML = renderApps();
  if (currentDocTab === 'kb')     el.innerHTML = renderKb();
  if (currentDocTab === 'checks') el.innerHTML = renderChecklists();
  if (currentDocTab === 'wiki')   el.innerHTML = renderWiki();
}

// ── APP E SERVIZI ─────────────────────────────────────────────
function renderApps() {
  const cats = [...new Set(docApps.map(a=>a.category||'Software'))];
  const today = new Date().toISOString().slice(0,10);
  return `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <div style="font-size:13px;font-weight:700">🖥 App e Servizi <span style="font-size:10px;color:var(--text3);font-family:monospace">(${docApps.length})</span></div>
      <button class="btn btn-p" onclick="openNewApp()">+ Aggiungi</button>
    </div>
    ${!docApps.length ? `<div class="empty"><div class="empty-icon">🖥</div>Nessuna app registrata</div>` :
    `<div style="overflow-x:auto">
      <table class="dev-table">
        <thead><tr><th>App / Servizio</th><th>Categoria</th><th>Versione</th><th>Licenza</th><th>Posti</th><th>Scadenza</th><th>Note</th><th></th></tr></thead>
        <tbody>
        ${docApps.map(a => {
          const exp = a.license_expiry;
          const expiring = exp && exp <= new Date(Date.now()+30*86400000).toISOString().slice(0,10);
          const expired  = exp && exp < today;
          return `<tr>
            <td><span style="font-weight:700;color:var(--text)">${esc(a.name)}</span></td>
            <td><span class="tag tag-dept">${esc(a.category||'—')}</span></td>
            <td><span style="font-family:monospace;font-size:11px;color:var(--text2)">${esc(a.version||'—')}</span></td>
            <td><span style="font-size:11px">${esc(a.license_type||'—')}</span></td>
            <td><span style="font-family:monospace;font-size:11px;color:var(--accent)">${a.license_count||'—'}</span></td>
            <td><span style="font-size:11px;font-family:monospace;color:${expired?'var(--red)':expiring?'var(--orange)':'var(--text2)'}">${exp||'—'}${expired?' ⚠':expiring?' ⏰':''}</span></td>
            <td><span style="font-size:11px;color:var(--text2)">${esc(a.notes||'—').slice(0,40)}</span></td>
            <td style="white-space:nowrap">
              <button class="btn btn-g" style="font-size:10px;padding:4px 8px" onclick="openEditApp('${a.id}')">✏</button>
              <button class="btn btn-d" style="font-size:10px;padding:4px 8px" onclick="deleteApp('${a.id}')">✕</button>
            </td>
          </tr>`;
        }).join('')}
        </tbody>
      </table>
    </div>`}`;
}

function openNewApp() {
  showModal('Nuova App / Servizio', `
    <div class="igrid">
      <div class="form-row"><label class="form-label">Nome *</label><input class="form-input" id="fa-name" placeholder="es. Microsoft 365"></div>
      <div class="form-row"><label class="form-label">Categoria</label>
        <select class="form-select" id="fa-cat">
          <option>Software</option><option>SaaS</option><option>Antivirus</option><option>Backup</option><option>VPN</option><option>Database</option><option>Altro</option>
        </select>
      </div>
    </div>
    <div class="igrid">
      <div class="form-row"><label class="form-label">Versione</label><input class="form-input" id="fa-ver" placeholder="es. 2024"></div>
      <div class="form-row"><label class="form-label">Tipo licenza</label><input class="form-input" id="fa-ltype" placeholder="es. Abbonamento annuale"></div>
    </div>
    <div class="igrid">
      <div class="form-row"><label class="form-label">N° posti</label><input class="form-input" id="fa-lcnt" type="number" min="0" placeholder="0"></div>
      <div class="form-row"><label class="form-label">Scadenza licenza</label><input class="form-input" id="fa-lexp" type="date"></div>
    </div>
    <div class="form-row"><label class="form-label">Note</label><textarea class="note-area" id="fa-notes" rows="2" placeholder="Note aggiuntive..."></textarea></div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="saveApp()">Salva</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}

async function saveApp() {
  const name = document.getElementById('fa-name').value.trim();
  if(!name){toast('Inserisci il nome','err');return}
  const body = {
    name, category: document.getElementById('fa-cat').value,
    version: document.getElementById('fa-ver').value,
    license_type: document.getElementById('fa-ltype').value,
    license_count: parseInt(document.getElementById('fa-lcnt').value)||0,
    license_expiry: document.getElementById('fa-lexp').value,
    notes: document.getElementById('fa-notes').value
  };
  await api(`/api/orgs/${currentDocOrg}/docs/apps`, {method:'POST',body:JSON.stringify(body)});
  closeModal(); toast('App aggiunta!');
  docApps = await api(`/api/orgs/${currentDocOrg}/docs/apps`);
  renderDocContent();
}

function openEditApp(aid) {
  const a = docApps.find(x=>x.id===aid); if(!a) return;
  showModal(`Modifica — ${a.name}`, `
    <div class="igrid">
      <div class="form-row"><label class="form-label">Nome *</label><input class="form-input" id="fa-name" value="${esc(a.name)}"></div>
      <div class="form-row"><label class="form-label">Categoria</label>
        <select class="form-select" id="fa-cat">
          ${['Software','SaaS','Antivirus','Backup','VPN','Database','Altro'].map(c=>`<option${c===a.category?' selected':''}>${c}</option>`).join('')}
        </select>
      </div>
    </div>
    <div class="igrid">
      <div class="form-row"><label class="form-label">Versione</label><input class="form-input" id="fa-ver" value="${esc(a.version||'')}"></div>
      <div class="form-row"><label class="form-label">Tipo licenza</label><input class="form-input" id="fa-ltype" value="${esc(a.license_type||'')}"></div>
    </div>
    <div class="igrid">
      <div class="form-row"><label class="form-label">N° posti</label><input class="form-input" id="fa-lcnt" type="number" value="${a.license_count||0}"></div>
      <div class="form-row"><label class="form-label">Scadenza</label><input class="form-input" id="fa-lexp" type="date" value="${a.license_expiry||''}"></div>
    </div>
    <div class="form-row"><label class="form-label">Note</label><textarea class="note-area" id="fa-notes" rows="2">${esc(a.notes||'')}</textarea></div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="updateApp('${aid}')">Salva</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}

async function updateApp(aid) {
  const body = {
    name: document.getElementById('fa-name').value.trim(),
    category: document.getElementById('fa-cat').value,
    version: document.getElementById('fa-ver').value,
    license_type: document.getElementById('fa-ltype').value,
    license_count: parseInt(document.getElementById('fa-lcnt').value)||0,
    license_expiry: document.getElementById('fa-lexp').value,
    notes: document.getElementById('fa-notes').value
  };
  await api(`/api/orgs/${currentDocOrg}/docs/apps/${aid}`, {method:'PATCH',body:JSON.stringify(body)});
  closeModal(); toast('Salvato!');
  docApps = await api(`/api/orgs/${currentDocOrg}/docs/apps`);
  renderDocContent();
}

async function deleteApp(aid) {
  if(!confirm('Eliminare questa app?')) return;
  await api(`/api/orgs/${currentDocOrg}/docs/apps/${aid}`, {method:'DELETE'});
  toast('Eliminata'); docApps = docApps.filter(a=>a.id!==aid); renderDocContent();
}

// ── KNOWLEDGE BASE ────────────────────────────────────────────
function renderKb() {
  const cats = [...new Set(docKb.map(k=>k.category||'Generale'))];
  return `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <div style="font-size:13px;font-weight:700">📚 Knowledge Base <span style="font-size:10px;color:var(--text3);font-family:monospace">(${docKb.length} articoli)</span></div>
      <button class="btn btn-p" onclick="openNewKb()">+ Nuovo articolo</button>
    </div>
    ${!docKb.length ? `<div class="empty"><div class="empty-icon">📚</div>Nessun articolo nella KB</div>` :
    `<div style="display:flex;flex-direction:column;gap:10px">
      ${docKb.map(k=>`
        <div class="panel" style="cursor:pointer" onclick="openKbDetail('${k.id}')">
          <div style="padding:14px 18px;display:flex;align-items:center;gap:12px">
            <div style="flex:1">
              <div style="font-size:13px;font-weight:700;margin-bottom:4px">${esc(k.title)}</div>
              <div style="display:flex;gap:8px;flex-wrap:wrap">
                <span class="tag tag-dept">${esc(k.category||'Generale')}</span>
                ${k.tags ? k.tags.split(',').filter(Boolean).map(t=>`<span style="font-size:9px;background:var(--bg4);color:var(--text3);padding:2px 7px;border-radius:4px">${esc(t.trim())}</span>`).join('') : ''}
              </div>
            </div>
            <div style="text-align:right">
              <div style="font-size:10px;color:var(--text3);font-family:monospace">${k.updated_at?.slice(0,10)||'—'}</div>
              <div style="display:flex;gap:5px;margin-top:6px">
                <button class="btn btn-g" style="font-size:10px;padding:4px 8px" onclick="event.stopPropagation();openEditKb('${k.id}')">✏</button>
                <button class="btn btn-d" style="font-size:10px;padding:4px 8px" onclick="event.stopPropagation();deleteKb('${k.id}')">✕</button>
              </div>
            </div>
          </div>
          ${k.content ? `<div style="padding:0 18px 14px;font-size:11px;color:var(--text2);line-height:1.6;white-space:pre-wrap;max-height:60px;overflow:hidden;mask-image:linear-gradient(to bottom,black 60%,transparent)">${esc(k.content.slice(0,200))}</div>` : ''}
        </div>`).join('')}
    </div>`}`;
}

function openNewKb() {
  showModal('Nuovo Articolo KB', `
    <div class="form-row"><label class="form-label">Titolo *</label><input class="form-input" id="fk-title" placeholder="es. Come configurare la VPN"></div>
    <div class="igrid">
      <div class="form-row"><label class="form-label">Categoria</label>
        <select class="form-select" id="fk-cat">
          <option>Generale</option><option>Rete</option><option>Hardware</option><option>Software</option><option>Sicurezza</option><option>Procedure</option>
        </select>
      </div>
      <div class="form-row"><label class="form-label">Tag (separati da virgola)</label><input class="form-input" id="fk-tags" placeholder="vpn, accesso, remoto"></div>
    </div>
    <div class="form-row"><label class="form-label">Contenuto</label><textarea class="note-area" id="fk-content" rows="8" placeholder="Scrivi l'articolo qui..."></textarea></div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="saveKb()">Salva</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}

async function saveKb() {
  const title = document.getElementById('fk-title').value.trim();
  if(!title){toast('Inserisci il titolo','err');return}
  const body = {title, category: document.getElementById('fk-cat').value,
    tags: document.getElementById('fk-tags').value, content: document.getElementById('fk-content').value};
  await api(`/api/orgs/${currentDocOrg}/docs/kb`, {method:'POST',body:JSON.stringify(body)});
  closeModal(); toast('Articolo creato!');
  docKb = await api(`/api/orgs/${currentDocOrg}/docs/kb`); renderDocContent();
}

function openEditKb(kid) {
  const k = docKb.find(x=>x.id===kid); if(!k) return;
  showModal(`Modifica — ${k.title}`, `
    <div class="form-row"><label class="form-label">Titolo *</label><input class="form-input" id="fk-title" value="${esc(k.title)}"></div>
    <div class="igrid">
      <div class="form-row"><label class="form-label">Categoria</label>
        <select class="form-select" id="fk-cat">
          ${['Generale','Rete','Hardware','Software','Sicurezza','Procedure'].map(c=>`<option${c===k.category?' selected':''}>${c}</option>`).join('')}
        </select>
      </div>
      <div class="form-row"><label class="form-label">Tag</label><input class="form-input" id="fk-tags" value="${esc(k.tags||'')}"></div>
    </div>
    <div class="form-row"><label class="form-label">Contenuto</label><textarea class="note-area" id="fk-content" rows="10">${esc(k.content||'')}</textarea></div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="updateKb('${kid}')">Salva</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}

async function updateKb(kid) {
  const body = {title: document.getElementById('fk-title').value.trim(),
    category: document.getElementById('fk-cat').value,
    tags: document.getElementById('fk-tags').value,
    content: document.getElementById('fk-content').value};
  await api(`/api/orgs/${currentDocOrg}/docs/kb/${kid}`, {method:'PATCH',body:JSON.stringify(body)});
  closeModal(); toast('Salvato!');
  docKb = await api(`/api/orgs/${currentDocOrg}/docs/kb`); renderDocContent();
}

async function deleteKb(kid) {
  if(!confirm('Eliminare questo articolo?')) return;
  await api(`/api/orgs/${currentDocOrg}/docs/kb/${kid}`, {method:'DELETE'});
  toast('Eliminato'); docKb = docKb.filter(k=>k.id!==kid); renderDocContent();
}

function openKbDetail(kid) {
  const k = docKb.find(x=>x.id===kid); if(!k) return;
  showModal(k.title, `
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
      <span class="tag tag-dept">${esc(k.category||'Generale')}</span>
      ${(k.tags||'').split(',').filter(Boolean).map(t=>`<span style="font-size:9px;background:var(--bg4);color:var(--text3);padding:2px 7px;border-radius:4px">${esc(t.trim())}</span>`).join('')}
      <span style="margin-left:auto;font-size:10px;color:var(--text3);font-family:monospace">Aggiornato: ${k.updated_at?.slice(0,10)||'—'}</span>
    </div>
    <div style="background:var(--bg3);border-radius:8px;padding:16px;font-size:13px;line-height:1.8;white-space:pre-wrap;max-height:60vh;overflow-y:auto">${esc(k.content||'Nessun contenuto.')}</div>
    <div style="display:flex;gap:8px;margin-top:14px">
      <button class="btn btn-b" onclick="closeModal();openEditKb('${kid}')">✏ Modifica</button>
      <button class="btn btn-g" onclick="closeModal()">Chiudi</button>
    </div>`);
}

// ── CHECKLIST ─────────────────────────────────────────────────
function renderChecklists() {
  return `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <div style="font-size:13px;font-weight:700">✅ Elenchi di controllo <span style="font-size:10px;color:var(--text3);font-family:monospace">(${docChecklists.length})</span></div>
      <button class="btn btn-p" onclick="openNewChecklist()">+ Nuova checklist</button>
    </div>
    ${!docChecklists.length ? `<div class="empty"><div class="empty-icon">✅</div>Nessuna checklist</div>` :
    `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px">
      ${docChecklists.map(cl => {
        const total = cl.items?.length || 0;
        const done  = cl.items?.filter(i=>i.checked).length || 0;
        const pct   = total ? Math.round(done/total*100) : 0;
        return `<div class="panel">
          <div style="padding:14px 18px;border-bottom:1px solid var(--border)">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
              <div style="font-size:13px;font-weight:700">${esc(cl.name)}</div>
              <div style="display:flex;gap:5px">
                <button class="btn btn-b" style="font-size:10px;padding:4px 8px" onclick="openAddCheckItem('${cl.id}')">+</button>
                <button class="btn btn-g" style="font-size:10px;padding:4px 8px" onclick="openEditChecklist('${cl.id}')">✏</button>
                <button class="btn btn-d" style="font-size:10px;padding:4px 8px" onclick="deleteChecklist('${cl.id}')">✕</button>
              </div>
            </div>
            ${cl.description ? `<div style="font-size:11px;color:var(--text2);margin-bottom:8px">${esc(cl.description)}</div>` : ''}
            <div style="display:flex;align-items:center;gap:8px">
              <div style="flex:1;height:4px;background:var(--bg4);border-radius:4px;overflow:hidden">
                <div style="height:100%;background:${pct===100?'var(--green)':pct>50?'var(--accent2)':'var(--orange)'};width:${pct}%;border-radius:4px;transition:width .3s"></div>
              </div>
              <span style="font-size:10px;color:var(--text2);font-family:monospace">${done}/${total}</span>
            </div>
          </div>
          <div style="padding:10px 18px;max-height:240px;overflow-y:auto">
            ${!cl.items?.length ? `<div style="font-size:11px;color:var(--text3);padding:6px 0">Nessun elemento. Clicca + per aggiungere.</div>` :
              cl.items.map(item => `
                <div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid rgba(42,53,71,.3)">
                  <input type="checkbox" ${item.checked?'checked':''} onchange="toggleCheckItem('${cl.id}','${item.id}',this.checked)"
                    style="width:16px;height:16px;accent-color:var(--accent);cursor:pointer;flex-shrink:0">
                  <span style="font-size:12px;flex:1;${item.checked?'text-decoration:line-through;color:var(--text3)':''}">${esc(item.text)}</span>
                  <button onclick="deleteCheckItem('${cl.id}','${item.id}')" style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:12px;padding:0 4px">×</button>
                </div>`).join('')}
          </div>
        </div>`;
      }).join('')}
    </div>`}`;
}

function openNewChecklist() {
  showModal('Nuova Checklist', `
    <div class="form-row"><label class="form-label">Nome *</label><input class="form-input" id="fc-name" placeholder="es. Onboarding nuovo dipendente"></div>
    <div class="form-row"><label class="form-label">Descrizione</label><input class="form-input" id="fc-desc" placeholder="Opzionale"></div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="saveChecklist()">Crea</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}

async function saveChecklist() {
  const name = document.getElementById('fc-name').value.trim();
  if(!name){toast('Inserisci il nome','err');return}
  await api(`/api/orgs/${currentDocOrg}/docs/checklists`, {method:'POST',body:JSON.stringify({name, description: document.getElementById('fc-desc').value})});
  closeModal(); toast('Checklist creata!');
  docChecklists = await api(`/api/orgs/${currentDocOrg}/docs/checklists`); renderDocContent();
}

function openEditChecklist(cid) {
  const cl = docChecklists.find(x=>x.id===cid); if(!cl) return;
  showModal(`Modifica — ${cl.name}`, `
    <div class="form-row"><label class="form-label">Nome *</label><input class="form-input" id="fc-name" value="${esc(cl.name)}"></div>
    <div class="form-row"><label class="form-label">Descrizione</label><input class="form-input" id="fc-desc" value="${esc(cl.description||'')}"></div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="updateChecklist('${cid}')">Salva</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}

async function updateChecklist(cid) {
  await api(`/api/orgs/${currentDocOrg}/docs/checklists/${cid}`, {method:'PATCH',body:JSON.stringify({name: document.getElementById('fc-name').value.trim(), description: document.getElementById('fc-desc').value})});
  closeModal(); toast('Salvato!');
  docChecklists = await api(`/api/orgs/${currentDocOrg}/docs/checklists`); renderDocContent();
}

async function deleteChecklist(cid) {
  if(!confirm('Eliminare questa checklist e tutti i suoi elementi?')) return;
  await api(`/api/orgs/${currentDocOrg}/docs/checklists/${cid}`, {method:'DELETE'});
  toast('Eliminata'); docChecklists = docChecklists.filter(c=>c.id!==cid); renderDocContent();
}

function openAddCheckItem(cid) {
  showModal('Aggiungi elemento', `
    <div class="form-row"><label class="form-label">Testo elemento *</label><input class="form-input" id="fi-text" placeholder="es. Creare account email aziendale" autofocus></div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="saveCheckItem('${cid}')">Aggiungi</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
  setTimeout(()=>document.getElementById('fi-text')?.focus(),100);
}

async function saveCheckItem(cid) {
  const text = document.getElementById('fi-text').value.trim();
  if(!text){toast('Inserisci il testo','err');return}
  await api(`/api/orgs/${currentDocOrg}/docs/checklists/${cid}/items`, {method:'POST',body:JSON.stringify({text})});
  closeModal(); toast('Elemento aggiunto!');
  docChecklists = await api(`/api/orgs/${currentDocOrg}/docs/checklists`); renderDocContent();
}

async function toggleCheckItem(cid, iid, checked) {
  await api(`/api/orgs/${currentDocOrg}/docs/checklists/${cid}/items/${iid}`, {method:'PATCH',body:JSON.stringify({checked})});
  const cl = docChecklists.find(c=>c.id===cid);
  if(cl){const item=cl.items?.find(i=>i.id===iid);if(item)item.checked=checked?1:0;}
  // Re-render solo la sezione progress senza reload completo
  docChecklists = await api(`/api/orgs/${currentDocOrg}/docs/checklists`); renderDocContent();
}

async function deleteCheckItem(cid, iid) {
  await api(`/api/orgs/${currentDocOrg}/docs/checklists/${cid}/items/${iid}`, {method:'DELETE'});
  docChecklists = await api(`/api/orgs/${currentDocOrg}/docs/checklists`); renderDocContent();
}

// ── WIKI / NOTE ───────────────────────────────────────────────
function renderWiki() {
  return `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <div style="font-size:13px;font-weight:700">📝 Wiki / Note libere <span style="font-size:10px;color:var(--text3);font-family:monospace">(${docWiki.length})</span></div>
      <button class="btn btn-p" onclick="openNewWiki()">+ Nuova nota</button>
    </div>
    ${!docWiki.length ? `<div class="empty"><div class="empty-icon">📝</div>Nessuna nota wiki</div>` :
    `<div style="display:flex;flex-direction:column;gap:10px">
      ${docWiki.map(w=>`
        <div class="panel" style="cursor:pointer" onclick="openWikiDetail('${w.id}')">
          <div style="padding:14px 18px;display:flex;align-items:center;gap:12px">
            <div style="flex:1">
              <div style="font-size:13px;font-weight:700">${esc(w.title)}</div>
              ${w.content ? `<div style="font-size:11px;color:var(--text2);margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:500px">${esc(w.content.slice(0,120))}</div>` : ''}
            </div>
            <div style="text-align:right;flex-shrink:0">
              <div style="font-size:10px;color:var(--text3);font-family:monospace">${w.updated_at?.slice(0,10)||'—'}</div>
              <div style="display:flex;gap:5px;margin-top:6px;justify-content:flex-end">
                <button class="btn btn-g" style="font-size:10px;padding:4px 8px" onclick="event.stopPropagation();openEditWiki('${w.id}')">✏</button>
                <button class="btn btn-d" style="font-size:10px;padding:4px 8px" onclick="event.stopPropagation();deleteWiki('${w.id}')">✕</button>
              </div>
            </div>
          </div>
        </div>`).join('')}
    </div>`}`;
}

function openNewWiki() {
  showModal('Nuova nota Wiki', `
    <div class="form-row"><label class="form-label">Titolo *</label><input class="form-input" id="fw-title" placeholder="es. Credenziali server NAS"></div>
    <div class="form-row"><label class="form-label">Contenuto (testo libero o markdown)</label><textarea class="note-area" id="fw-content" rows="10" placeholder="Scrivi qui le note..."></textarea></div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="saveWiki()">Salva</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}

async function saveWiki() {
  const title = document.getElementById('fw-title').value.trim();
  if(!title){toast('Inserisci il titolo','err');return}
  await api(`/api/orgs/${currentDocOrg}/docs/wiki`, {method:'POST',body:JSON.stringify({title, content: document.getElementById('fw-content').value})});
  closeModal(); toast('Nota salvata!');
  docWiki = await api(`/api/orgs/${currentDocOrg}/docs/wiki`); renderDocContent();
}

function openEditWiki(wid) {
  const w = docWiki.find(x=>x.id===wid); if(!w) return;
  showModal(`Modifica — ${w.title}`, `
    <div class="form-row"><label class="form-label">Titolo *</label><input class="form-input" id="fw-title" value="${esc(w.title)}"></div>
    <div class="form-row"><label class="form-label">Contenuto</label><textarea class="note-area" id="fw-content" rows="12">${esc(w.content||'')}</textarea></div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="updateWiki('${wid}')">Salva</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}

async function updateWiki(wid) {
  await api(`/api/orgs/${currentDocOrg}/docs/wiki/${wid}`, {method:'PATCH',body:JSON.stringify({title: document.getElementById('fw-title').value.trim(), content: document.getElementById('fw-content').value})});
  closeModal(); toast('Salvato!');
  docWiki = await api(`/api/orgs/${currentDocOrg}/docs/wiki`); renderDocContent();
}

async function deleteWiki(wid) {
  if(!confirm('Eliminare questa nota?')) return;
  await api(`/api/orgs/${currentDocOrg}/docs/wiki/${wid}`, {method:'DELETE'});
  toast('Eliminata'); docWiki = docWiki.filter(w=>w.id!==wid); renderDocContent();
}

function openWikiDetail(wid) {
  const w = docWiki.find(x=>x.id===wid); if(!w) return;
  showModal(w.title, `
    <div style="font-size:10px;color:var(--text3);font-family:monospace;margin-bottom:14px">Aggiornato: ${w.updated_at?.slice(0,10)||'—'}</div>
    <div style="background:var(--bg3);border-radius:8px;padding:16px;font-size:13px;line-height:1.8;white-space:pre-wrap;max-height:65vh;overflow-y:auto">${esc(w.content||'Nessun contenuto.')}</div>
    <div style="display:flex;gap:8px;margin-top:14px">
      <button class="btn btn-b" onclick="closeModal();openEditWiki('${wid}')">✏ Modifica</button>
      <button class="btn btn-g" onclick="closeModal()">Chiudi</button>
    </div>`);
}

// ── INIT ──────────────────────────────────────────────────────
(async()=>{
  await initAuth();
  await refreshAll();
  clock();
  setInterval(clock,10000);
  setInterval(refreshAll,30000);
})();
</script>
</body>
</html>
"""

@app.route("/")
@app.route("/dashboard")
@require_login
def dashboard():
    return Response(DASHBOARD_HTML, mimetype="text/html")

init_db()

if __name__ == "__main__":
    print("Uptime Service Dashboard v4 — SQLite — http://localhost:5000")
    print("Login: admin / admin")
    app.run(debug=False, host="0.0.0.0", port=5000)
