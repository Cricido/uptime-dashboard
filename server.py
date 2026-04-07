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
    <img src="data:image/png;base64,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" style="height:44px;width:auto;object-fit:contain;filter:brightness(0) invert(1)" alt="Uptime Service">
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
    <img src="data:image/png;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAH4AABAAEAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/wAARCAEGA0EDASIAAhEBAxEB/8QAHAABAAMBAQEBAQAAAAAAAAAAAAUGBwQDCAEC/8QAVxAAAgECAgQFDAwMAwgCAwAAAAECAwQFEQYSITEHQVFzshMVFjU2VFVhcZGSsQgUIjI0coGTocHR4SNCUmJldIKUo7PC0iQl4kNTY2Siw9PwJjMXRVb/xAAbAQEBAAMBAQEAAAAAAAAAAAAABQMEBgIBB//EADgRAAEDAgIHBAkEAwEBAAAAAAABAgMEEQVREhMhMTNxgRUyQWEGIkJSobHB0fAUIzXhNJHxgrL/2gAMAwEAAhEDEQA/APjIAAAAAAAAAAAAAAAAAAAAAAAAAk9GMDxHSPGqGE4XR6pcVnvfvYR45SfEkFWx5e9rGq5y2RCMBdeE3g9xLQu4pVHUd5h1ZJQuowySnltjJcT35cq+UpR8a5HJdDHT1EdRGkkS3RQAD6ZgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdlbD61DD6V7cLqUbj4PCXvqiTyc0vyc9mfG9izyeQ+K5E3nGAAfQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeltQrXNxTt7elOrWqyUKcILOUpPYklxsBVttU9sJw+8xXEqGHYfbzuLqvNQp0472/qXj4j6o4LtB7PQzBepLUrYlXSd3cJb3+TH81fTv8kdwO8H1HRHDVfX8IVMauYfhZb1Qi/wDZxfrfG/EjQTQnm0vVTcfnmP41+qdqIV9RN/mv2/6cuLYfZYth1fDsQt4XFrXjq1Kc1sa+p+PiPlzhU0BvdDMU14a9xhNeT9rXGW78yfJJfStq40vq048awuxxnC6+G4lbwuLWvHVnCXrXI1vT4jHFKsa+RPwnFpMPkzYu9PqnmfFILjwoaCX2hmK6r17jDK8n7Vuct/5kuSS+neuNKnFJrkcl0P02CeOojSSNbooAB9MwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB+pNvJbWbVwWcGNtYWXZXprCFGhQg61O0rLJRilnr1V/T5+Q8PejEuppV1dFRR6cnRPFVyQquiuh9phmj70z0ypyhhsMnZWLerUvZv3qfJB7/Gs3u303HsVu8axWtiN449UqPKMILKFOK2RhFcUUskkWDhT0zuNMdIHXjr0sOt84WdF8UeOTX5T+jYuIqAYi73bzzRxyqmun76+HuplzzXxXyRAAD2b4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB+xTlJRim23kkuM+jOBHg4WA28MfxuguutaOdGlNfBoP8Ara38i2cpEcBXBv1FUNKseofhXlOxtpr3q4qsly/kri38mW2GlPNf1WnDekON6d6WBdntLn5J9QADUOOAAAOHHsIw/HMKr4XidvGva145Si965GnxNcTPljhM0HxDQzF+o1davh9Zt2tzlskvyZcklyfKj6rvcQsLJpXt9bWzks0qtWMM18rIHSa/0IxzCK+FYxjeDVLassmpXtNOL4pReexrlM0MjmL5F3BsSnoZNjVVi70+qefzPkUE1plg1vgeOVbOzxWyxS199RuLWtGopR4lLVbylyo5VguLNdr7j0Sm1Ff3UP0hkzHMR6LsUjwSHWTFvB9f0R1kxbwfX9E9ap+SnrWszQjwSHWTFvB9f0R1kxbwfX9Eap+SjWszQjwSHWTFvB9f0R1kxbwfX9Eap+SjWszQjwSHWTFvB9f0R1kxbwfX9Eap+SjWszQjwd8sGxWMc3h9xl4oNnlUw7EKVu7ipYXUKKeTqSoyUU/LlkfFY5N6H1HtXcpygA8noAAAA/ujTqVq0KNGEqlSclGEYrNyb2JJcp29ZMW7wr+iemtc7ch5c9rd6keCQ6yYt3hX9EdZMW7wr+ifdU/JTzrWZoR4JDrJi3eFf0R1kxbvCv6I1T8lGtZmhHgkOsmLd4V/RHWTFu8K/ojVPyUa1maEeCQ6yYt3hX9EdZMW7wr+iNU/JRrWZoR4JDrJi3eFf0R1kxbvCv6I1T8lGtZmhHgkOsmLd4V/RHWTFu8K/ojVPyUa1maEeCQ6yYt3hX9EdZMW7wr+iNU/JRrWZoR4Pe8tLmzmoXVCdKUlmlJZZo8DyqKi2U9oqKl0AP7oUqterGlRpyqVJboxWbZ2dZsV8H3HoM+tY525D457W71OAHf1mxXwfcegx1mxXwfcegz1qn5KedazNDgB39ZsV8H3HoM469GrQqypVqcqdSO+Mlk0eXMc3eh6a9rtyn8AA8noA6rTD727pupbW1SrFPJuKzyZ7dZMW7wr+ie0jeu1EPCyMRbKpHgkOsmLd4V/RHWTFu8K/ojVPyU+a1maEeCQ6yYvxYdcN8ihm38hHnxzVbvQ9NcjtygAHk9AAAAAAAA/YRlOahCLlKTySSzbYB+AkOsmLd4V/RHWTFu8K/onvVPyU8a1maEeCQ6yYt3hX9EdZMW7wr+iNU/JT5rWZoR5/dGlUr1oUaNOdSrUkowhBZuTe5JcbJK20dxy5uKdvb4Xc1atSSjCEYZts+huCXgytNFaMMTxSNO5xqcd++Fsn+LHllyy+RbN+GZ+qT1k2k7EsWgoY9JVu5dyZ/0RfA/wV08GVHHdI6UKuJbJULZ5ONvyN8s/oXl3VPh80+67Xk9GcIr54fbz/wAVUg9leovxVyxi/O/Ii58O+n3WHD3o/hNbLFLqH4apF7bem/VKXFyLbyHznThKpUjCEXKUmkkuNswQsV66buhJwellrZe0Kv8A8p4J5/b/AGfyCR6yYt3hX9EdZMW7wr+ibuqfkp0+tZ7yEcCR6yYt3hX9EdZMW7wr+iNU/JRrWe8hHAkesmLd4V/RHWTFu8K/ojVPyUa1nvIRwJHrJi3eFf0R1kxbvCv6I1T8lGtZ7yEcCR6yYt3hX9EdZMW7wr+iNU/JRrWe8hHAkesmLd4V/RHWTFu8K/ojVPyUa1nvIRwJHrJi3eFf0T86yYt3hX9Eap+SjWs95CPAB4MgAAAAAAAAAAAABMaJWNtiGI1be6g5Q6hJxybWrLNJPZyZ+QksT0Prw1qmH3CrR2tU6nuZr3WxJ7nsybb1ePYZ200jmabUuhgdUxtfoOWylVBJ1cAxuFWpTWF3dR0nlOVKm6kV+1HNPznPRwzEa89Sjh93Un+TCjJv6EYVRU2KZkVFS6HICYstGsYuajjK0dso1FCbuPcOD5XF+6a8iZPWWilpb21Sd5J3NTqb2JuMYvJPZk83tTWb3p7kZo6aWTaibDDJUxR7FXaUkAGAzg9LatO3uKdelq69OSlHWipLNPNZp7H5GeYAVLlz/wDylp7/AP0NX5il/abdwDY/i+kWh91fYzeSu7iF/OlGcoxjlFU6bS9ykt8n5z5ePo32MXcFfL9KVP5VI1qhjUZdEOW9I6SnioldGxEW6bkRDVQAaB+fAAAGAeykX+f4M/8AlZ9Mxw2T2Ui/zzBX/wAtU6SMbKcHDQ/U8B/j4uS/NQa6txkRrq3FvCt7ugxXc3qAAWCMAAAAAAAAAA9u8AA8L2ysr6cp31nRuZSacpTXu3ktnu1lLLxZlWxPQ6e2eG1lN/7qq0m9vFLd58uPaXAGtLSRS702m1DWSxLsW6eZktalUo1ZUq1OdOpF5SjJZNeVH8GmY9g9vi9qqc3CjcQ/+qvlu/NlltcfO1vXGnnF3b1rS5qW1xBwq03qyjnn9K2NeNbyHU0zoHWXcXaapbO26bzq0cn1PSHDan5N3SfmmjTjLMJbWK2jW/q8MvSRqZQwpPVcTsVX1mpzAAKpJAAAAAAAAAAAAAAAAAAKTwh9sLbmvrZWCz8IfbC25r62Vg5ut47jpqLgNJXRPuhtPjPos0gzfRPuhtPjPos0gpYXw15k3FeI3kAAUiWDN9Le6K7+NHoo0gzfS3uiu/jR6KJuKcNOZUwriO5EUACGXC88Hvamvz76MSyFb4Pe1Nfn30YlkOlo+A05mt47gADZNUFL05wh0riWKW1FRo1GurqL2Rm/xst6T8yfJmkXQ/itSpV6UqVenGrTmspRlua9fm2mvVU6Tst4+Bs0tQsD7+HiZKCRx/C6mFX7oSanTktalNPPOPI/Gtz+xpkcc05qtWynTNcjkum4AA+H0AAAFt0EwrOfXWtGElHONGMo57dznt2bNy35PN7GkyG0bwqeK4gqbjP2vTylXlFpNRz3Jvjfy8byaTNJSjFKMIKEIpKMFnlFLYks+JLYUcPptY7TduQm4hU6tug3evyAALpBB04bY3WI3kLSzpSq1pvYlxeN8iPXBMKvMYvo2llT1pPbKT97BcrZsGjGAWeBWfUqC160l+FrNe6m/qXiJ1fiLKVtk2uy+5o1tc2nSybXHNohoxa4Db671a17NfhKuW782PIvWcvCZpja6G6PTvZ6tS9rZwtKDfv58r/NW9/IuNE7jeJ2mDYTc4pf1Op21tTdSb48lxJcbe5I+StPtKb7S7SKtil3nCn7y3o55qlTW6Pl42+NnKpp1MiySLc1MHw5+J1CyS91N/n5fngRGJ311iWIV7++rSr3NebqVKkt8mz9wntrac/DpI5Tqwntrac/DpI34+8h+jORGsVEyNTAB1hyQAAAAAAAAAAAAAAAPyfvH5D9PyfvH5AEMjYDByJ2AAAAAAAAAAAABYdAO3c+Yl64l8KHoD27nzEvXEvhfw3g9TnsS4/QAA3zQB53Hwep8R+o9DzuPg9T4j9R5k7inuPvpzMmAByZ1oAAAPoz2MPcLfr9Jz/lUj5zPov2MHcPiC/SU/5VMwVPcOe9J/8AAXmhq4AJx+bAAAGB+ylX+c4I/wDl6nSRjJs/spl/m2Bv/gVelExgpwcND9SwD+Pj6/NQa6txkRrq3FvCt7uh9xXc3qAAWCMACOx3FqeEUKdepayuIzlqasauo1szzzyfIeZHpG1XO3Ie42LI5Gt3qSIKv2b2vgat++L/AMY7N7XwNW/fF/4zU7Qgz+Bt9nT5fEtAKv2b2vgat++L/wAZ+T02t3F6uEVVLibu01/LHaEGfwHZ0+XxLSCGw/SXCbvVg6s7eq0s41oqKzybeUk2sllx5N5rJE0002mmmtjTNmOZkqXYtzVkhfEtnpY/AAZDGCsaeYZ1W0WJUacVKglGs0ks4t5JvbtabS3N7d+SRZz+atKnXo1KFVuNOrCVObUU2oyTTaT48ns8ZgqYkljVpsU0yxSo4y/BlrYvZr/jw6SNSMrtKsrDEqdWpSbnQqpypv3LzT3eIsvZr+jf4/8ApJdBURwtVHqVK+mkmcisS5bwVDs1/Rv8f/SOzX9G/wAf/Sb/AOvg974KaHZ9R7vxQt4Kh2a/o3+P/pHZr+jf4/8ApH6+D3vgo7PqPd+KFvB/dxT6lXqUs89STjny5M/g3EW6XNNUstlAAB8ABWMS0s9p4jc2ftDX6hWnT1urZa2q2s8tXxGGaojhtprvM0NPJNfQS9izgqHZr+jf4/8ApHZr+jf4/wDpMP6+D3vgpn7PqPd+KFvBUOzX9G/x/wDSOzX9G/x/9I/Xwe98FHZ9R7vxQ8OEPthbc19bKwSmkOLdd7inV9r9R1IauWvrZ7c+REWRKl7Xyuc3cXKZjo4mtdvJXRPuhtPjPos0gzfRPuhtPjPos0gq4Xw15krFeI3kAAUiWDN9Le6K7+NHoo0gzfS3uiu/jR6KJuKcNOZUwriO5EUACGXC88Hvamvz76MSyFb4Pe1Nfn30YlkOlo+A05mt47gADZNUAAA4Mfw6OKYbK2fU41E9alOS95Lyrbk+P5NmaRmlanOjVnSqR1ZwbjJcjRrRWtOcKd1ReJ0m3WpQSqR1c3OCW/PliuXiW/YkS8QpdJNY3f4lXDqrRXVO3eBRwARS2D+6FKpXrQo0oOdSpJRhFcbexI/guuguFTtodc68Zwq1ItUU1llBrbLl2p5eR8eZmghdM9GoYZ5mwsV6kzgWG08LsIW6VKVXNupVgn7t8ub25bsls8mbefeAdNGxI2o1u5DmJHukcrnb1BK6NYFe47e9Qto6tKP/ANtaS9zBfW/EdOiWjV3j1zms6NnB/hKzX0R5X6jXcLw+0wyyhaWdJU6UOJb2+VvjZKxHE206aEe13yJNdiCQJoM2u+R44DhFlg1jG1s6eS3zm/fTfK2d7aim20ktrbP0oHCZpL1OMsEsanu5L/Ezi9y/I+3zcpzcEMlZNo3uq71IMMUlVLbxXepVOF/SR4zY3trazftGhSnq5f7SWT915OT7zBzT9IO0d7zMvUZgW62FkGjGzciH6TgsTYoFY3cig6sJ7a2nPw6SOU6sJ7a2nPw6SNNneQrP7qmpgA6w5EAAAAr+lWOXGE3tChQpU5qpQVRuee/Wkv6URHZjfd7UPpNN9fCxytXwN1lBM9qOTxLuCkdmN93tQ+kdmN93tQ+k89oweZ67Nn8i7gpHZjfd7UPpHZjfd7UPpHaMHmOzZ/Iu4KR2Y33e1D6R2Y33e1D6R2jB5js2fyLufk/ePyFJ7Mb7vah9J+PTC+ay9rUPpHaMI7Nn8itMAHPnQgAAAAAAAAAAAFh0B7dz5iXrRfCicH6/zqp+ry6US9l/DeD1OfxLj9AADfJ4PO4+D1PiP1Hoedx8HqfEfqPMncU9x99OZkwAOTOtAAAB9E+xg7isRX6Rl/LpnzsfRHsX+43El+kX/LgYKnhnP+k3+A7mhrQAJx+agAAGDeynX+ZYE/8Ag1ulExY2r2U6/wAfgD/4Vf1wMVKUHDQ/UfR/+Oj6/NQa6txkRrq3FzCt7uh6xXc3qAAWCMCs8IXa23576mWYrfCCv8noy5LhL/pka1bwHG1RcdpRgAc0dMAAAC8aD4tUureWH3NSc6lCK6i3HP8AB7mm/FsSzz2PLYkkUcntBvbHX1dRz1OpS6tl+Rs3/taps0j1ZM22djWq2I+F18rl/AB0pzAAABmOkLqPHb+VV5zncTlJ8rcm/rOAkdJe315zrI45SRLPVDrY1uxF8gADwewAADZL/wCHXHOy9bPA97/4dcc7L1s8DrGd1DkpO8oAB6PAMy0k7osS/W6vTZppmWkndFiX63V6bJGK+x1+hYwn2+n1I8AEgsAAAAAAEron3Q2nxn0WaQZvon3Q2nxn0WaQXML4a8yHivEbyAAKRLBm+lvdFd/Gj0UaQZvpb3RXfxo9FE3FOGnMqYVxHciKABDLheeD3tTX599GJZCt8Hvamvz76MSyHS0fAaczW8dwABsmqAAAAm0002mtzT3AAFB0vwbrdcq6toT9qVXlm0soTyzcdnE9rW7ZmtuWZAGr3ttQvLWpbXENenUi01nk1yNeNPJ/JxmdV8Fv6WMxwtUXKtNp08tqlF7dbNZrJLNvkyee5nP1tLqn3buU6Kiqtcyzt6HvonhSxPENaqou2oZSqRk2tfbsistu3j3bE9qeRojybbUYxze6MVFLyJbEcuE2VPDsPp2dKTlGDbcnHVcm97a5d3G9yXEdRVo6bUs271JNbU69+zcgLPoXonXxqorm51qNhF7ZbnU8UftOvQfQ6piThiGJwlTst8Ke6VX7I+s1GlThSpxpUoRhCCyjGKySXIibiWKpFeKFdviuX9nN1+IpHeOLfnkfxZ21C0tqdtbUo0qNNZRhFbEj1BwY9iltg+GVL65fuY7IxT2zlxRRzLWukdZNqqQERz3WTaqkXp1pFDA8O1KMk76umqUd+quOT+rx/KY/UnKpUlUnJynJtyk3m23xnTjGI3OK4jVvrqWtUqPct0VxJeJHIdrh9E2ljt7S7zq6KkSnjt4rvOHSDtHe8zL1GYGn6Qdo73mZeozA0sU4jeR1GFcN3MHVhPbW05+HSRynVhPbW05+HSROZ3kKT+6pqYAOsORAAAKTwjdtrT9UX8yZWCz8I3ba0/VF/MmVg5ip4zuZ1NLwW8kAAMBnAAAAAAAAAAAAAAAAAAAAAAAALJwer/Oa36tLpRLyUfg7X+b3PitX04F4L+G8Hqc/ifG6AAG+Twedx8HqfEfqPQ87j4PU+I/UeZO4p7j76czJgAcmdaAAAD6H9i/3H4mv0g/5cD54Pob2L3clii/5/wD7cTBU8Mgek38e7mnzNcABOPzQAAAwn2VC/wAZo+/+HX9dMxM232VK/wARo8/zLj10zEilBw0P1H0e/jo+vzUGurcZEa6txcwre7oesV3N6gAFgjAr+n6/+PwlyXUF/wBEywEdpThl3imAuhZQpTqxuqc3GdaFN6upUWa1ms963cpq1qKsDkT82m1QqiTtVfzYZmCf7D9IO9KH75R/vHYfpB3pQ/fKP95z2qfkp0WtZmhAAn+w/SDvSh++Uf7z+Z6I4/CDm7Si0lm8rui35lLafdU/JRrWe8hBF10Cw10rapiVXNTq+4pJSa9wtrbWXG8stv4r2bUz+cI0RhSnGtiFWNVrb1KCeruWWb2NvNvZlls3tMtMUoxUYpJJZJJbEilRUTkckj0tYmV1a1WrHGt7n6ACwRgAeV5cQs7Ovd1FBxoU3NqeerJrdF5cryj8p8c5GtVy+B6Y1XORqeJmuPpxx2/i6iqatzUjrRex5SazXiOEA5NVutzrUSyWAAPh9AAANkv/AIdcc7L1s8D3v/h1xzsvWzwOsZ3UOSk7ygAHo8AzLSTuixL9bq9NmmmZaSd0WJfrdXpskYr7HX6FjCfb6fUjwASCwAAAAAASuifdDafGfRZpBm+ifdDafGfRZpBcwvhrzIeK8RvIAApEsGb6W90V38aPRRpBm+lvdFd/Gj0UTcU4acyphXEdyIoAEMuF54Pe1Nfn30YlkK3we9qa/PvoxLIdLR8BpzNbx3AAGyap+Ota0Mqt9WlRtk/wlSMNZwXLlxpceW3I7sUwy6w9051VGpQrRU6Fem86dWL2pxf1byA0n7Q3fNk1wE6YWt1RehOkU1Wt6vwB1Vmk/wDd58XLH5VyImVla+mlTZdLbjJJC9KZZ2JfRXanls2pyOcFy0t0IucP17vC9e5tVtdPfUpr+pfT6ymm7BUR1DdKNbmtDOyZukxbg/HCi2pu3pOqtkauXu4p74+NPJPbnllsyzef6fsYynJRjFyk3kklm2zKqIu8zI5W7j8L/oNoZ1TqeJYxSyh76lbyXvvHJcni8526DaGRtOp4li1NSuPfUqD2qn45cr8XF5d15OcxLFr3igXmv2+5Br8S3xxLzX7H4kkskskj9AOdIR/FerToUZ1q04wpwi5SlJ7ElvZjWmmkFTHcScouUbSlnGhB8n5T8bJrhI0nje1p4Ph9VSt6U3G4nF7JzT2x8ia2+NeIpB1OD0Grbrn713eSf2dHhtFq01r02ru8gAC6Vzh0g7R3vMy9RmBp+kHaO95mXqMwImKcRvIuYVw3cwdWE9tbTn4dJHKdWE9tbTn4dJE5neQpP7qmpgA6w5EAAA9qd1dU4KFO5rQit0YzaSP69vXvfdx84znB50Gr4HrTcnidHt6977uPnGPb1733cfOM5wNBuQ03ZnR7eve+7j5xj29e993HzjOcDQbkNN2Z0e3r3vu4+cY9vXvfdx84znA0G5DTdmUrhGq1a2L0JVqk6klQSTlJt5az2fSVcsvCD21o8z9bK0c3VpaZx01It4W8gADXNgAAAAAAAAAAAAs/Byv82u/FaP8AmQLsUrg47a3v6m/5lMupew3g9SBifG6AAFAnA87j4PU+I/Ueh53Hwep8R+o8ydxT3H305mTAA5M60AAAH0J7F5//ABXFV/z3/bifPZ9CexdT7FcVeTyd8knxe8iYKjhkD0l/j3c0+ZrwAJx+aAAAGGeypX4XR1/m3P8A2jEDcPZVL3Wjj8V1/wBow8pU/DQ/UPR7+Oj6/wD0oNdW4yI11bi5hW93Q94rub1AALBGAAAAAAAAAAAAAAABUdPcTy1cMozebynXSzXjjF7dvFLd+TtJTSbHaWF0nQo5VLycE4JNNUs2snJZcazyXjT3b8/rVKlarOrVnKpUnJynOTzcm97b42ScQqkVNUzqWMPpFRda/ofwACOWAAAAAADZL/4dcc7L1s8D3v8A4dcc7L1s8DrGd1DkpO8oAB6PAMy0k7osS/W6vTZppmWkndFiX63V6bJGK+x1+hYwn2+n1I8AEgsAAAAAAEron3Q2nxn0WaQZvon3Q2nxn0WaQXML4a8yHivEbyAAKRLBm+lvdFd/Gj0UaQZvpb3RXfxo9FE3FOGnMqYVxHciKABDLheeD3tTX599GJZCt8Hvamvz76MSyHS0fAaczW8dwABsmqRuk/aG75szalUqUqsKtKcqdSElKE4vJxa3NPiZpOk/aG75szQhYnxk5fcvYXwV5/RD6l4G9OKel2BKheVV13tIqNzFpLqi4qiy2bePkfiyJHSzQu0xXXurHUtbx7XkvcVH41xPxr6T5f0Tx6/0ax63xfDqjjVpS91HPJVIfjQl4n9j3o+t9FMesNJcCt8Yw6bdGtHbGSylCS3xa5UyIrpKZ+siWxx+N4e/Dp9fBsY74LlyyMcu8KxC1xFYfWtKsbpvKNNLNy5MuVeQ0vQjRClhMY3t/GNW/azS3xo+Jcr8fm8dqlSpyqRqypwc4Z6smtsc9+T4j+zYq8XlqI0YiWz8/wCiVU4nJMzQRLZgAEkmAzPhy09WjWFPBsMqvrveU37uL+D03sc/jPal8r4lnaOETS2y0P0dqYlc5VLiWcLWhntq1OJeJLe3yeNpP5MxjEr3F8UuMSxCvKvdXE3OpOT3vk8SS2JcSSRs08Wkuku46f0ewj9U/Xyp6ibvNfsn54l70P7nrb9rpMlyI0O7nbb9rpMlzt6fgt5IWanjO5qAAZjCcOkHaO95mXqMwNP0g7R3vMy9RmBExTiN5FzCuG7mDqwntrac/DpI5Tqwntrac/DpInM7yFJ/dU1MAHWHIgAAAFR0wxbELHFIUbW5dOm6Kk1qp7c3yrxEN2R4139L0I/YaMmIRxuVqouw348OkkYjkVNpo4M47I8a7+l6EfsHZHjXf0vQj9h47UiyX86nvsuXNPzoaODOOyPGu/pehH7B2R4139L0I/YO1Isl/Oo7LlzT86Gjgzjsjxrv6XoR+wdkeNd/S9CP2DtSLJfzqOy5c0/Oh38IPbWjzP1srR0399dX9WNW7qurOK1U8ktnyHMR55EkkVyeJZgjWONGr4AAGIygAAAAAAAAAAAFl4O6tKni9zGpJRlUtXCmnxy14PLzJl4M00Yu4WWPWlxUdONPX1Jyms1CMk4uXyJt/IaUmmk0809qLeFvvGrclIeKMtIjs0P0AFMlgNJpqUVJPem8s/EAFS6WU+otluhleJWdfD72paXEdWpB78mlJb1JZ7cmsmvKcxqeKYfaYlRVK7pKpqpqEt0obHufleeW5vLNMgamhdrOs+p4hWo0tVZKVJVJZ8fHHYQJcOlavq7UL8OIxPT1tilKBbuwt9Uy65Lqf5XUNvm1vrPejoZaQrS6tf161LVerq01TkpePbLZ/wC7DElFOvsmZa2BE7xUsPs7nELynZ2dGVWtUeUYrZ4223sSSzbb2JJtn0/wHYfHDNDJWkZqerdTzmlsk9WObWxPLPPLPblkuIyvDcPtMOpyhZ0VTUvfPPNy8rZt/B7aSs9E7NTWU6qdV/tPNfRkeMQpUp6e7l2qpyvpHXpNAjG7rlgABAOJAAAMM9lTNOpo7T40rl+fqX2GIGg8PuOwxnhAr0KE9ahh1NWscp5xc025vxPN6v7JnxUhTRYiH6tgsKw0MbHb7X/2t/qDXVuMiNdW4tYVvd0PGK7m9QACwRgAQem11c2uD052tzWoSdxFN05uLa1Zchinl1Uavtexmgi10iMva5OAzDrxi/hW+/eJ/aOvGL+Fb794n9pO7VT3fiUeyl974GngzDrxi/hW+/eJ/aOvGL+Fb794n9o7VT3fiOyl974Gnn7FOUnGKcmlm0try5TMIY1jMJa0MWv4vdmrmafrOS5r17mq6txWqVqj3zqScm/lZ8XFcm/E+phWbvgaRd45hNrBSq31KecXJRpPqknk8stm5/Ga3FaxnS2vXzpYbCVtT2p1JNOcltWaW6OxrlaazTKwDUlrpZNl7J5G5DQQxbbXXzP2TcpOUm22823xn4AaZuAAAAAAAAAGyX/w6452XrZ4Hvf/AA6452XrZ4HWM7qHJSd5QAD0eAZlpJ3RYl+t1emzTTMtJO6LEv1ur02SMV9jr9CxhPt9PqR4AJBYAAAAAAJXRPuhtPjPos0gzfRPuhtPjPos0guYXw15kPFeI3kAAUiWDN9Le6K7+NHoo0gzfS3uiu/jR6KJuKcNOZUwriO5EUACGXC88Hvamvz76MSyFb4Pe1Nfn30YlkOlo+A05mt47gADZNUjdJ+0N3zZmhpek/aG75szQhYnxk5fcvYXwV5/RAX7gZ04lolj3te9q1HhF5JRrxTzVKW5VUvFueW9cuSRQQTXNRyWU26mnjqYnRSJdFPuCnONSEZwkpRks4tPNNcp/RinsedOlWpQ0QxSrJ1YJuwqSeetFLN0vk3rxZrZks9rJcjFY6yn5ViFDJQzrE/ouaZg5MYxGywjDLjEsRrxoWtvBzqTlxL629yXGzqbSWb2I+bOHPT56R4m8FwqunhFpP3U4PZc1F+NnxxW5cu17dmXqKNZHWM2FYa/EJ9BNjU3r5fdSrcI2l17pjpFUxCu5QtoZwtKDeylTz6T3t/UkVoApIiIlkP1KKJkLEjYlkQ0bQ7udtv2ukyXIjQ7udtv2ukyXOpp+C3khzNTxnc1AAMxhOHSDtHe8zL1GYGn6Qdo73mZeozAiYpxG8i5hXDdzB1YT21tOfh0kcp1YT21tOfh0kTmd5Ck/uqamADrDkQAACiaf9u6fMR9ciul10qwDFMUxKNxZUKU6caSg3K4pweebe6Uk+NET2HaQd62/wC+0f7znKqN6zOVEOkpJGJC1FXwIAE/2HaQd62/77R/vHYdpB3rb/vtH+8wap+SmxrWe8hAAn+w7SDvW3/faP8AeOw7SDvW3/faP941T8lGtZ7yEACf7DtIO9bf99o/3jsO0g71t/32j/eNU/JRrWe8hAAn+w7SDvW3/faP94Wh2kLeUbOjJvco3dFt+RKe0+ap+Sn3WszQgAAeD2AAAAAAAAAAAADRtFMS65YZFzk3Xo5Qq55vN8Um23m3ln5c9mRnJ2YNiNxhd9G7t2m0nGcHunF70/8A3Y0nvRs0s6wSaXh4mtVU6Tx6Pj4Gog4sIxK2xO26tbyzcclOL3xb5fpO06Nj2vTSauw5p7HMXRcm0AA9HkAAAAEhgWD3+M3at7Ki5Ze/qPZGC5Wzy97WNVzlsh5c5GJpOWyHrorg9XGsYpWkU1ST1q0l+LBb/le5eU26nCNOEYQioxikkluSIvRjA7XAsPVvQ93Ultq1Wts39S5ESxxuJ1v6qT1e6m77nLV9X+ok2bk3AAE00AU/hX0xo6H6M1LiEoSxG5Tp2dJva5ZbZtfkxzzfyLjPbhB06wXQ6xc7yoq99OOdCzpy93U5G/yY/nPkeWb2Hy9pbpFielGNVcVxWtr1p7IQjshSgt0IriS+1va2bEEKuW67jo8DwV9W9JZUtGnx8uWZFVZzq1JVKk5TnNuUpSebk3vbZ/IBQP0cGurcZEa6txWwre7oSMV3N6gAFgjArvCB2kpfrMejIsRXeEDtJS/WY9GRqV/+O7p8zcoP8hvX5FEABzh0gAAAAAAAAAAAAAAAAAAAABsl/wDDrjnZetnge9/8OuOdl62eB1jO6hyUneUAA9HgGZaSd0WJfrdXps00zLSTuixL9bq9NkjFfY6/QsYT7fT6keACQWAAAAAACV0T7obT4z6LNIM30T7obT4z6LNILmF8NeZDxXiN5AAFIlgzfS3uiu/jR6KNIM30t7orv40eiibinDTmVMK4juRFAAhlwvPB72pr8++jEshW+D3tTX599GJZDpaPgNOZreO4AA2TVI3SftDd82ZoaXpP2hu+bM0IWJ8ZOX3L2F8Fef0QAAnFI9LatWtrincW9WdKtSmp05weUoyTzTT4mmfVfBJprS0x0dVSrqwxK1yp3dNcb4prxSyfkea4s38oEtoppDiejGLxxTCayp14wlBqSzjKLW1Nca3PypGKWPWJ5kjGMLbiEOimxybl+nJTavZAafdb7apophNVe268P8bVi9tKm17xfnSW/kXl2fP56XVetdXNW5uKsqtarNzqTk83KTebbfLmeZ6jYjG2Q2MOoI6GBImb/Fc1AAPZvmjaHdztt+10mS5EaHdztt+10mS51FPwW8kOVqeM7moABmMJw6Qdo73mZeozA0/SDtHe8zL1GYETFOI3kXMK4buYOrCe2tpz8OkjlOrCe2tpz8OkiczvIUn91TUwAdYciAAAAAAAAAAAAAAADowztla89DpI5zowztla89DpI8v7qnpneQxoAHJnXAAAAAAAAAAAAAAAHTh17dYfcxubOs6VReJNNZ55NPY1mlsezYW/C9LrOtHVxCDtamTevFOVN7342uJJbeVtFHBmhqJIVuxTBNTxzJZ6Gs0K1GvDqlCrTqw1nFShJSTa35Nb96856GTW9atb1VVt6tSlUWaUoScWs9j2omsL0ux3DupKjcUakabzUa9tTq5+Vyi2/OUm4ps9ZpMkwp3sO/2aDTpzqTUKcJTk9yis2TOHaKY/fNOnh1WnF/jVvwa+nb5iqWfDZpVbJRp4fgmrxxVtOOfmmiUp8PWNqPu8Cw+UuWM5petmvLis26NidVv9iVNQ4imxjE/3/wANEwTg7oU3Gri106zX+yo5qPyy3v5Mi7WVpbWVvG3tKFOhSjujCOSMDqcPWPNfg8Ew2L/OlN/WjkqcOul0n7mwwWK5Oo1H/wBwkVDqmoX9xfsTJcCxSoX9y3+z6OB8u4hww6d3VTWpYlQs4/kULWGXnmpP6SrYvpNpFi8ZxxPG8Quqc3nKnUuJOHo55LzGBKV3ipki9Eqh3Eeicrr9j6l0k090SwBTjiGNWzrRzToUZdVqZricY56vy5IyXTPhxxC8jO20Ys+t9J7PbNdKdVrxR2xj8ut8hjoM7Kdjd+0u0fo1SU66T/XXz3f6+9z2vLm5vLqpdXdercV6j1p1Kk3KUnytveeIBnOgRERLIAAD6DXVuMiLKtMcQ72tfNL7TfoahkKu0/En19O+ZG6HgXgFH7McQ72tfNL7R2Y4h3ta+aX2lHtGDMm9nT5F4K7wgdpKX6zHoyInsxxDva180vtOHGsfusVtY21ajRhCM1POCeeaTXG/Ga9VWxSRK1q7TZpKKWKVHOTZ/REAAjlkAAAAAAAAAAAAAAAAAAAAA2S/+HXHOy9bPAqFTTetUqSqVMPp68m5S1ajSzfJsP57NKng+Pzv3F9uIQo1Euc+7Dp1cq2LiCndmlTwfH537h2aVPB8fnfuPvaMGZ87NnyLiZlpJ3RYl+t1emyc7NKng+Pzv3FZvrid3e17uooxnWqSqSUdycnm8vOT6+oZNo6HhcoUFNJBpafjY8QATyiAAAAAASuifdDafGfRZpBlWG3c7G9pXdOMZTpttKW57Mid7Mb/AL2tvNL7SnQ1UcLFR+ZLrqWSZ6KzIvAKP2Y3/e1t5pfaOzG/72tvNL7Td7RgzNHs6fIvBm+lvdFd/Gj0USHZjf8Ae1t5pfaQWJXc769qXdSMYzqNNqO5bMvqNKuqo5mIjMzeoaWSF6q/I5wATCoXng97U1+ffRiWQz3AMflhNrOhG1VbXnr5ueWWxLk8RI9mlTwfH537i1T10UcSNcu1CJU0M0krnN3KXEFO7NKng+Pzv3Ds0qeD4/O/cZu0YMzD2bPkT+k/aG75szQseKaU1L2wq2vtKNPqiy1uqZ5fJkVwl1szZpEc3Iq0MD4Y1a/MAA0zcAAAAAAAAANG0O7nbb9rpMlyh4RpPPD8Pp2is41FTz911TLPNt8njOvs0qeD4/O/cXIa+FkbWqu5EIU1BM+RzkTepcQU7s0qeD4/O/cOzSp4Pj879xk7RgzMfZs+RY9IO0d7zMvUZgWXENLKl3Y1rb2lGHVYOOt1TPLP5CtEyunZM9FYU6GB8LFR4OrCe2tpz8OkjlPW1quhdUq6jrOnNTy5cnmajVs5FNxyXaqGsAp3ZpU8Hx+d+4dmlTwfH537i92jBmQOzZ8i4gp3ZpU8Hx+d+4dmlTwfH537h2jBmOzZ8i4gp3ZpU8Hx+d+4dmlTwfH537h2jBmOzZ8i4gp3ZpU8Hx+d+4dmlTwfH537h2jBmOzZ8i4gp3ZpU8Hx+d+4dmlTwfH537h2jBmOzZ8i4gp3ZpU8Hx+d+4dmlTwfH537h2jBmOzZ8i4nRhnbK156HSRRuzSp4Pj879x/dHTitRrQq08Pp68JKUdaq2s1t27D47EIVRUufW4dOiotioAAgHQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH7FOTSSbb2JIkKWB4tUhrxsK2X5yyfmZY9BMNpRtXiNSClUnJxpt/ipbG1488zrvNKsNt7iVFRr1dV5SlCKy+TN7SjFRxpGj5XWuTpayTWKyJt7FHu7S6tJqNzb1KTe7Xjln5DwNPhKxxvDM0lVoVFk01k4v6mjOMRtpWd9WtZPN05uOfKuJmKqpdTZzVuimWlqtddrksqHOettb3FzNwt6FStJLNqEXJpfIeRZeD3tpccx/UjBBGkkiMXxM08ixRq9PAhutWJ+Drv5mX2DrVifg67+Zl9hoGKYzY4bWjSupTUpR1lqxz2HJ2VYR/vKvzbKDqKnatlk2mg2tqHJdI9hRbmzu7aKlcWtaim8k5wcc/OeBZdL8YssStaFO1lNyhNyetHLZkVonzsYx9mLdDfge97LvSyn9QjKc4whFylJ5JJZts6+tWKeDrv5mX2H8YP22s+fh0kaViN7QsLV3Nw5Kmmk8lm9ps0tKyZquctrGvVVT4XNa1L3M3eFYmv8A9dd/My+w561GtRlq1qVSnLknFp/SX1aVYO3tq1V5abO+4pWWMYdk3GrRqrOM1xPlXIzN+gjei6t91MH6+ViprGWQy8HrdUZW9zVt5++pzcH5U8jyJipZbKVEW6XQ644ZiMoKcbC5cGs1JUpZNcu45DRdDrr2zgVFN5yot0n8m76GijY3be08WubdLJRqPV+K9q+ho2p6ZI42yNW6KakFSskjo3JZUOSMXKSjFNtvJJcZ01sOv6NOVSrZXNOEd8pUmkvlOvRS29s49bRazjTfVJfJtX05Fl0+uupYXTtk/dV57fix2+vIRUyOhdK5dx9lqVbM2Jqbyin90aVWvVVKjTnUqS3Rgs2/kP4JfQ7uktP2+hI14mab0bmpsSv0GK7JCPubO7toqVxbVqKk8k5wcc/OeBdOET4Ha84/UUsyVMKQyKxDFTTLNGj1QH7CMpyUYRcpN5JJZtn4aFoxhFHDLJXFeMfbM4605S/EXJ4vGfaandO6ybj5U1LYG3XapT4YFi84a6sK2XjWT8zOG4oVreo6delOlNfizi0y+VdK8JhX6kpVppPLXjD3Prz+g7b+0ssaw1LOM4TjnSqrfF8q+w3FoYnouqfdUNNK+ViprWWRTMgelxSnQr1KFRZTpycZLxo8yWqW2FVFvtPa2tLq51va1tWravvupwcsvMe3WrE/B138zL7Cx8HPvb7y0/6iaxHHsPsLp21xOoqiSbyhnvKMVHG6JJHutcmzVkjZVjY29ihdasT8HXfzMvsPG5tbm2cVc29Wi5bteDjn5y99lWEf7yr82yuaYYpaYnVtpWspNU4yUtaOW/I8TU8LGKrH3UyQVE73o17LIQIANE3gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC/6DXEKuBxoprXoTlGS8rbT+n6CLxbRGv1adWwqwnCTbVOexrxJ7n9BX8LxC5w256vbTSeWUovapLkZbLDS+zqJRvKNShLjlH3UftK0U0E0aRy7FQkywzwSrJFtRSBpXWN4DTlb9TlQjOWt7uCaby4nu4iMvLmteXM7mvJSqT980kuLLiNOhUssTs5akqVzQnsa3r7mZ1j1j1uxStaptwTzg3+S932GGrp3RMRUddplo6hsr1u2zjgLLwe9tLjmP6kVosvB720uOY/qRgo+O0z1vAcdumeF399f0alpburGNLVbUksnm+VkF2O4z3jL04/aXLGsdtsKuIUa1GrOU4aycMst+XGzg7MbDva580ftKE8NM6RVe+y/nkaEE1U2NEYy6fnmVC/sbuxqRp3dF0pSWaTaea+Q5iX0oxWjit1Sq0adSChDVanly+IiCVK1rXqjFuhVic9zEV6WU6sH7bWfPw6SLzppCdTApxpwlOWvHZFZveUbB+21nz8OkjS8QvLewtncXMnGmmk2k3vKVA1HQvRVshNr3K2Ziol1MxjZ3knlG0rt+KmzQNErSvZ4LTpXEXCbk5ar3xT4jsw7ELPEKTqWlZVFF5SWTTXlTK/pfjN9auVlTt3RjUWytnnrLjy5DLHDFSJrdK5ikmlq11OjYrGNVY1sXu6sHnGVaTT5VmcYBFc7SVVLLW6KIhaeD261bq4tJPZOKnHyrY/X9B/HCBbdTxChdJbKsNV+WP3NeYh8AuvaeMW1dvKKmlLyPY/WXLTe26vgcqiWcqE1NeTc/X9BTi/dpHN8W/n3Jsv7VY13g7/n2I3g8ttt1eNclOL+l/UcGnN11fGuop+5oQUfle1+teYs2i1GNlo7RnU9zrRdab8T2+rIz+8ryuburcT99Um5P5WfKj9qmZHntPtP+7VPky2HkS+h3dJaft9CREEvod3SWn7fQkaVPxW80+Zu1HCdyX5E7wifA7XnH6ill04RPgdrzj9RSzPiHHXoYMO4CdTv0foK4xq0pSWcXUTa5Utv1Fx04uZUMEcIPJ1qig8uTa36iq6ItLSK0b5ZL/pZYuEJPrXby4lWy/wClmem2Uj1TeYKn1quNF3FHJbC8fvcOsZWtuqbTk5KU1m458SIkcWZOZI5i3atii+NsiWclz1uq9W6uJ3FeWtUm85PJLPzHkAeVVVW6npEREshb+Dn3t95af9R56V4PiV5jM69tayqU3CKUlJLi8bPTg597feWn/USmLaR2mG3srWrQrTkknnHLLb8pZjZG+kaki2T+1I0j5GVbljS6/wBIVHsdxnvGXpx+04b20uLOu6FzTdOoknqtp7PkLj2Y2He1z5o/aVnSK/pYliTuqMJwi4qOUss9hpVEVO1t43XU3aeWoe+0jbIRoANI3QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADQsBs8Ou8BoTVpQUp0tSclTWtmtjefKUfEbC5sLmVC4pyTTyUstklyokdGMdeFzlRrRlUtpvNpb4vlRb6WP4RUhrK+prxSzi/pKyNhqo23doqhIV01LI6zdJFInQGzuqFK4uK0JU6dXVUFJZa2We3L5SJ06nGeOuMd8KUYy8u1/WiwYnpTh1vSkrabuauWxRTUU/G39RRbmtUuLipXrS1qlSTlJ+M8VT42QpCxbmSlZI+ZZnpY8yy8HvbS45j+pFaJzQ2/tMPv61W7q9ThKlqp6re3NciNSkcjZmqptVbVdC5EQ7tPaFeriVB0qNSolRybjFvjZXPad33rX+bZf+yXBO/f4U/sHZLgnfv8Kf2FCangler9Ym3kaENTPExGatdnP7GfVbevSjrVaFWEc8s5QaR5Ft0vxjDr/C40bS46pUVVSa1JLZk+VeMqRNnjbG/Rat0KVPI6Rmk5tlOrB+21nz8Oki76cdoKnOR9ZRsNqQo4jbVaj1YQqwlJ5bkmsy06VY1hl7hE7e1ueqVHOLUdSS3Pxo2qV7WwSIq7VNSqY508aomxCv6PYjLDMShXzfUpe5qrlj928vePWFPFcLlSjqueWvRl4+L5GZmW/RbSG1t8OVriFZ05UnlTlquWceTYnu+w+0M7bLFIuxT5XQOuksabUKjKMoycZJqSeTT4mfhK6T1LCvicrnD6yqQqrWmtVxylx71x7/ORRoyN0XK1Fub8btNqOVLA0zDKkMU0fp9UearUdSflyyf0mZlq0PxuzsbGrbXtfqaU9an7lvNNbVsXi+k3MPlayRUcuxUNPEInPjRWptRSZ0srxstHqlOn7nXSowXie/6EzPCxaZ4tbYjK3pWdXqlKCcpPVa2vy/8Au0rp5r5Ukl9Xch6oIlji9ZNqgl9Du6S0/b6EiIJHRq5oWeN29xcT1KUNbWlk3lnFri8prwKiStVc0NidFWJyJkpY+ET4Ha84/UUss+meK2GIW1vCzr9VlCbclqSWSy8aKwZq5zXTKrVuYKFrmwojksdGHXDtL+hcrb1OopNcqz2mh47ZrFsGnToyi5SSqUpcTe9edeszQsmjOkftGkrS9Up0F7ya2uHi8aMlFOxt45Nynitge7Rkj3oQVS0uoXHtedvVVXPLU1XmXzRvCI2mDdQvKMJzqy16kJJNLkR0Rx3CJQ11f0svHmn5t5BaRaUUqlvO1w1yeuspVmssl4uP5TZjjgprvV1zVkknqrMRtit4s7eWJXDtYKFDXagluyXGcoBIct1VSw1LIiFv4Ofe33lp/wBRw6Z21xUx2pKnQqzjqR2xg2tx/eheJ2OHK79uV+pdU1NX3LeeWtnuXjLF2S4J37/Cn9hWjSKWmaxz0T8UkSLLFVOkaxV/4hQPad33rX+bZ/FWhWpJOrRqU892tFrM0LslwTv3+FP7Cv6Z4pY4hRto2dfqrhKTl7iSyzy5Ua81LExiua9FXobMNVM96NdGqJ1KyADQN8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//Z" style="height:38px;width:auto;object-fit:contain;filter:brightness(0) invert(1)" alt="Uptime Service">
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
