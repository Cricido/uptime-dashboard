"""
Uptime Service — Dashboard Server
Flask + SQLite backend
"""
from flask import Flask, request, jsonify, render_template, abort
from flask_cors import CORS
import sqlite3, json, os, hashlib, secrets
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
CORS(app)

DB = os.path.join(os.path.dirname(__file__), "dashboard.db")
API_KEY = os.environ.get("UPTIME_API_KEY", "uptime-sos-2025")  # cambia in produzione

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS machines (
        id          TEXT PRIMARY KEY,
        pc_name     TEXT,
        user        TEXT,
        domain      TEXT,
        ip          TEXT,
        os          TEXT,
        rustdesk_id TEXT,
        last_seen   TEXT,
        status      TEXT DEFAULT 'online',
        cpu         REAL DEFAULT 0,
        ram         REAL DEFAULT 0,
        disk        REAL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS tickets (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        machine_id  TEXT,
        pc_name     TEXT,
        user        TEXT,
        ip          TEXT,
        rustdesk_id TEXT,
        description TEXT,
        screenshot  TEXT,
        status      TEXT DEFAULT 'open',
        priority    TEXT DEFAULT 'normal',
        created_at  TEXT,
        updated_at  TEXT,
        note        TEXT DEFAULT ''
    );
    """)
    db.commit()
    db.close()

# ── Auth ──────────────────────────────────────────────────────────────────────
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if key != API_KEY:
            abort(401)
        return f(*args, **kwargs)
    return decorated

# ── API: Ricezione dati da SOS app ────────────────────────────────────────────
@app.route("/api/ticket", methods=["POST"])
@require_api_key
def create_ticket():
    data = request.json
    now  = datetime.now().isoformat()
    pc   = data.get("pc_name", "N/D")
    user = data.get("user", "N/D")
    ip   = data.get("ip", "N/D")
    domain     = data.get("domain", "N/D")
    os_info    = data.get("os", "N/D")
    rustdesk   = data.get("rustdesk_id", "")
    desc       = data.get("description", "")
    screenshot = data.get("screenshot", "")  # base64 PNG
    priority   = data.get("priority", "normal")

    machine_id = hashlib.md5(f"{pc}{domain}".encode()).hexdigest()[:12]

    db = get_db()
    # Upsert macchina
    db.execute("""
        INSERT INTO machines (id, pc_name, user, domain, ip, os, rustdesk_id, last_seen, status)
        VALUES (?,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            user=excluded.user, ip=excluded.ip, os=excluded.os,
            rustdesk_id=excluded.rustdesk_id, last_seen=excluded.last_seen, status='online'
    """, (machine_id, pc, user, domain, ip, os_info, rustdesk, now, "online"))

    # Inserisci ticket
    cur = db.execute("""
        INSERT INTO tickets (machine_id, pc_name, user, ip, rustdesk_id, description,
                             screenshot, status, priority, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (machine_id, pc, user, ip, rustdesk, desc, screenshot, "open", priority, now, now))
    ticket_id = cur.lastrowid
    db.commit()
    db.close()
    return jsonify({"ok": True, "ticket_id": ticket_id, "machine_id": machine_id})

@app.route("/api/heartbeat", methods=["POST"])
@require_api_key
def heartbeat():
    """Aggiornamento periodico stato macchina (CPU, RAM, disco)."""
    data = request.json
    now  = datetime.now().isoformat()
    pc   = data.get("pc_name", "N/D")
    domain = data.get("domain", "N/D")
    machine_id = hashlib.md5(f"{pc}{domain}".encode()).hexdigest()[:12]
    db = get_db()
    db.execute("""
        INSERT INTO machines (id, pc_name, user, domain, ip, os, rustdesk_id, last_seen, status, cpu, ram, disk)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            user=excluded.user, ip=excluded.ip, rustdesk_id=excluded.rustdesk_id,
            last_seen=excluded.last_seen, status='online',
            cpu=excluded.cpu, ram=excluded.ram, disk=excluded.disk
    """, (machine_id, pc, data.get("user",""), domain,
          data.get("ip",""), data.get("os",""), data.get("rustdesk_id",""),
          now, "online", data.get("cpu",0), data.get("ram",0), data.get("disk",0)))
    db.commit()
    db.close()
    return jsonify({"ok": True})

# ── API: Dashboard ────────────────────────────────────────────────────────────
@app.route("/api/machines")
@require_api_key
def get_machines():
    db = get_db()
    # Marca offline le macchine che non hanno heartbeat da 5 min
    threshold = (datetime.now() - timedelta(minutes=5)).isoformat()
    db.execute("UPDATE machines SET status='offline' WHERE last_seen < ?", (threshold,))
    db.commit()
    rows = db.execute("SELECT * FROM machines ORDER BY last_seen DESC").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/tickets")
@require_api_key
def get_tickets():
    status = request.args.get("status", "all")
    db = get_db()
    if status == "all":
        rows = db.execute("SELECT * FROM tickets ORDER BY created_at DESC").fetchall()
    else:
        rows = db.execute("SELECT * FROM tickets WHERE status=? ORDER BY created_at DESC", (status,)).fetchall()
    db.close()
    result = []
    for r in rows:
        d = dict(r)
        d.pop("screenshot", None)  # non inviare screenshot nella lista
        result.append(d)
    return jsonify(result)

@app.route("/api/ticket/<int:tid>")
@require_api_key
def get_ticket(tid):
    db = get_db()
    row = db.execute("SELECT * FROM tickets WHERE id=?", (tid,)).fetchone()
    db.close()
    if not row:
        abort(404)
    return jsonify(dict(row))

@app.route("/api/ticket/<int:tid>", methods=["PATCH"])
@require_api_key
def update_ticket(tid):
    data = request.json
    now  = datetime.now().isoformat()
    db = get_db()
    if "status" in data:
        db.execute("UPDATE tickets SET status=?, updated_at=? WHERE id=?",
                   (data["status"], now, tid))
    if "priority" in data:
        db.execute("UPDATE tickets SET priority=?, updated_at=? WHERE id=?",
                   (data["priority"], now, tid))
    if "note" in data:
        db.execute("UPDATE tickets SET note=?, updated_at=? WHERE id=?",
                   (data["note"], now, tid))
    db.commit()
    db.close()
    return jsonify({"ok": True})

@app.route("/api/stats")
@require_api_key
def get_stats():
    db = get_db()
    total_machines  = db.execute("SELECT COUNT(*) FROM machines").fetchone()[0]
    online_machines = db.execute("SELECT COUNT(*) FROM machines WHERE status='online'").fetchone()[0]
    open_tickets    = db.execute("SELECT COUNT(*) FROM tickets WHERE status='open'").fetchone()[0]
    closed_tickets  = db.execute("SELECT COUNT(*) FROM tickets WHERE status='closed'").fetchone()[0]
    urgent_tickets  = db.execute("SELECT COUNT(*) FROM tickets WHERE status='open' AND priority='urgent'").fetchone()[0]
    db.close()
    return jsonify({
        "total_machines": total_machines,
        "online_machines": online_machines,
        "offline_machines": total_machines - online_machines,
        "open_tickets": open_tickets,
        "closed_tickets": closed_tickets,
        "urgent_tickets": urgent_tickets,
    })

# ── Frontend ──────────────────────────────────────────────────────────────────
@app.route("/")
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", api_key=API_KEY)

@app.route("/api/demo", methods=["POST"])
def demo_data():
    """Inserisce dati demo per testare la dashboard."""
    now = datetime.now().isoformat()
    db = get_db()
    machines = [
        ("abc001", "DESKTOP-MARIO", "mario.rossi", "UPTIME.LOCAL", "192.168.1.10", "Windows 11 Pro", "123456789", now, "online", 45, 62, 78),
        ("abc002", "LAPTOP-GIULIA", "giulia.bianchi", "UPTIME.LOCAL", "192.168.1.11", "Windows 10 Pro", "987654321", now, "online", 12, 34, 45),
        ("abc003", "PC-CONTABILITA", "admin", "WORKGROUP", "192.168.1.20", "Windows 10 Home", "", (datetime.now()-timedelta(hours=2)).isoformat(), "offline", 0, 0, 0),
        ("abc004", "SERVER-FILE", "Administrator", "UPTIME.LOCAL", "192.168.1.1", "Windows Server 2022", "111222333", now, "online", 78, 88, 92),
    ]
    for m in machines:
        db.execute("""INSERT INTO machines VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen""", m)
    tickets = [
        ("abc001","DESKTOP-MARIO","mario.rossi","192.168.1.10","123456789","Il PC va lento, non riesco ad aprire Excel","","open","urgent", (datetime.now()-timedelta(hours=1)).isoformat(), now,""),
        ("abc002","LAPTOP-GIULIA","giulia.bianchi","192.168.1.11","987654321","Stampante non trovata in rete","","open","normal",(datetime.now()-timedelta(hours=3)).isoformat(),now,""),
        ("abc003","PC-CONTABILITA","admin","192.168.1.20","","Aggiornamento Windows bloccato","","closed","normal",(datetime.now()-timedelta(days=1)).isoformat(),now,"Risolto reinstallando Windows Update"),
        ("abc004","SERVER-FILE","Administrator","192.168.1.1","111222333","Disco quasi pieno - 92% utilizzato","","open","urgent",(datetime.now()-timedelta(minutes=20)).isoformat(),now,""),
    ]
    for t in tickets:
        db.execute("""INSERT OR IGNORE INTO tickets
            (machine_id,pc_name,user,ip,rustdesk_id,description,screenshot,status,priority,created_at,updated_at,note)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", t)
    db.commit()
    db.close()
    return jsonify({"ok": True})

if __name__ == "__main__":
    init_db()
    print("=" * 50)
    print("  Uptime Service Dashboard")
    print(f"  http://localhost:5000")
    print(f"  API Key: {API_KEY}")
    print("=" * 50)
    app.run(debug=False, host="0.0.0.0", port=5000)
