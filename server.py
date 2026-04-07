"""
Uptime Service — Dashboard Server v3
Flask + memoria — Auth multi-utente + 2FA TOTP
"""
from flask import Flask, request, jsonify, abort, Response, session, redirect, url_for
from flask_cors import CORS
import os, hashlib, threading, secrets, base64, time, hmac, struct
from datetime import datetime, timedelta
from functools import wraps
import urllib.parse

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
CORS(app)
API_KEY = os.environ.get("UPTIME_API_KEY", "uptime-sos-2025")

# ── Store in memoria ──────────────────────────────────────────
_lock     = threading.Lock()
machines  = {}
tickets   = []
_tid      = [1]
orgs      = {}
sites     = {}
depts     = {}
_oid      = [1]
_sid      = [1]
_did      = [1]

# ── Auth store ────────────────────────────────────────────────
users     = {}   # uid -> {id,username,password_hash,role,totp_secret,totp_enabled,created_at}
sessions  = {}   # token -> {uid, created_at, totp_verified}
_uid      = [1]

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

def _qr_svg(data):
    """Genera un QR code SVG minimale via API pubblica (URL encoded)"""
    encoded = urllib.parse.quote(data, safe='')
    # restituisce un URL per generare QR lato client con JS
    return encoded

# ── Crea admin di default ─────────────────────────────────────
def _ensure_default_admin():
    with _lock:
        if not users:
            uid = str(_uid[0]); _uid[0] += 1
            totp_secret = _totp_secret()
            users[uid] = {
                "id": uid, "username": "admin",
                "password_hash": _hash("admin"),
                "role": "admin",
                "totp_secret": totp_secret,
                "totp_enabled": False,
                "created_at": _now()
            }

# ── Session helpers ───────────────────────────────────────────
def _create_session(uid):
    token = secrets.token_hex(32)
    sessions[token] = {"uid": uid, "created_at": _now(), "totp_verified": False}
    return token

def _get_session(token):
    s = sessions.get(token)
    if not s: return None
    # scadenza 8 ore
    created = datetime.fromisoformat(s["created_at"])
    if datetime.now() - created > timedelta(hours=8):
        sessions.pop(token, None)
        return None
    return s

def _current_user():
    token = request.cookies.get("uptime_token") or request.headers.get("X-Session-Token")
    if not token: return None, None
    s = _get_session(token)
    if not s: return None, None
    u = users.get(s["uid"])
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
        # Accetta sia API key (per agenti) sia sessione web
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
    with _lock:
        user = next((u for u in users.values() if u["username"].lower() == username), None)
    if not user or user["password_hash"] != _hash(password):
        return jsonify({"ok": False, "error": "Credenziali non valide"}), 401
    token = _create_session(user["id"])
    resp = jsonify({"ok": True, "needs_2fa": user.get("totp_enabled", False), "token": token})
    resp.set_cookie("uptime_token", token, httponly=True, samesite="Lax", max_age=28800)
    return resp

@app.route("/api/auth/verify2fa", methods=["POST"])
def verify_2fa():
    d = request.json or {}
    code = d.get("code","").replace(" ","")
    token = request.cookies.get("uptime_token") or request.headers.get("X-Session-Token")
    s = _get_session(token)
    if not s: return jsonify({"ok": False, "error": "Sessione non valida"}), 401
    u = users.get(s["uid"])
    if not u: return jsonify({"ok": False, "error": "Utente non trovato"}), 401
    if not _totp_verify(u["totp_secret"], code):
        return jsonify({"ok": False, "error": "Codice 2FA non valido"}), 401
    s["totp_verified"] = True
    return jsonify({"ok": True})

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    token = request.cookies.get("uptime_token")
    if token: sessions.pop(token, None)
    resp = jsonify({"ok": True})
    resp.delete_cookie("uptime_token")
    return resp

@app.route("/api/auth/me")
def auth_me():
    u, s = _current_user()
    if not u: return jsonify({"ok": False}), 401
    return jsonify({"ok": True, "user": {
        "id": u["id"], "username": u["username"], "role": u["role"],
        "totp_enabled": u.get("totp_enabled", False)
    }})

# ── User management (admin only) ──────────────────────────────
@app.route("/api/users", methods=["GET"])
@require_api_key
@require_admin
def get_users():
    with _lock:
        return jsonify([{k:v for k,v in u.items() if k not in ("password_hash","totp_secret")} for u in users.values()])

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
    with _lock:
        if any(u["username"].lower()==username.lower() for u in users.values()):
            return jsonify({"error":"Username già esistente"}), 409
        uid = str(_uid[0]); _uid[0] += 1
        totp_secret = _totp_secret()
        users[uid] = {"id":uid,"username":username,"password_hash":_hash(password),
                      "role":role,"totp_secret":totp_secret,"totp_enabled":False,"created_at":_now()}
        return jsonify({"id":uid,"username":username,"role":role,"totp_enabled":False,"created_at":users[uid]["created_at"]})

@app.route("/api/users/<uid>", methods=["PATCH"])
@require_api_key
@require_admin
def update_user(uid):
    d = request.json or {}
    with _lock:
        if uid not in users: abort(404)
        if "role"     in d: users[uid]["role"]          = d["role"]
        if "password" in d: users[uid]["password_hash"] = _hash(d["password"])
        return jsonify({"ok": True})

@app.route("/api/users/<uid>", methods=["DELETE"])
@require_api_key
@require_admin
def delete_user(uid):
    with _lock:
        if uid not in users: abort(404)
        # non puoi cancellare te stesso o l'ultimo admin
        admins = [u for u in users.values() if u["role"]=="admin"]
        if users[uid]["role"]=="admin" and len(admins)<=1:
            return jsonify({"error":"Non puoi eliminare l'unico admin"}), 400
        users.pop(uid)
        return jsonify({"ok": True})

# ── 2FA setup per l'utente corrente ───────────────────────────
@app.route("/api/auth/2fa/setup", methods=["GET"])
@require_api_key
def totp_setup():
    u, _ = _current_user()
    # Anche con API key forniamo il setup per l'admin default
    if not u:
        # per chiamate da API key, ritorna per l'admin
        with _lock:
            u = next((x for x in users.values() if x["role"]=="admin"), None)
    if not u: abort(401)
    uri = _totp_uri(u["totp_secret"], u["username"])
    return jsonify({"secret": u["totp_secret"], "uri": uri, "username": u["username"]})

@app.route("/api/auth/2fa/enable", methods=["POST"])
@require_api_key
def totp_enable():
    d = request.json or {}
    uid = d.get("uid")
    code = d.get("code","").replace(" ","")
    u_caller, _ = _current_user()
    with _lock:
        target = users.get(uid) if uid else u_caller
        if not target: abort(404)
        # solo admin può abilitare per altri
        if uid and u_caller and uid != u_caller["id"] and u_caller["role"] != "admin":
            abort(403)
        if not _totp_verify(target["totp_secret"], code):
            return jsonify({"ok": False, "error": "Codice non valido"}), 400
        target["totp_enabled"] = True
        return jsonify({"ok": True})

@app.route("/api/auth/2fa/disable", methods=["POST"])
@require_api_key
@require_admin
def totp_disable():
    d = request.json or {}
    uid = d.get("uid")
    with _lock:
        if uid not in users: abort(404)
        users[uid]["totp_enabled"] = False
        users[uid]["totp_secret"]  = _totp_secret()  # rigenera segreto
        return jsonify({"ok": True})

# ── Org API ───────────────────────────────────────────────────
@app.route("/api/orgs", methods=["GET"])
@require_api_key
def get_orgs():
    with _lock:
        return jsonify(list(orgs.values()))

@app.route("/api/orgs", methods=["POST"])
@require_api_key
def create_org():
    d = request.json or {}
    with _lock:
        oid = str(_oid[0]); _oid[0] += 1
        orgs[oid] = {"id":oid,"name":d.get("name","Nuova Org"),"color":d.get("color","#00d4aa"),"created_at":_now()}
        return jsonify(orgs[oid])

@app.route("/api/orgs/<oid>", methods=["PATCH"])
@require_api_key
def update_org(oid):
    d = request.json or {}
    with _lock:
        if oid not in orgs: abort(404)
        if "name"  in d: orgs[oid]["name"]  = d["name"]
        if "color" in d: orgs[oid]["color"] = d["color"]
        return jsonify(orgs[oid])

@app.route("/api/orgs/<oid>", methods=["DELETE"])
@require_api_key
def delete_org(oid):
    with _lock:
        orgs.pop(oid, None)
        to_del_s = [s for s,v in sites.items() if v["oid"]==oid]
        for s in to_del_s:
            [depts.pop(dd) for dd in [k for k,v in depts.items() if v["sid"]==s]]
            sites.pop(s)
        for m in machines.values():
            if m.get("oid")==oid: m.update({"oid":None,"sid":None,"did":None})
        return jsonify({"ok":True})

# ── Sites API ─────────────────────────────────────────────────
@app.route("/api/sites", methods=["GET"])
@require_api_key
def get_sites():
    oid = request.args.get("oid")
    with _lock:
        result = [v for v in sites.values() if not oid or v["oid"]==oid]
        return jsonify(result)

@app.route("/api/sites", methods=["POST"])
@require_api_key
def create_site():
    d = request.json or {}
    with _lock:
        sid = str(_sid[0]); _sid[0] += 1
        sites[sid] = {"id":sid,"oid":d.get("oid",""),"name":d.get("name","Nuova Sede"),"address":d.get("address",""),"created_at":_now()}
        return jsonify(sites[sid])

@app.route("/api/sites/<sid>", methods=["PATCH"])
@require_api_key
def update_site(sid):
    d = request.json or {}
    with _lock:
        if sid not in sites: abort(404)
        for k in ["name","address","oid"]:
            if k in d: sites[sid][k] = d[k]
        return jsonify(sites[sid])

@app.route("/api/sites/<sid>", methods=["DELETE"])
@require_api_key
def delete_site(sid):
    with _lock:
        sites.pop(sid, None)
        [depts.pop(dd) for dd in [k for k,v in depts.items() if v["sid"]==sid]]
        for m in machines.values():
            if m.get("sid")==sid: m.update({"sid":None,"did":None})
        return jsonify({"ok":True})

# ── Depts API ─────────────────────────────────────────────────
@app.route("/api/depts", methods=["GET"])
@require_api_key
def get_depts():
    sid = request.args.get("sid")
    with _lock:
        result = [v for v in depts.values() if not sid or v["sid"]==sid]
        return jsonify(result)

@app.route("/api/depts", methods=["POST"])
@require_api_key
def create_dept():
    d = request.json or {}
    with _lock:
        did = str(_did[0]); _did[0] += 1
        depts[did] = {"id":did,"sid":d.get("sid",""),"oid":d.get("oid",""),"name":d.get("name","Nuovo Reparto"),"created_at":_now()}
        return jsonify(depts[did])

@app.route("/api/depts/<did>", methods=["PATCH"])
@require_api_key
def update_dept(did):
    d = request.json or {}
    with _lock:
        if did not in depts: abort(404)
        for k in ["name","sid","oid"]:
            if k in d: depts[did][k] = d[k]
        return jsonify(depts[did])

@app.route("/api/depts/<did>", methods=["DELETE"])
@require_api_key
def delete_dept(did):
    with _lock:
        depts.pop(did, None)
        for m in machines.values():
            if m.get("did")==did: m["did"] = None
        return jsonify({"ok":True})

# ── Machine assign ────────────────────────────────────────────
@app.route("/api/machines/<mid>/assign", methods=["PATCH"])
@require_api_key
def assign_machine(mid):
    d = request.json or {}
    with _lock:
        if mid not in machines: abort(404)
        machines[mid]["oid"] = d.get("oid")
        machines[mid]["sid"] = d.get("sid")
        machines[mid]["did"] = d.get("did")
        return jsonify({"ok":True})

# ── Ticket API ────────────────────────────────────────────────
@app.route("/api/ticket", methods=["POST"])
@require_api_key
def create_ticket():
    data = request.json or {}
    pc = data.get("pc_name","N/D"); domain = data.get("domain","N/D")
    mid = hashlib.md5(f"{pc}{domain}".encode()).hexdigest()[:12]
    now = _now()
    with _lock:
        if mid in machines:
            machines[mid].update({"user":data.get("user",machines[mid]["user"]),"ip":data.get("ip",machines[mid]["ip"]),"rustdesk_id":data.get("rustdesk_id",machines[mid]["rustdesk_id"]),"last_seen":now,"status":"online"})
        else:
            machines[mid] = {"id":mid,"pc_name":pc,"user":data.get("user",""),"domain":domain,"ip":data.get("ip",""),"os":data.get("os",""),"rustdesk_id":data.get("rustdesk_id",""),"last_seen":now,"status":"online","cpu":0,"ram":0,"disk":0,"oid":None,"sid":None,"did":None}
        tid = _tid[0]; _tid[0] += 1
        t = {"id":tid,"machine_id":mid,"pc_name":pc,"user":data.get("user",""),"ip":data.get("ip",""),"rustdesk_id":data.get("rustdesk_id",""),"description":data.get("description",""),"screenshot":data.get("screenshot",""),"status":"open","priority":data.get("priority","normal"),"created_at":now,"updated_at":now,"note":""}
        tickets.append(t)
        return jsonify({"ok":True,"ticket_id":tid,"machine_id":mid})

@app.route("/api/heartbeat", methods=["POST"])
@require_api_key
def heartbeat():
    data = request.json or {}
    pc = data.get("pc_name","N/D"); domain = data.get("domain","N/D")
    mid = hashlib.md5(f"{pc}{domain}".encode()).hexdigest()[:12]
    now = _now()
    with _lock:
        if mid in machines:
            machines[mid].update({"last_seen":now,"status":"online","cpu":data.get("cpu",0),"ram":data.get("ram",0),"disk":data.get("disk",0),"rustdesk_id":data.get("rustdesk_id",machines[mid]["rustdesk_id"])})
        else:
            machines[mid] = {"id":mid,"pc_name":pc,"user":data.get("user",""),"domain":domain,"ip":data.get("ip",""),"os":data.get("os",""),"rustdesk_id":data.get("rustdesk_id",""),"last_seen":now,"status":"online","cpu":data.get("cpu",0),"ram":data.get("ram",0),"disk":data.get("disk",0),"oid":None,"sid":None,"did":None}
    return jsonify({"ok":True})

@app.route("/api/machines")
@require_api_key
def get_machines():
    threshold = (datetime.now()-timedelta(minutes=5)).isoformat()
    with _lock:
        for m in machines.values():
            if m["last_seen"] < threshold: m["status"]="offline"
        return jsonify(list(machines.values()))

@app.route("/api/tickets")
@require_api_key
def get_tickets():
    status = request.args.get("status","all")
    with _lock:
        result = []
        for t in reversed(tickets):
            if status!="all" and t["status"]!=status: continue
            d = dict(t); d.pop("screenshot",None); result.append(d)
        return jsonify(result)

@app.route("/api/ticket/<int:tid>")
@require_api_key
def get_ticket(tid):
    with _lock:
        for t in tickets:
            if t["id"]==tid: return jsonify(dict(t))
    abort(404)

@app.route("/api/ticket/<int:tid>", methods=["PATCH"])
@require_api_key
def update_ticket(tid):
    data = request.json or {}
    with _lock:
        for t in tickets:
            if t["id"]==tid:
                for k in ["status","priority","note"]:
                    if k in data: t[k]=data[k]
                t["updated_at"]=_now()
                return jsonify({"ok":True})
    abort(404)

@app.route("/api/stats")
@require_api_key
def get_stats():
    threshold = (datetime.now()-timedelta(minutes=5)).isoformat()
    with _lock:
        total  = len(machines)
        online = sum(1 for m in machines.values() if m["last_seen"]>=threshold)
        return jsonify({"total_machines":total,"online_machines":online,"offline_machines":total-online,"open_tickets":sum(1 for t in tickets if t["status"]=="open"),"closed_tickets":sum(1 for t in tickets if t["status"]=="closed"),"urgent_tickets":sum(1 for t in tickets if t["status"]=="open" and t["priority"]=="urgent"),"total_orgs":len(orgs)})

@app.route("/api/demo", methods=["POST"])
def demo_data():
    with _lock:
        orgs["1"]={"id":"1","name":"Emotion Design Srl","color":"#00d4aa","created_at":_now()}
        orgs["2"]={"id":"2","name":"Cliente Rossi Spa","color":"#0091ff","created_at":_now()}
        _oid[0]=3
        sites["1"]={"id":"1","oid":"1","name":"Sede Milano","address":"Via Roma 1, Milano","created_at":_now()}
        sites["2"]={"id":"2","oid":"1","name":"Sede Roma","address":"Via Veneto 10, Roma","created_at":_now()}
        sites["3"]={"id":"3","oid":"2","name":"Sede Principale","address":"Corso Italia 5, Torino","created_at":_now()}
        _sid[0]=4
        depts["1"]={"id":"1","sid":"1","oid":"1","name":"Amministrazione","created_at":_now()}
        depts["2"]={"id":"2","sid":"1","oid":"1","name":"IT","created_at":_now()}
        depts["3"]={"id":"3","sid":"2","oid":"1","name":"Commerciale","created_at":_now()}
        _did[0]=4
        ms=[
            {"id":"abc001","pc_name":"DESKTOP-MARIO","user":"mario.rossi","domain":"EMOTIONDESIGN","ip":"192.168.1.10","os":"Windows 11 Pro","rustdesk_id":"123 456 789","last_seen":_now(),"status":"online","cpu":45,"ram":62,"disk":78,"oid":"1","sid":"1","did":"1"},
            {"id":"abc002","pc_name":"LAPTOP-GIULIA","user":"giulia.bianchi","domain":"EMOTIONDESIGN","ip":"192.168.1.11","os":"Windows 10 Pro","rustdesk_id":"987 654 321","last_seen":_now(),"status":"online","cpu":12,"ram":34,"disk":45,"oid":"1","sid":"1","did":"2"},
            {"id":"abc003","pc_name":"PC-CONTABILITA","user":"admin","domain":"WORKGROUP","ip":"192.168.1.20","os":"Windows 10 Home","rustdesk_id":"","last_seen":"2020-01-01","status":"offline","cpu":0,"ram":0,"disk":0,"oid":"1","sid":"2","did":"3"},
            {"id":"abc004","pc_name":"SERVER-FILE","user":"Administrator","domain":"EMOTIONDESIGN","ip":"192.168.1.1","os":"Windows Server 2022","rustdesk_id":"111 222 333","last_seen":_now(),"status":"online","cpu":78,"ram":88,"disk":92,"oid":"2","sid":"3","did":None},
        ]
        for m in ms: machines[m["id"]]=m
        ts=[
            {"pc_name":"DESKTOP-MARIO","user":"mario.rossi","domain":"EMOTIONDESIGN","ip":"192.168.1.10","rustdesk_id":"123 456 789","description":"Il PC va lento, non riesco ad aprire Excel","priority":"urgent"},
            {"pc_name":"LAPTOP-GIULIA","user":"giulia.bianchi","domain":"EMOTIONDESIGN","ip":"192.168.1.11","rustdesk_id":"987 654 321","description":"Stampante non trovata in rete","priority":"normal"},
            {"pc_name":"SERVER-FILE","user":"Administrator","domain":"EMOTIONDESIGN","ip":"192.168.1.1","rustdesk_id":"111 222 333","description":"Disco quasi pieno 92%","priority":"urgent"},
        ]
        for d in ts:
            mid=hashlib.md5(f"{d['pc_name']}{d['domain']}".encode()).hexdigest()[:12]
            d["machine_id"]=mid; tid=_tid[0]; _tid[0]+=1
            tickets.append({"id":tid,"machine_id":mid,"pc_name":d["pc_name"],"user":d["user"],"ip":d["ip"],"rustdesk_id":d["rustdesk_id"],"description":d["description"],"screenshot":"","status":"open","priority":d["priority"],"created_at":_now(),"updated_at":_now(),"note":""})
    return jsonify({"ok":True})


# ═══════════════════════════════════════════════════════════════
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
  <div class="logo">
    <div class="logo-icon">U</div>
    <div><div class="logo-text">UPTIME RMM</div><div class="logo-sub">SERVICE DASHBOARD</div></div>
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
  <div class="logo">
    <div class="logo-icon">U</div>
    <div><div class="logo-name">UPTIME</div><div class="logo-sub">SERVICE RMM</div></div>
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

_ensure_default_admin()

if __name__ == "__main__":
    print("Uptime Service Dashboard v3 — http://localhost:5000")
    print("Login: admin / admin")
    app.run(debug=False, host="0.0.0.0", port=5000)
