"""
Uptime Service RMM — Server v3
Flask + WebSocket (flask-sock) + comandi remoti
"""
from flask import Flask, request, jsonify, abort, Response
from flask_cors import CORS
from flask_sock import Sock
import os, hashlib, threading, json, queue
from datetime import datetime, timedelta
from functools import wraps

app  = Flask(__name__)
CORS(app)
sock = Sock(app)

API_KEY = os.environ.get("UPTIME_API_KEY", "uptime-sos-2025")

# ── Store in memoria ──────────────────────────────────────────
_lock    = threading.Lock()
machines = {}
tickets  = []
orgs     = {}
sites    = {}
depts    = {}
cmd_log  = []  # log comandi eseguiti
_tid = [1]; _oid = [1]; _sid = [1]; _did = [1]; _cid = [1]

# WebSocket connections: mid -> ws object
ws_clients = {}  # mid -> {"ws": ws, "queue": Queue}

def _now(): return datetime.now().isoformat()

# ── Auth ──────────────────────────────────────────────────────
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if key != API_KEY: abort(401)
        return f(*args, **kwargs)
    return decorated

# ── WebSocket handler (client agent) ─────────────────────────
@sock.route("/ws/agent")
def agent_ws(ws):
    """Connessione WebSocket dal client agent."""
    mid = None
    try:
        # Prima ricezione: registrazione
        raw = ws.receive(timeout=15)
        if not raw: return
        data = json.loads(raw)
        if data.get("type") != "register": return

        pc     = data.get("pc_name","N/D")
        domain = data.get("domain","N/D")
        mid    = hashlib.md5(f"{pc}{domain}".encode()).hexdigest()[:12]

        now = _now()
        with _lock:
            if mid in machines:
                machines[mid].update({"last_seen":now,"status":"online",
                    "user":data.get("user",machines[mid]["user"]),
                    "ip":data.get("ip",machines[mid]["ip"]),
                    "rustdesk_id":data.get("rustdesk_id",machines[mid].get("rustdesk_id",""))})
            else:
                machines[mid] = {"id":mid,"pc_name":pc,"user":data.get("user",""),
                    "domain":domain,"ip":data.get("ip",""),"os":data.get("os",""),
                    "rustdesk_id":data.get("rustdesk_id",""),"last_seen":now,
                    "status":"online","cpu":0,"ram":0,"disk":0,
                    "oid":None,"sid":None,"did":None}
            q = queue.Queue()
            ws_clients[mid] = {"ws":ws,"queue":q}

        ws.send(json.dumps({"type":"registered","machine_id":mid}))

        # Loop: ricevi heartbeat / risultati, invia comandi
        while True:
            try:
                raw = ws.receive(timeout=1)
                if raw:
                    msg = json.loads(raw)
                    mtype = msg.get("type")

                    if mtype == "heartbeat":
                        with _lock:
                            if mid in machines:
                                machines[mid].update({
                                    "last_seen":_now(),"status":"online",
                                    "cpu":msg.get("cpu",0),"ram":msg.get("ram",0),
                                    "disk":msg.get("disk",0),
                                    "rustdesk_id":msg.get("rustdesk_id",machines[mid].get("rustdesk_id",""))
                                })

                    elif mtype == "cmd_result":
                        cid = msg.get("cmd_id")
                        with _lock:
                            for c in cmd_log:
                                if c["id"] == cid:
                                    c["status"]  = msg.get("status","done")
                                    c["output"]  = msg.get("output","")
                                    c["done_at"] = _now()
                                    break
            except Exception:
                pass

            # Controlla se ci sono comandi da inviare
            try:
                with _lock:
                    q2 = ws_clients.get(mid,{}).get("queue")
                if q2:
                    cmd = q2.get_nowait()
                    ws.send(json.dumps(cmd))
            except queue.Empty:
                pass
            except Exception:
                break

    except Exception:
        pass
    finally:
        if mid:
            with _lock:
                ws_clients.pop(mid, None)
                if mid in machines:
                    machines[mid]["status"] = "offline"

# ── WebSocket handler (dashboard browser) ────────────────────
@sock.route("/ws/dashboard")
def dashboard_ws(ws):
    """Push aggiornamenti alla dashboard browser ogni 3s."""
    try:
        while True:
            threshold = (datetime.now()-timedelta(minutes=5)).isoformat()
            with _lock:
                for m in machines.values():
                    if m["last_seen"] < threshold and mid not in ws_clients:
                        m["status"] = "offline"
                payload = {
                    "type":     "update",
                    "machines": list(machines.values()),
                    "tickets":  [{k:v for k,v in t.items() if k!="screenshot"} for t in reversed(tickets[-50:])],
                    "cmd_log":  list(reversed(cmd_log[-30:])),
                    "connected_agents": list(ws_clients.keys()),
                    "stats": {
                        "total_machines":  len(machines),
                        "online_machines": sum(1 for m in machines.values() if m["status"]=="online"),
                        "open_tickets":    sum(1 for t in tickets if t["status"]=="open"),
                        "urgent_tickets":  sum(1 for t in tickets if t["status"]=="open" and t["priority"]=="urgent"),
                        "total_orgs":      len(orgs),
                        "connected_agents":len(ws_clients),
                    }
                }
            ws.send(json.dumps(payload))
            import time; time.sleep(3)
    except Exception:
        pass

# ── API: Invia comando a un agent ─────────────────────────────
@app.route("/api/command", methods=["POST"])
@require_api_key
def send_command():
    data = request.json or {}
    mid  = data.get("machine_id")
    cmd  = data.get("command")
    params = data.get("params", {})

    ALLOWED = ["reboot","shutdown","lock","screenshot","ps_exec","open_app","kill_app","msg"]
    if cmd not in ALLOWED:
        return jsonify({"ok":False,"error":"Comando non permesso"}), 400

    with _lock:
        if mid not in ws_clients:
            return jsonify({"ok":False,"error":"Agent non connesso"}), 404
        cid = _cid[0]; _cid[0] += 1
        entry = {"id":cid,"machine_id":mid,"pc_name":machines.get(mid,{}).get("pc_name","N/D"),
                 "command":cmd,"params":params,"status":"pending",
                 "sent_at":_now(),"done_at":None,"output":""}
        cmd_log.append(entry)
        ws_clients[mid]["queue"].put({"type":"command","cmd_id":cid,"command":cmd,"params":params})

    return jsonify({"ok":True,"cmd_id":cid})

@app.route("/api/commands")
@require_api_key
def get_commands():
    with _lock:
        return jsonify(list(reversed(cmd_log[-50:])))

# ── Resto API (org/site/dept/machine/ticket) ──────────────────
@app.route("/api/orgs", methods=["GET"])
@require_api_key
def get_orgs():
    with _lock: return jsonify(list(orgs.values()))

@app.route("/api/orgs", methods=["POST"])
@require_api_key
def create_org():
    d = request.json or {}
    with _lock:
        oid=str(_oid[0]);_oid[0]+=1
        orgs[oid]={"id":oid,"name":d.get("name","Nuova Org"),"color":d.get("color","#00d4aa"),"created_at":_now()}
        return jsonify(orgs[oid])

@app.route("/api/orgs/<oid>", methods=["PATCH"])
@require_api_key
def update_org(oid):
    d=request.json or {}
    with _lock:
        if oid not in orgs: abort(404)
        for k in ["name","color"]:
            if k in d: orgs[oid][k]=d[k]
        return jsonify(orgs[oid])

@app.route("/api/orgs/<oid>", methods=["DELETE"])
@require_api_key
def delete_org(oid):
    with _lock:
        orgs.pop(oid,None)
        for s in [k for k,v in sites.items() if v["oid"]==oid]:
            [depts.pop(dd) for dd in [k for k,v in depts.items() if v["sid"]==s]]
            sites.pop(s)
        for m in machines.values():
            if m.get("oid")==oid: m.update({"oid":None,"sid":None,"did":None})
        return jsonify({"ok":True})

@app.route("/api/sites", methods=["GET"])
@require_api_key
def get_sites():
    oid=request.args.get("oid")
    with _lock: return jsonify([v for v in sites.values() if not oid or v["oid"]==oid])

@app.route("/api/sites", methods=["POST"])
@require_api_key
def create_site():
    d=request.json or {}
    with _lock:
        sid=str(_sid[0]);_sid[0]+=1
        sites[sid]={"id":sid,"oid":d.get("oid",""),"name":d.get("name","Nuova Sede"),"address":d.get("address",""),"created_at":_now()}
        return jsonify(sites[sid])

@app.route("/api/sites/<sid>", methods=["PATCH"])
@require_api_key
def update_site(sid):
    d=request.json or {}
    with _lock:
        if sid not in sites: abort(404)
        for k in ["name","address","oid"]:
            if k in d: sites[sid][k]=d[k]
        return jsonify(sites[sid])

@app.route("/api/sites/<sid>", methods=["DELETE"])
@require_api_key
def delete_site(sid):
    with _lock:
        sites.pop(sid,None)
        [depts.pop(dd) for dd in [k for k,v in depts.items() if v["sid"]==sid]]
        for m in machines.values():
            if m.get("sid")==sid: m.update({"sid":None,"did":None})
        return jsonify({"ok":True})

@app.route("/api/depts", methods=["GET"])
@require_api_key
def get_depts():
    sid=request.args.get("sid")
    with _lock: return jsonify([v for v in depts.values() if not sid or v["sid"]==sid])

@app.route("/api/depts", methods=["POST"])
@require_api_key
def create_dept():
    d=request.json or {}
    with _lock:
        did=str(_did[0]);_did[0]+=1
        depts[did]={"id":did,"sid":d.get("sid",""),"oid":d.get("oid",""),"name":d.get("name","Nuovo Reparto"),"created_at":_now()}
        return jsonify(depts[did])

@app.route("/api/depts/<did>", methods=["PATCH"])
@require_api_key
def update_dept(did):
    d=request.json or {}
    with _lock:
        if did not in depts: abort(404)
        for k in ["name","sid","oid"]:
            if k in d: depts[did][k]=d[k]
        return jsonify(depts[did])

@app.route("/api/depts/<did>", methods=["DELETE"])
@require_api_key
def delete_dept(did):
    with _lock:
        depts.pop(did,None)
        for m in machines.values():
            if m.get("did")==did: m["did"]=None
        return jsonify({"ok":True})

@app.route("/api/machines/<mid>/assign", methods=["PATCH"])
@require_api_key
def assign_machine(mid):
    d=request.json or {}
    with _lock:
        if mid not in machines: abort(404)
        machines[mid].update({"oid":d.get("oid"),"sid":d.get("sid"),"did":d.get("did")})
        return jsonify({"ok":True})

@app.route("/api/machines")
@require_api_key
def get_machines():
    threshold=(datetime.now()-timedelta(minutes=5)).isoformat()
    with _lock:
        for m in machines.values():
            if m["last_seen"]<threshold and m["id"] not in ws_clients:
                m["status"]="offline"
        return jsonify(list(machines.values()))

@app.route("/api/ticket", methods=["POST"])
@require_api_key
def create_ticket():
    data=request.json or {}
    pc=data.get("pc_name","N/D"); domain=data.get("domain","N/D")
    mid=hashlib.md5(f"{pc}{domain}".encode()).hexdigest()[:12]
    now=_now()
    with _lock:
        if mid in machines:
            machines[mid].update({"user":data.get("user",machines[mid]["user"]),
                "ip":data.get("ip",machines[mid]["ip"]),"last_seen":now,"status":"online",
                "rustdesk_id":data.get("rustdesk_id",machines[mid].get("rustdesk_id",""))})
        else:
            machines[mid]={"id":mid,"pc_name":pc,"user":data.get("user",""),"domain":domain,
                "ip":data.get("ip",""),"os":data.get("os",""),"rustdesk_id":data.get("rustdesk_id",""),
                "last_seen":now,"status":"online","cpu":0,"ram":0,"disk":0,"oid":None,"sid":None,"did":None}
        tid=_tid[0];_tid[0]+=1
        t={"id":tid,"machine_id":mid,"pc_name":pc,"user":data.get("user",""),
            "ip":data.get("ip",""),"rustdesk_id":data.get("rustdesk_id",""),
            "description":data.get("description",""),"screenshot":data.get("screenshot",""),
            "status":"open","priority":data.get("priority","normal"),
            "created_at":now,"updated_at":now,"note":""}
        tickets.append(t)
        return jsonify({"ok":True,"ticket_id":tid,"machine_id":mid})

@app.route("/api/heartbeat", methods=["POST"])
@require_api_key
def heartbeat():
    data=request.json or {}
    pc=data.get("pc_name","N/D"); domain=data.get("domain","N/D")
    mid=hashlib.md5(f"{pc}{domain}".encode()).hexdigest()[:12]
    now=_now()
    with _lock:
        if mid in machines:
            machines[mid].update({"last_seen":now,"status":"online",
                "cpu":data.get("cpu",0),"ram":data.get("ram",0),"disk":data.get("disk",0),
                "rustdesk_id":data.get("rustdesk_id",machines[mid].get("rustdesk_id",""))})
        else:
            machines[mid]={"id":mid,"pc_name":pc,"user":data.get("user",""),"domain":domain,
                "ip":data.get("ip",""),"os":data.get("os",""),"rustdesk_id":data.get("rustdesk_id",""),
                "last_seen":now,"status":"online","cpu":data.get("cpu",0),
                "ram":data.get("ram",0),"disk":data.get("disk",0),"oid":None,"sid":None,"did":None}
    return jsonify({"ok":True})

@app.route("/api/tickets")
@require_api_key
def get_tickets():
    status=request.args.get("status","all")
    with _lock:
        result=[]
        for t in reversed(tickets):
            if status!="all" and t["status"]!=status: continue
            d=dict(t); d.pop("screenshot",None); result.append(d)
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
    data=request.json or {}
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
    threshold=(datetime.now()-timedelta(minutes=5)).isoformat()
    with _lock:
        total=len(machines); online=sum(1 for m in machines.values() if m["last_seen"]>=threshold)
        return jsonify({"total_machines":total,"online_machines":online,
            "offline_machines":total-online,
            "open_tickets":sum(1 for t in tickets if t["status"]=="open"),
            "closed_tickets":sum(1 for t in tickets if t["status"]=="closed"),
            "urgent_tickets":sum(1 for t in tickets if t["status"]=="open" and t["priority"]=="urgent"),
            "total_orgs":len(orgs),"connected_agents":len(ws_clients)})

@app.route("/api/demo", methods=["POST"])
def demo_data():
    with _lock:
        orgs["1"]={"id":"1","name":"Emotion Design Srl","color":"#00d4aa","created_at":_now()}
        orgs["2"]={"id":"2","name":"Cliente Rossi Spa","color":"#0091ff","created_at":_now()}
        _oid[0]=3
        sites["1"]={"id":"1","oid":"1","name":"Sede Milano","address":"Via Roma 1, Milano","created_at":_now()}
        sites["2"]={"id":"2","oid":"2","name":"Sede Torino","address":"Corso Italia 5, Torino","created_at":_now()}
        _sid[0]=3
        depts["1"]={"id":"1","sid":"1","oid":"1","name":"Amministrazione","created_at":_now()}
        depts["2"]={"id":"2","sid":"1","oid":"1","name":"IT","created_at":_now()}
        _did[0]=3
        ms=[
            {"id":"abc001","pc_name":"DESKTOP-MARIO","user":"mario.rossi","domain":"EMOTIONDESIGN","ip":"192.168.1.10","os":"Windows 11 Pro","rustdesk_id":"123 456 789","last_seen":_now(),"status":"online","cpu":45,"ram":62,"disk":78,"oid":"1","sid":"1","did":"1"},
            {"id":"abc002","pc_name":"LAPTOP-GIULIA","user":"giulia.bianchi","domain":"EMOTIONDESIGN","ip":"192.168.1.11","os":"Windows 10 Pro","rustdesk_id":"987 654 321","last_seen":_now(),"status":"online","cpu":12,"ram":34,"disk":45,"oid":"1","sid":"1","did":"2"},
            {"id":"abc003","pc_name":"SERVER-FILE","user":"Administrator","domain":"EMOTIONDESIGN","ip":"192.168.1.1","os":"Windows Server 2022","rustdesk_id":"111 222 333","last_seen":_now(),"status":"online","cpu":78,"ram":88,"disk":92,"oid":"2","sid":"2","did":None},
        ]
        for m in ms: machines[m["id"]]=m
        ts=[
            {"pc_name":"DESKTOP-MARIO","user":"mario.rossi","domain":"EMOTIONDESIGN","ip":"192.168.1.10","rustdesk_id":"123 456 789","description":"Il PC va lento","priority":"urgent"},
            {"pc_name":"LAPTOP-GIULIA","user":"giulia.bianchi","domain":"EMOTIONDESIGN","ip":"192.168.1.11","rustdesk_id":"987 654 321","description":"Stampante non trovata","priority":"normal"},
        ]
        for d in ts:
            mid=hashlib.md5(f"{d['pc_name']}{d['domain']}".encode()).hexdigest()[:12]
            d["machine_id"]=mid; tid=_tid[0]; _tid[0]+=1
            tickets.append({"id":tid,"machine_id":mid,"pc_name":d["pc_name"],"user":d["user"],
                "ip":d["ip"],"rustdesk_id":d["rustdesk_id"],"description":d["description"],
                "screenshot":"","status":"open","priority":d["priority"],
                "created_at":_now(),"updated_at":_now(),"note":""})
    return jsonify({"ok":True})


# ── Frontend ──────────────────────────────────────────────────
@app.route("/")
@app.route("/dashboard")
def dashboard():
    page = DASHBOARD_HTML.replace("{{ api_key }}", API_KEY)
    page = page.replace("{{ ws_url }}", f"wss://{request.host}/ws/dashboard")
    return Response(page, mimetype="text/html")

if __name__ == "__main__":
    print("Uptime Service Dashboard v3 — http://localhost:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Uptime Service — Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg0:     #090c10;
  --bg1:     #0d1117;
  --bg2:     #161b22;
  --bg3:     #1c2333;
  --bg4:     #243044;
  --border:  #2a3547;
  --accent:  #00d4aa;
  --accent2: #0091ff;
  --red:     #ff4757;
  --orange:  #ffa502;
  --green:   #00d4aa;
  --yellow:  #ffd32a;
  --text:    #e6edf3;
  --text2:   #8b949e;
  --text3:   #4a5568;
  --ninja:   #00d4aa;
  --glow:    0 0 20px rgba(0,212,170,0.15);
  --glow2:   0 0 40px rgba(0,212,170,0.08);
}

* { margin:0; padding:0; box-sizing:border-box; }

body {
  font-family: 'Syne', sans-serif;
  background: var(--bg0);
  color: var(--text);
  min-height: 100vh;
  overflow-x: hidden;
}

/* Scanline effect */
body::before {
  content:'';
  position:fixed; inset:0;
  background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
  pointer-events:none; z-index:9999;
}

/* ── SIDEBAR ─────────────────────────────── */
.sidebar {
  position: fixed; left:0; top:0; bottom:0;
  width: 220px;
  background: var(--bg1);
  border-right: 1px solid var(--border);
  display: flex; flex-direction: column;
  z-index: 100;
}

.sidebar-logo {
  padding: 24px 20px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 10px;
}
.logo-icon {
  width: 32px; height: 32px;
  background: linear-gradient(135deg, var(--accent), var(--accent2));
  border-radius: 8px;
  display: flex; align-items: center; justify-content: center;
  font-size: 16px; font-weight: 800; color: #000;
  box-shadow: var(--glow);
}
.logo-text { font-size: 13px; font-weight: 700; letter-spacing: 1px; color: var(--text); }
.logo-sub  { font-size: 9px; color: var(--accent); letter-spacing: 2px; font-family: 'JetBrains Mono', monospace; }

.nav { flex: 1; padding: 16px 12px; }
.nav-section { font-size: 9px; color: var(--text3); letter-spacing: 2px; padding: 16px 8px 8px; font-family:'JetBrains Mono',monospace; }

.nav-item {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 12px; border-radius: 8px;
  font-size: 13px; font-weight: 600; color: var(--text2);
  cursor: pointer; transition: all .2s;
  margin-bottom: 2px; position: relative;
}
.nav-item:hover { background: var(--bg2); color: var(--text); }
.nav-item.active {
  background: rgba(0,212,170,0.1);
  color: var(--accent);
  box-shadow: inset 3px 0 0 var(--accent);
}
.nav-item .badge {
  margin-left: auto;
  background: var(--red);
  color: #fff; font-size: 10px; font-weight: 700;
  padding: 2px 6px; border-radius: 10px;
  font-family: 'JetBrains Mono', monospace;
}
.nav-item .badge.green { background: var(--accent); color: #000; }

.sidebar-footer {
  padding: 16px; border-top: 1px solid var(--border);
  font-size: 11px; color: var(--text3);
  font-family: 'JetBrains Mono', monospace;
}
.status-dot {
  display: inline-block; width: 6px; height: 6px;
  border-radius: 50%; background: var(--accent);
  margin-right: 6px; animation: pulse 2s infinite;
}
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

/* ── MAIN ─────────────────────────────────── */
.main {
  margin-left: 220px;
  min-height: 100vh;
  display: flex; flex-direction: column;
}

.topbar {
  padding: 16px 28px;
  background: var(--bg1);
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
  position: sticky; top: 0; z-index: 50;
}
.topbar-title { font-size: 18px; font-weight: 800; letter-spacing: -.5px; }
.topbar-title span { color: var(--accent); }

.topbar-actions { display: flex; align-items: center; gap: 12px; }
.btn {
  padding: 8px 16px; border-radius: 8px;
  font-size: 12px; font-weight: 700; cursor: pointer;
  border: none; transition: all .2s; font-family: 'Syne', sans-serif;
  letter-spacing: .5px;
}
.btn-primary { background: var(--accent); color: #000; }
.btn-primary:hover { background: #00f0c0; box-shadow: var(--glow); }
.btn-ghost { background: var(--bg3); color: var(--text2); border: 1px solid var(--border); }
.btn-ghost:hover { background: var(--bg4); color: var(--text); }
.btn-danger { background: rgba(255,71,87,0.15); color: var(--red); border: 1px solid rgba(255,71,87,0.3); }
.btn-danger:hover { background: rgba(255,71,87,0.25); }

.content { padding: 24px 28px; flex: 1; }

/* ── STATS CARDS ─────────────────────────── */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px; margin-bottom: 28px;
}
.stat-card {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 12px; padding: 20px;
  position: relative; overflow: hidden;
  transition: all .3s; cursor: default;
  animation: fadeUp .4s ease both;
}
.stat-card:hover { border-color: var(--accent); box-shadow: var(--glow); transform: translateY(-2px); }
.stat-card::before {
  content:''; position:absolute; top:0; left:0; right:0; height:2px;
  background: linear-gradient(90deg, var(--accent), var(--accent2));
  opacity: 0; transition: opacity .3s;
}
.stat-card:hover::before { opacity: 1; }

.stat-label { font-size: 10px; color: var(--text3); letter-spacing: 2px; text-transform: uppercase; font-family:'JetBrains Mono',monospace; margin-bottom: 10px; }
.stat-value { font-size: 36px; font-weight: 800; line-height: 1; margin-bottom: 6px; }
.stat-sub   { font-size: 11px; color: var(--text2); }
.stat-icon  { position: absolute; right: 16px; top: 16px; font-size: 28px; opacity: .15; }

.stat-green  .stat-value { color: var(--green); }
.stat-red    .stat-value { color: var(--red); }
.stat-orange .stat-value { color: var(--orange); }
.stat-blue   .stat-value { color: var(--accent2); }

@keyframes fadeUp { from{opacity:0;transform:translateY(16px)} to{opacity:1;transform:translateY(0)} }

/* ── GRID LAYOUT ─────────────────────────── */
.grid-2 {
  display: grid;
  grid-template-columns: 1fr 380px;
  gap: 20px; margin-bottom: 20px;
}
@media(max-width:1200px){ .grid-2{ grid-template-columns:1fr; } }

/* ── PANELS ──────────────────────────────── */
.panel {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 12px; overflow: hidden;
  animation: fadeUp .5s ease both;
}
.panel-header {
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
}
.panel-title {
  font-size: 13px; font-weight: 700;
  display: flex; align-items: center; gap: 8px;
}
.panel-title .dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--accent); box-shadow: 0 0 8px var(--accent);
}
.panel-body { padding: 0; }

/* ── TICKET LIST ─────────────────────────── */
.ticket-item {
  display: flex; align-items: flex-start; gap: 14px;
  padding: 14px 20px;
  border-bottom: 1px solid rgba(42,53,71,.5);
  cursor: pointer; transition: background .2s;
  position: relative;
}
.ticket-item:hover { background: var(--bg3); }
.ticket-item:last-child { border-bottom: none; }

.ticket-priority {
  width: 4px; border-radius: 4px; align-self: stretch; flex-shrink: 0;
}
.priority-urgent { background: var(--red); box-shadow: 0 0 8px var(--red); }
.priority-normal { background: var(--accent2); }
.priority-low    { background: var(--text3); }

.ticket-body { flex: 1; min-width: 0; }
.ticket-title {
  font-size: 13px; font-weight: 600; color: var(--text);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  margin-bottom: 4px;
}
.ticket-meta { display: flex; gap: 10px; flex-wrap: wrap; }
.ticket-meta span {
  font-size: 10px; color: var(--text2);
  font-family: 'JetBrains Mono', monospace;
  display: flex; align-items: center; gap: 4px;
}
.ticket-time { font-size: 10px; color: var(--text3); font-family:'JetBrains Mono',monospace; white-space: nowrap; }

.ticket-badge {
  font-size: 9px; font-weight: 700; padding: 3px 8px;
  border-radius: 6px; text-transform: uppercase; letter-spacing: 1px;
  flex-shrink: 0; align-self: flex-start; margin-top: 2px;
}
.badge-open   { background: rgba(0,145,255,.15); color: var(--accent2); border: 1px solid rgba(0,145,255,.3); }
.badge-closed { background: rgba(74,85,104,.2);  color: var(--text3);   border: 1px solid var(--border); }
.badge-urgent { background: rgba(255,71,87,.15); color: var(--red);     border: 1px solid rgba(255,71,87,.3); }

/* ── MACHINE LIST ────────────────────────── */
.machine-item {
  display: flex; align-items: center; gap: 14px;
  padding: 12px 20px;
  border-bottom: 1px solid rgba(42,53,71,.5);
  cursor: pointer; transition: background .2s;
}
.machine-item:hover { background: var(--bg3); }
.machine-item:last-child { border-bottom: none; }

.machine-status {
  width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
}
.status-online  { background: var(--green); box-shadow: 0 0 8px var(--green); animation: pulse 2s infinite; }
.status-offline { background: var(--text3); }

.machine-name { font-size: 13px; font-weight: 700; color: var(--text); }
.machine-user { font-size: 10px; color: var(--text2); font-family:'JetBrains Mono',monospace; }
.machine-ip   { font-size: 10px; color: var(--text3); font-family:'JetBrains Mono',monospace; margin-left: auto; }

.machine-bars { display: flex; gap: 6px; align-items: center; }
.mini-bar {
  width: 48px; height: 4px; background: var(--bg4);
  border-radius: 4px; overflow: hidden;
}
.mini-fill { height: 100%; border-radius: 4px; transition: width .5s; }
.fill-ok     { background: var(--green); }
.fill-warn   { background: var(--orange); }
.fill-danger { background: var(--red); }

/* ── MODAL ───────────────────────────────── */
.modal-overlay {
  display: none; position: fixed; inset: 0;
  background: rgba(0,0,0,.7); backdrop-filter: blur(4px);
  z-index: 200; align-items: center; justify-content: center;
}
.modal-overlay.open { display: flex; }

.modal {
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: 16px; width: 680px; max-width: 95vw;
  max-height: 90vh; overflow-y: auto;
  animation: modalIn .3s cubic-bezier(.34,1.56,.64,1);
}
@keyframes modalIn { from{opacity:0;transform:scale(.9)} to{opacity:1;transform:scale(1)} }

.modal-header {
  padding: 20px 24px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
  position: sticky; top: 0; background: var(--bg2); z-index: 1;
}
.modal-title { font-size: 16px; font-weight: 800; }
.modal-close {
  width: 32px; height: 32px; border-radius: 8px;
  background: var(--bg3); border: none; color: var(--text2);
  cursor: pointer; font-size: 18px; display: flex;
  align-items: center; justify-content: center; transition: all .2s;
}
.modal-close:hover { background: var(--red); color: #fff; }

.modal-body { padding: 24px; }

.info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 20px; }
.info-item { background: var(--bg3); border-radius: 8px; padding: 12px; }
.info-label { font-size: 9px; color: var(--text3); letter-spacing: 2px; text-transform: uppercase; font-family:'JetBrains Mono',monospace; margin-bottom: 4px; }
.info-value { font-size: 13px; font-weight: 600; color: var(--text); font-family:'JetBrains Mono',monospace; word-break: break-all; }

.rd-box {
  background: rgba(0,212,170,.06);
  border: 1px solid rgba(0,212,170,.2);
  border-radius: 10px; padding: 16px; margin-bottom: 20px;
  display: flex; align-items: center; justify-content: space-between;
}
.rd-id {
  font-size: 24px; font-weight: 800; letter-spacing: 3px;
  color: var(--accent); font-family: 'JetBrains Mono', monospace;
}
.rd-label { font-size: 10px; color: var(--text2); margin-bottom: 4px; letter-spacing: 1px; }

.desc-box {
  background: var(--bg3); border-radius: 8px; padding: 14px;
  font-size: 13px; color: var(--text); line-height: 1.6;
  margin-bottom: 20px; white-space: pre-wrap;
}

.screenshot-box {
  background: var(--bg0); border-radius: 8px; overflow: hidden;
  border: 1px solid var(--border); margin-bottom: 20px; text-align: center;
}
.screenshot-box img { max-width: 100%; max-height: 400px; object-fit: contain; }

.note-area {
  width: 100%; background: var(--bg3);
  border: 1px solid var(--border); border-radius: 8px;
  padding: 12px; color: var(--text); font-size: 13px;
  font-family: 'Syne', sans-serif; resize: vertical;
  min-height: 80px; margin-bottom: 16px;
  transition: border-color .2s;
}
.note-area:focus { outline: none; border-color: var(--accent); }

.modal-actions { display: flex; gap: 10px; flex-wrap: wrap; }

/* ── TABS ────────────────────────────────── */
.tabs { display: flex; gap: 4px; margin-bottom: 20px; }
.tab {
  padding: 8px 18px; border-radius: 8px;
  font-size: 12px; font-weight: 700; cursor: pointer;
  background: var(--bg2); color: var(--text2);
  border: 1px solid var(--border); transition: all .2s;
  font-family: 'Syne', sans-serif;
}
.tab.active { background: rgba(0,212,170,.1); color: var(--accent); border-color: rgba(0,212,170,.3); }
.tab:hover:not(.active) { background: var(--bg3); color: var(--text); }

/* ── EMPTY STATE ─────────────────────────── */
.empty {
  padding: 60px 20px; text-align: center; color: var(--text3);
  font-size: 13px; font-family: 'JetBrains Mono', monospace;
}
.empty-icon { font-size: 40px; margin-bottom: 12px; opacity: .3; }

/* ── FILTER BAR ──────────────────────────── */
.filter-bar {
  display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap;
  align-items: center;
}
.search-input {
  flex: 1; min-width: 200px;
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: 8px; padding: 9px 14px;
  color: var(--text); font-size: 13px; font-family:'Syne',sans-serif;
  transition: border-color .2s;
}
.search-input:focus { outline: none; border-color: var(--accent); }
.search-input::placeholder { color: var(--text3); }

/* ── TOASTS ──────────────────────────────── */
#toast-container { position: fixed; bottom: 24px; right: 24px; z-index: 9000; display: flex; flex-direction: column; gap: 8px; }
.toast {
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: 10px; padding: 12px 16px;
  font-size: 13px; color: var(--text);
  animation: toastIn .3s ease;
  display: flex; align-items: center; gap: 10px;
  min-width: 260px; box-shadow: 0 8px 24px rgba(0,0,0,.4);
}
.toast.success { border-color: rgba(0,212,170,.4); }
.toast.error   { border-color: rgba(255,71,87,.4); }
@keyframes toastIn { from{opacity:0;transform:translateX(20px)} to{opacity:1;transform:translateX(0)} }

/* ── SCROLLBAR ───────────────────────────── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg0); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text3); }

/* ── VIEWS ───────────────────────────────── */
.view { display: none; }
.view.active { display: block; }

.section-header { display:flex; align-items:center; justify-content:space-between; margin-bottom:16px; }
.section-title { font-size:14px; font-weight:700; display:flex; align-items:center; gap:8px; }

/* ── MACHINE CARDS ───────────────────────── */
.machines-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:16px; }
.machine-card {
  background:var(--bg2); border:1px solid var(--border);
  border-radius:12px; padding:18px; cursor:pointer;
  transition: all .2s; animation: fadeUp .4s ease both;
}
.machine-card:hover { border-color:var(--accent); transform:translateY(-2px); box-shadow:var(--glow2); }
.machine-card-header { display:flex; align-items:center; gap:10px; margin-bottom:14px; }
.machine-card-name { font-size:14px; font-weight:700; }
.machine-card-user { font-size:11px; color:var(--text2); font-family:'JetBrains Mono',monospace; }

.resource-row { margin-bottom:10px; }
.resource-label { display:flex; justify-content:space-between; font-size:10px; color:var(--text2); font-family:'JetBrains Mono',monospace; margin-bottom:4px; }
.resource-bar { height:5px; background:var(--bg4); border-radius:4px; overflow:hidden; }
.resource-fill { height:100%; border-radius:4px; transition:width .8s cubic-bezier(.4,0,.2,1); }

.machine-footer { display:flex; justify-content:space-between; align-items:center; margin-top:14px; padding-top:14px; border-top:1px solid var(--border); }
.machine-ip-text { font-size:10px; color:var(--text3); font-family:'JetBrains Mono',monospace; }
</style>
</head>
<body>

<!-- SIDEBAR -->
<nav class="sidebar">
  <div class="sidebar-logo">
    <div class="logo-icon">U</div>
    <div>
      <div class="logo-text">UPTIME</div>
      <div class="logo-sub">SERVICE RMM</div>
    </div>
  </div>
  <div class="nav">
    <div class="nav-section">NAVIGAZIONE</div>
    <div class="nav-item active" onclick="showView('overview')">
      <span>⬡</span> Overview
    </div>
    <div class="nav-item" onclick="showView('tickets')">
      <span>◈</span> Ticket
      <span class="badge" id="nav-badge-tickets">0</span>
    </div>
    <div class="nav-item" onclick="showView('machines')">
      <span>◉</span> Macchine
      <span class="badge green" id="nav-badge-machines">0</span>
    </div>
    <div class="nav-section">SISTEMA</div>
    <div class="nav-item" onclick="loadDemo()">
      <span>◎</span> Carica Demo
    </div>
    <div class="nav-item" onclick="refreshAll()">
      <span>↺</span> Aggiorna
    </div>
  </div>
  <div class="sidebar-footer">
    <span class="status-dot"></span>LIVE
    <span id="last-refresh" style="float:right;color:var(--text3)">--:--</span>
  </div>
</nav>

<!-- MAIN -->
<div class="main">
  <div class="topbar">
    <div class="topbar-title">Uptime <span>Dashboard</span></div>
    <div class="topbar-actions">
      <span style="font-size:11px;color:var(--text3);font-family:'JetBrains Mono',monospace">
        API: <span style="color:var(--accent)">{{ api_key }}</span>
      </span>
      <button class="btn btn-primary" onclick="refreshAll()">↺ Refresh</button>
    </div>
  </div>

  <div class="content">

    <!-- ══ OVERVIEW ══ -->
    <div id="view-overview" class="view active">
      <div class="stats-grid" id="stats-grid">
        <div class="stat-card stat-blue">
          <div class="stat-label">Macchine Totali</div>
          <div class="stat-value" id="s-total">—</div>
          <div class="stat-sub">dispositivi monitorati</div>
          <div class="stat-icon">◉</div>
        </div>
        <div class="stat-card stat-green">
          <div class="stat-label">Online</div>
          <div class="stat-value" id="s-online">—</div>
          <div class="stat-sub">connesse ora</div>
          <div class="stat-icon">●</div>
        </div>
        <div class="stat-card stat-red">
          <div class="stat-label">Offline</div>
          <div class="stat-value" id="s-offline">—</div>
          <div class="stat-sub">non raggiungibili</div>
          <div class="stat-icon">○</div>
        </div>
        <div class="stat-card stat-orange">
          <div class="stat-label">Ticket Aperti</div>
          <div class="stat-value" id="s-open">—</div>
          <div class="stat-sub">da gestire</div>
          <div class="stat-icon">◈</div>
        </div>
        <div class="stat-card stat-red">
          <div class="stat-label">Urgenti</div>
          <div class="stat-value" id="s-urgent">—</div>
          <div class="stat-sub">priorità alta</div>
          <div class="stat-icon">⚠</div>
        </div>
      </div>

      <div class="grid-2">
        <!-- Ultimi Ticket -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title"><span class="dot"></span>Ultimi Ticket</div>
            <button class="btn btn-ghost" style="font-size:11px;padding:6px 12px" onclick="showView('tickets')">Vedi tutti →</button>
          </div>
          <div class="panel-body" id="overview-tickets"></div>
        </div>

        <!-- Macchine -->
        <div class="panel">
          <div class="panel-header">
            <div class="panel-title"><span class="dot"></span>Stato Macchine</div>
            <button class="btn btn-ghost" style="font-size:11px;padding:6px 12px" onclick="showView('machines')">Vedi tutte →</button>
          </div>
          <div class="panel-body" id="overview-machines"></div>
        </div>
      </div>
    </div>

    <!-- ══ TICKETS ══ -->
    <div id="view-tickets" class="view">
      <div class="section-header">
        <div class="section-title">◈ Gestione Ticket</div>
      </div>
      <div class="filter-bar">
        <input class="search-input" type="text" id="ticket-search" placeholder="Cerca per PC, utente, descrizione..." oninput="filterTickets()">
        <div class="tabs" style="margin:0">
          <div class="tab active" onclick="setTicketFilter('all',this)">Tutti</div>
          <div class="tab" onclick="setTicketFilter('open',this)">Aperti</div>
          <div class="tab" onclick="setTicketFilter('closed',this)">Chiusi</div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-body" id="tickets-list"></div>
      </div>
    </div>

    <!-- ══ MACHINES ══ -->
    <div id="view-machines" class="view">
      <div class="section-header">
        <div class="section-title">◉ Macchine Monitorate</div>
      </div>
      <div class="filter-bar">
        <input class="search-input" type="text" id="machine-search" placeholder="Cerca per nome, utente, IP..." oninput="filterMachines()">
        <div class="tabs" style="margin:0">
          <div class="tab active" onclick="setMachineFilter('all',this)">Tutte</div>
          <div class="tab" onclick="setMachineFilter('online',this)">Online</div>
          <div class="tab" onclick="setMachineFilter('offline',this)">Offline</div>
        </div>
      </div>
      <div class="machines-grid" id="machines-grid"></div>
    </div>

  </div>
</div>

<!-- MODAL TICKET -->
<div class="modal-overlay" id="ticket-modal" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="modal-header">
      <div class="modal-title" id="modal-title">Ticket #—</div>
      <button class="modal-close" onclick="closeModal()">✕</button>
    </div>
    <div class="modal-body" id="modal-body"></div>
  </div>
</div>

<!-- TOAST -->
<div id="toast-container"></div>

<script>
const API_KEY = "{{ api_key }}";
const H = { "X-API-Key": API_KEY, "Content-Type": "application/json" };

let allTickets = [], allMachines = [];
let ticketFilter = 'all', machineFilter = 'all';

// ── FETCH ───────────────────────────────────────────────────
async function api(path, opts={}) {
  const r = await fetch(path, { headers: H, ...opts });
  return r.json();
}

async function refreshAll() {
  await Promise.all([loadStats(), loadTickets(), loadMachines()]);
  const now = new Date();
  document.getElementById('last-refresh').textContent =
    now.toLocaleTimeString('it-IT', {hour:'2-digit',minute:'2-digit'});
}

async function loadStats() {
  const s = await api('/api/stats');
  document.getElementById('s-total').textContent  = s.total_machines;
  document.getElementById('s-online').textContent  = s.online_machines;
  document.getElementById('s-offline').textContent = s.offline_machines;
  document.getElementById('s-open').textContent   = s.open_tickets;
  document.getElementById('s-urgent').textContent  = s.urgent_tickets;
  document.getElementById('nav-badge-tickets').textContent = s.open_tickets;
  document.getElementById('nav-badge-machines').textContent = s.online_machines;
}

async function loadTickets() {
  allTickets = await api('/api/tickets');
  renderOverviewTickets();
  renderTicketsList();
}

async function loadMachines() {
  allMachines = await api('/api/machines');
  renderOverviewMachines();
  renderMachinesGrid();
}

// ── RENDER TICKET ────────────────────────────────────────────
function timeAgo(iso) {
  const diff = Date.now() - new Date(iso);
  const m = Math.floor(diff/60000);
  if(m < 1)  return 'Adesso';
  if(m < 60) return `${m}m fa`;
  const h = Math.floor(m/60);
  if(h < 24) return `${h}h fa`;
  return `${Math.floor(h/24)}g fa`;
}

function priorityBar(p) {
  const cls = p==='urgent'?'priority-urgent': p==='low'?'priority-low':'priority-normal';
  return `<div class="ticket-priority ${cls}"></div>`;
}

function statusBadge(s, p) {
  if(p==='urgent' && s==='open') return `<span class="ticket-badge badge-urgent">URGENTE</span>`;
  if(s==='open')   return `<span class="ticket-badge badge-open">APERTO</span>`;
  return `<span class="ticket-badge badge-closed">CHIUSO</span>`;
}

function ticketHTML(t) {
  return `
  <div class="ticket-item" onclick="openTicket(${t.id})">
    ${priorityBar(t.priority)}
    <div class="ticket-body">
      <div class="ticket-title">${escHtml(t.description)}</div>
      <div class="ticket-meta">
        <span>🖥 ${t.pc_name}</span>
        <span>👤 ${t.user}</span>
        ${t.rustdesk_id ? `<span style="color:var(--accent)">⬡ ${t.rustdesk_id}</span>` : ''}
        <span>📡 ${t.ip}</span>
      </div>
    </div>
    <div style="display:flex;flex-direction:column;align-items:flex-end;gap:6px">
      ${statusBadge(t.status, t.priority)}
      <span class="ticket-time">${timeAgo(t.created_at)}</span>
    </div>
  </div>`;
}

function renderOverviewTickets() {
  const el = document.getElementById('overview-tickets');
  const list = allTickets.slice(0,8);
  el.innerHTML = list.length ? list.map(ticketHTML).join('') :
    `<div class="empty"><div class="empty-icon">◈</div>Nessun ticket</div>`;
}

function renderTicketsList() {
  const el = document.getElementById('tickets-list');
  const q = document.getElementById('ticket-search').value.toLowerCase();
  let list = allTickets.filter(t => {
    if(ticketFilter==='open'   && t.status!=='open')   return false;
    if(ticketFilter==='closed' && t.status!=='closed') return false;
    if(q && !`${t.pc_name} ${t.user} ${t.description} ${t.ip}`.toLowerCase().includes(q)) return false;
    return true;
  });
  el.innerHTML = list.length ? list.map(ticketHTML).join('') :
    `<div class="empty"><div class="empty-icon">◈</div>Nessun ticket trovato</div>`;
}

function filterTickets() { renderTicketsList(); }
function setTicketFilter(f, el) {
  ticketFilter = f;
  document.querySelectorAll('#view-tickets .tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  renderTicketsList();
}

// ── RENDER MACHINES ──────────────────────────────────────────
function barColor(v) {
  if(v >= 85) return 'fill-danger';
  if(v >= 60) return 'fill-warn';
  return 'fill-ok';
}

function renderOverviewMachines() {
  const el = document.getElementById('overview-machines');
  el.innerHTML = allMachines.slice(0,8).map(m => `
    <div class="machine-item" onclick="openMachineTickets('${m.id}')">
      <div class="machine-status status-${m.status}"></div>
      <div style="flex:1;min-width:0">
        <div class="machine-name">${m.pc_name}</div>
        <div class="machine-user">${m.user}</div>
      </div>
      <div class="machine-bars">
        <div title="CPU ${m.cpu}%">
          <div class="mini-bar"><div class="mini-fill ${barColor(m.cpu)}" style="width:${m.cpu}%"></div></div>
        </div>
        <div title="RAM ${m.ram}%">
          <div class="mini-bar"><div class="mini-fill ${barColor(m.ram)}" style="width:${m.ram}%"></div></div>
        </div>
        <div title="Disco ${m.disk}%">
          <div class="mini-bar"><div class="mini-fill ${barColor(m.disk)}" style="width:${m.disk}%"></div></div>
        </div>
      </div>
      <div class="machine-ip">${m.ip}</div>
    </div>`).join('') ||
    `<div class="empty"><div class="empty-icon">◉</div>Nessuna macchina</div>`;
}

function renderMachinesGrid() {
  const el = document.getElementById('machines-grid');
  const q = document.getElementById('machine-search').value.toLowerCase();
  let list = allMachines.filter(m => {
    if(machineFilter==='online'  && m.status!=='online')  return false;
    if(machineFilter==='offline' && m.status!=='offline') return false;
    if(q && !`${m.pc_name} ${m.user} ${m.ip} ${m.domain}`.toLowerCase().includes(q)) return false;
    return true;
  });

  el.innerHTML = list.length ? list.map((m,i) => `
    <div class="machine-card" style="animation-delay:${i*0.05}s">
      <div class="machine-card-header">
        <div class="machine-status status-${m.status}" style="width:12px;height:12px"></div>
        <div>
          <div class="machine-card-name">${m.pc_name}</div>
          <div class="machine-card-user">${m.user} · ${m.domain}</div>
        </div>
      </div>

      <div class="resource-row">
        <div class="resource-label"><span>CPU</span><span>${m.cpu}%</span></div>
        <div class="resource-bar"><div class="resource-fill ${barColor(m.cpu)}" style="width:${m.cpu}%"></div></div>
      </div>
      <div class="resource-row">
        <div class="resource-label"><span>RAM</span><span>${m.ram}%</span></div>
        <div class="resource-bar"><div class="resource-fill ${barColor(m.ram)}" style="width:${m.ram}%"></div></div>
      </div>
      <div class="resource-row">
        <div class="resource-label"><span>DISCO</span><span>${m.disk}%</span></div>
        <div class="resource-bar"><div class="resource-fill ${barColor(m.disk)}" style="width:${m.disk}%"></div></div>
      </div>

      <div class="machine-footer">
        <span class="machine-ip-text">📡 ${m.ip}</span>
        ${m.rustdesk_id ? `
          <button class="btn btn-primary" style="font-size:11px;padding:5px 12px"
            onclick="event.stopPropagation();connectRustdesk('${m.rustdesk_id}')">
            ⬡ Connetti
          </button>` : `<span style="font-size:10px;color:var(--text3);font-family:'JetBrains Mono',monospace">${m.status==='online'?'RustDesk N/D':'Offline'}</span>`}
      </div>
    </div>`).join('') :
    `<div class="empty" style="grid-column:1/-1"><div class="empty-icon">◉</div>Nessuna macchina trovata</div>`;
}

function filterMachines() { renderMachinesGrid(); }
function setMachineFilter(f, el) {
  machineFilter = f;
  document.querySelectorAll('#view-machines .tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  renderMachinesGrid();
}

// ── MODAL ────────────────────────────────────────────────────
async function openTicket(id) {
  const t = await api(`/api/ticket/${id}`);
  document.getElementById('modal-title').textContent = `Ticket #${t.id} — ${t.pc_name}`;

  let screenshotHtml = '';
  if(t.screenshot) {
    screenshotHtml = `
      <div style="font-size:11px;color:var(--text2);margin-bottom:8px;letter-spacing:1px;text-transform:uppercase;font-family:'JetBrains Mono',monospace">📸 Screenshot</div>
      <div class="screenshot-box"><img src="data:image/png;base64,${t.screenshot}" alt="Screenshot"></div>`;
  }

  let rdHtml = t.rustdesk_id ? `
    <div class="rd-box">
      <div>
        <div class="rd-label">RUSTDESK ID — Connessione Remota</div>
        <div class="rd-id">${t.rustdesk_id}</div>
      </div>
      <button class="btn btn-primary" onclick="connectRustdesk('${t.rustdesk_id}')">⬡ Connetti</button>
    </div>` : '';

  document.getElementById('modal-body').innerHTML = `
    <div class="info-grid">
      <div class="info-item"><div class="info-label">Nome PC</div><div class="info-value">${t.pc_name}</div></div>
      <div class="info-item"><div class="info-label">Utente</div><div class="info-value">${t.user}</div></div>
      <div class="info-item"><div class="info-label">IP Locale</div><div class="info-value">${t.ip}</div></div>
      <div class="info-item"><div class="info-label">Stato</div><div class="info-value">${t.status.toUpperCase()}</div></div>
      <div class="info-item"><div class="info-label">Priorità</div><div class="info-value">${t.priority.toUpperCase()}</div></div>
      <div class="info-item"><div class="info-label">Creato</div><div class="info-value">${new Date(t.created_at).toLocaleString('it-IT')}</div></div>
    </div>

    ${rdHtml}

    <div style="font-size:11px;color:var(--text2);margin-bottom:8px;letter-spacing:1px;text-transform:uppercase;font-family:'JetBrains Mono',monospace">Descrizione</div>
    <div class="desc-box">${escHtml(t.description)}</div>

    ${screenshotHtml}

    <div style="font-size:11px;color:var(--text2);margin-bottom:8px;letter-spacing:1px;text-transform:uppercase;font-family:'JetBrains Mono',monospace">Note Tecnician</div>
    <textarea class="note-area" id="note-input" placeholder="Aggiungi note di lavorazione...">${t.note||''}</textarea>

    <div class="modal-actions">
      ${t.status==='open' ?
        `<button class="btn btn-primary" onclick="updateTicket(${t.id},'status','closed')">✓ Chiudi Ticket</button>
         <button class="btn btn-danger"  onclick="updateTicket(${t.id},'priority','urgent')">⚠ Segna Urgente</button>` :
        `<button class="btn btn-ghost"   onclick="updateTicket(${t.id},'status','open')">↺ Riapri</button>`}
      <button class="btn btn-ghost" onclick="saveNote(${t.id})">💾 Salva Note</button>
      <button class="btn btn-ghost" onclick="closeModal()">Chiudi</button>
    </div>`;

  document.getElementById('ticket-modal').classList.add('open');
}

function closeModal() {
  document.getElementById('ticket-modal').classList.remove('open');
}

async function updateTicket(id, field, val) {
  await api(`/api/ticket/${id}`, { method:'PATCH', body: JSON.stringify({[field]: val}) });
  closeModal();
  toast(`Ticket aggiornato`, 'success');
  refreshAll();
}

async function saveNote(id) {
  const note = document.getElementById('note-input').value;
  await api(`/api/ticket/${id}`, { method:'PATCH', body: JSON.stringify({note}) });
  toast('Note salvate', 'success');
}

function openMachineTickets(machineId) {
  // filtra ticket per macchina
  showView('tickets');
  ticketFilter = 'all';
  // filtra in base all'ID macchina
  const machine = allMachines.find(m=>m.id===machineId);
  if(machine) {
    document.getElementById('ticket-search').value = machine.pc_name;
    filterTickets();
  }
}

function connectRustdesk(id) {
  // Apre RustDesk con l'ID — funziona se installato localmente
  window.open(`rustdesk://${id}`, '_blank');
  toast(`Avvio connessione RustDesk → ${id}`, 'success');
}

// ── VIEWS ────────────────────────────────────────────────────
function showView(name) {
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.getElementById(`view-${name}`).classList.add('active');
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  const idx = {overview:0,tickets:1,machines:2}[name];
  if(idx !== undefined) document.querySelectorAll('.nav-item')[idx].classList.add('active');
}

// ── DEMO ─────────────────────────────────────────────────────
async function loadDemo() {
  await api('/api/demo', {method:'POST'});
  toast('Dati demo caricati!', 'success');
  refreshAll();
}

// ── UTILS ────────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function toast(msg, type='success') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span>${type==='success'?'✓':'✕'}</span> ${msg}`;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(()=>el.remove(), 3500);
}


// ── WebSocket Dashboard ───────────────────────────────────────
let dashWs = null;
let cmdLogLocal = [];

function connectDashWs() {
  const wsUrl = window.location.href
    .replace("https://","wss://").replace("http://","ws://")
    .replace(/\/$/, "") + "/ws/dashboard";

  dashWs = new WebSocket(wsUrl);

  dashWs.onopen = () => {
    document.getElementById("ws-dot").style.background = "var(--accent)";
    document.getElementById("ws-status").textContent = "Connesso (live)";
  };

  dashWs.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      if(msg.type === "update") {
        allMachines = msg.machines || allMachines;
        allTickets  = msg.tickets  || allTickets;
        const s     = msg.stats || {};
        // Aggiorna stats
        document.getElementById("s-orgs").textContent    = s.total_orgs    || "—";
        document.getElementById("s-total").textContent   = s.total_machines || "—";
        document.getElementById("s-online").textContent  = s.online_machines|| "—";
        document.getElementById("s-offline").textContent = s.offline_machines||"—";
        document.getElementById("s-open").textContent    = s.open_tickets   || "—";
        document.getElementById("s-urgent").textContent  = s.urgent_tickets || "—";
        document.getElementById("nb-t").textContent      = s.open_tickets   || "0";
        document.getElementById("nb-dev").textContent    = s.total_machines || "0";
        document.getElementById("nb-agents").textContent = s.connected_agents||"0";

        // Aggiorna selettore device
        const sel = document.getElementById("cmd-target");
        const cur = sel.value;
        sel.innerHTML = '<option value="">— Seleziona device —</option>' +
          allMachines.map(m => {
            const connected = (msg.connected_agents||[]).includes(m.id);
            return `<option value="${m.id}"${m.id===cur?' selected':''} ${!connected?'disabled':''}>
              ${connected?'🟢':'🔴'} ${m.pc_name} (${m.user}) ${!connected?'— offline':'— connesso'}
            </option>`;
          }).join('');

        // Aggiorna log comandi
        if(msg.cmd_log) updateCmdLog(msg.cmd_log);

        // Aggiorna render corrente
        const active = document.querySelector('.view.active');
        if(active) {
          if(active.id==='view-overview') renderOverview();
          else if(active.id==='view-devices') renderDevices();
          else if(active.id==='view-tickets') renderTickets();
        }
      }
    } catch(e) {}
  };

  dashWs.onerror = () => {
    document.getElementById("ws-dot").style.background = "var(--red)";
    document.getElementById("ws-status").textContent = "Errore connessione";
  };

  dashWs.onclose = () => {
    document.getElementById("ws-dot").style.background = "var(--orange)";
    document.getElementById("ws-status").textContent = "Disconnesso — riconnessione...";
    setTimeout(connectDashWs, 5000);
  };
}

// ── Invio comandi ─────────────────────────────────────────────
async function sendCmd(cmd, params) {
  const mid = document.getElementById("cmd-target").value;
  if(!mid) { toast("Seleziona un device!", "err"); return; }

  const machine = allMachines.find(m=>m.id===mid);
  const pcName = machine ? machine.pc_name : mid;

  // Conferma per comandi pericolosi
  if(cmd==="reboot"&&!confirm(`Riavviare ${pcName}?`)) return;
  if(cmd==="shutdown"&&!confirm(`Spegnere ${pcName}?`)) return;

  try {
    const r = await api("/api/command", {
      method:"POST",
      body: JSON.stringify({machine_id:mid, command:cmd, params})
    });
    if(r.ok) toast(`Comando ${cmd} inviato a ${pcName}`);
    else toast(r.error||"Errore invio comando","err");
  } catch(e) {
    toast("Device non connesso o errore rete","err");
  }
}

function updateCmdLog(log) {
  const el = document.getElementById("cmd-log");
  if(!el) return;
  el.innerHTML = log.map(c => {
    const isScreenshot = c.command==="screenshot" && c.status==="done" && c.output && c.output.length>100;
    const statusColor = c.status==="done"?"var(--green)":c.status==="error"?"var(--red)":"var(--orange)";
    return `<div style="padding:12px 18px;border-bottom:1px solid rgba(42,53,71,.4);display:flex;align-items:flex-start;gap:12px">
      <div style="flex-shrink:0;font-size:9px;color:var(--text3);font-family:monospace;margin-top:2px;white-space:nowrap">
        ${new Date(c.sent_at).toLocaleTimeString("it-IT")}
      </div>
      <div style="flex:1;min-width:0">
        <div style="font-size:12px;font-weight:700;margin-bottom:3px">
          <span style="color:var(--accent2)">${c.pc_name}</span>
          <span style="color:var(--text2);font-weight:400"> → </span>
          <span style="color:var(--text)">${c.command}</span>
          <span style="color:${statusColor};font-size:10px;margin-left:8px;font-family:monospace">[${c.status}]</span>
        </div>
        ${isScreenshot
          ? `<button class="btn btn-g" style="font-size:10px;padding:4px 10px" onclick="showScreenshot('${c.output.substring(0,50)}',event,${c.id})">📸 Visualizza screenshot</button>`
          : c.output ? `<div style="font-size:11px;color:var(--text2);font-family:monospace;background:var(--bg3);padding:6px 10px;border-radius:5px;white-space:pre-wrap;max-height:80px;overflow:hidden">${c.output.substring(0,300)}</div>` : ""
        }
      </div>
    </div>`;
  }).join("") || '<div class="empty"><div class="empty-icon">⚡</div>Nessun comando eseguito</div>';

  // Salva screenshot per visualizzazione
  window._cmdScreenshots = {};
  log.forEach(c => {
    if(c.command==="screenshot" && c.status==="done" && c.output && c.output.length>100)
      window._cmdScreenshots[c.id] = c.output;
  });
}

function showScreenshot(_, event, cid) {
  event.stopPropagation();
  const b64 = window._cmdScreenshots && window._cmdScreenshots[cid];
  if(!b64) { toast("Screenshot non disponibile","err"); return; }
  document.getElementById("screenshot-img").src = "data:image/png;base64," + b64;
  document.getElementById("screenshot-preview").style.display = "block";
  document.getElementById("screenshot-preview").scrollIntoView({behavior:"smooth"});
}

// Avvia WS al caricamento
connectDashWs();

// ── INIT ─────────────────────────────────────────────────────
refreshAll();
setInterval(refreshAll, 30000); // auto-refresh ogni 30s
</script>
</body>
</html>

"""
