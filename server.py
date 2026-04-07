"""
Uptime Service — Dashboard Server v2
Flask + memoria — Organizzazioni / Sedi / Reparti / Device
"""
from flask import Flask, request, jsonify, abort, Response
from flask_cors import CORS
import os, hashlib, threading
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
CORS(app)
API_KEY = os.environ.get("UPTIME_API_KEY", "uptime-sos-2025")

# ── Store in memoria ──────────────────────────────────────────
_lock     = threading.Lock()
machines  = {}   # mid -> dict
tickets   = []
_tid      = [1]
orgs      = {}   # oid -> {id,name,color,created_at}
sites     = {}   # sid -> {id,oid,name,address,created_at}
depts     = {}   # did -> {id,sid,oid,name,created_at}
_oid      = [1]
_sid      = [1]
_did      = [1]

def _now(): return datetime.now().isoformat()

# ── Auth ──────────────────────────────────────────────────────
def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if key != API_KEY:
            abort(401)
        return f(*args, **kwargs)
    return decorated

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
        # Rimuovi sedi e reparti collegati
        to_del_s = [s for s,v in sites.items() if v["oid"]==oid]
        for s in to_del_s:
            [depts.pop(dd) for dd in [k for k,v in depts.items() if v["sid"]==s]]
            sites.pop(s)
        # Deassegna macchine
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
        # Org
        orgs["1"]={"id":"1","name":"Emotion Design Srl","color":"#00d4aa","created_at":_now()}
        orgs["2"]={"id":"2","name":"Cliente Rossi Spa","color":"#0091ff","created_at":_now()}
        _oid[0]=3
        # Sedi
        sites["1"]={"id":"1","oid":"1","name":"Sede Milano","address":"Via Roma 1, Milano","created_at":_now()}
        sites["2"]={"id":"2","oid":"1","name":"Sede Roma","address":"Via Veneto 10, Roma","created_at":_now()}
        sites["3"]={"id":"3","oid":"2","name":"Sede Principale","address":"Corso Italia 5, Torino","created_at":_now()}
        _sid[0]=4
        # Reparti
        depts["1"]={"id":"1","sid":"1","oid":"1","name":"Amministrazione","created_at":_now()}
        depts["2"]={"id":"2","sid":"1","oid":"1","name":"IT","created_at":_now()}
        depts["3"]={"id":"3","sid":"2","oid":"1","name":"Commerciale","created_at":_now()}
        _did[0]=4
        # Macchine
        ms=[
            {"id":"abc001","pc_name":"DESKTOP-MARIO","user":"mario.rossi","domain":"EMOTIONDESIGN","ip":"192.168.1.10","os":"Windows 11 Pro","rustdesk_id":"123 456 789","last_seen":_now(),"status":"online","cpu":45,"ram":62,"disk":78,"oid":"1","sid":"1","did":"1"},
            {"id":"abc002","pc_name":"LAPTOP-GIULIA","user":"giulia.bianchi","domain":"EMOTIONDESIGN","ip":"192.168.1.11","os":"Windows 10 Pro","rustdesk_id":"987 654 321","last_seen":_now(),"status":"online","cpu":12,"ram":34,"disk":45,"oid":"1","sid":"1","did":"2"},
            {"id":"abc003","pc_name":"PC-CONTABILITA","user":"admin","domain":"WORKGROUP","ip":"192.168.1.20","os":"Windows 10 Home","rustdesk_id":"","last_seen":"2020-01-01","status":"offline","cpu":0,"ram":0,"disk":0,"oid":"1","sid":"2","did":"3"},
            {"id":"abc004","pc_name":"SERVER-FILE","user":"Administrator","domain":"EMOTIONDESIGN","ip":"192.168.1.1","os":"Windows Server 2022","rustdesk_id":"111 222 333","last_seen":_now(),"status":"online","cpu":78,"ram":88,"disk":92,"oid":"2","sid":"3","did":None},
        ]
        for m in ms: machines[m["id"]]=m
        # Ticket
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

/* ── SIDEBAR ── */
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

/* ── ORG TREE in sidebar ── */
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
.tree-site-header.active{color:var(--accent2)}
.tree-dept{display:flex;align-items:center;gap:7px;padding:5px 10px 5px 26px;border-radius:6px;cursor:pointer;font-size:11px;color:var(--text3);transition:all .2s}
.tree-dept:hover{background:var(--bg3);color:var(--text2)}
.tree-dept.active{color:var(--accent);background:rgba(0,212,170,.06)}
.tree-count{margin-left:auto;font-size:9px;color:var(--text3);font-family:'JetBrains Mono',monospace}

/* ── MAIN ── */
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.topbar{padding:14px 24px;background:var(--bg1);border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.topbar-left{display:flex;align-items:center;gap:12px}
.topbar-title{font-size:17px;font-weight:800}
.topbar-title span{color:var(--accent)}
.breadcrumb{font-size:11px;color:var(--text2);font-family:'JetBrains Mono',monospace}
.breadcrumb span{color:var(--accent)}
.topbar-right{display:flex;align-items:center;gap:10px}
.btn{padding:7px 14px;border-radius:7px;font-size:11px;font-weight:700;cursor:pointer;border:none;transition:all .2s;font-family:'Syne',sans-serif}
.btn-p{background:var(--accent);color:#000}.btn-p:hover{background:#00f0c0}
.btn-g{background:var(--bg3);color:var(--text2);border:1px solid var(--border)}.btn-g:hover{background:var(--bg4);color:var(--text)}
.btn-d{background:rgba(255,71,87,.12);color:var(--red);border:1px solid rgba(255,71,87,.25)}.btn-d:hover{background:rgba(255,71,87,.22)}
.btn-b{background:rgba(0,145,255,.12);color:var(--accent2);border:1px solid rgba(0,145,255,.25)}.btn-b:hover{background:rgba(0,145,255,.22)}
.content{flex:1;overflow-y:auto;padding:22px 24px}

/* ── STATS ── */
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

/* ── ORG CARDS ── */
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

/* ── DEVICE TABLE ── */
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

/* ── TICKET LIST ── */
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

/* ── MODAL ── */
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

/* ── TOAST ── */
#toasts{position:fixed;bottom:20px;right:20px;z-index:9000;display:flex;flex-direction:column;gap:7px}
.toast{background:var(--bg2);border:1px solid rgba(0,212,170,.3);border-radius:9px;padding:10px 14px;font-size:12px;color:var(--text);display:flex;align-items:center;gap:9px;min-width:240px;box-shadow:0 8px 24px rgba(0,0,0,.4);animation:tin .3s ease}
@keyframes tin{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:translateX(0)}}

/* ── FILTER BAR ── */
.filter-bar{display:flex;gap:10px;margin-bottom:18px;flex-wrap:wrap;align-items:center}
.search-input{flex:1;min-width:180px;background:var(--bg2);border:1px solid var(--border);border-radius:7px;padding:8px 12px;color:var(--text);font-size:12px;font-family:'Syne',sans-serif}
.search-input:focus{outline:none;border-color:var(--accent)}
.search-input::placeholder{color:var(--text3)}
.tabs{display:flex;gap:4px}
.tab{padding:7px 14px;border-radius:7px;font-size:11px;font-weight:700;cursor:pointer;background:var(--bg2);color:var(--text2);border:1px solid var(--border);transition:all .2s;font-family:'Syne',sans-serif}
.tab.active{background:rgba(0,212,170,.1);color:var(--accent);border-color:rgba(0,212,170,.3)}

::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:var(--bg0)}::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
.view{display:none}.view.active{display:block}
.grid2{display:grid;grid-template-columns:1fr 360px;gap:18px}
.empty{padding:50px 20px;text-align:center;color:var(--text3);font-size:12px;font-family:'JetBrains Mono',monospace}
.empty-icon{font-size:36px;margin-bottom:10px;opacity:.25}
.color-swatches{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
.swatch{width:24px;height:24px;border-radius:6px;cursor:pointer;border:2px solid transparent;transition:all .2s}
.swatch.sel{border-color:#fff;transform:scale(1.15)}
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
      <span style="font-size:10px;color:var(--text3);font-family:'JetBrains Mono',monospace">API: <span style="color:var(--accent)">{{ api_key }}</span></span>
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

<script>
const API = "{{ api_key }}";
const H = {"X-API-Key":API,"Content-Type":"application/json"};
let allOrgs=[], allSites=[], allDepts=[], allMachines=[], allTickets=[];
let devFilter='all', tFilter='all';
let selColor='#00d4aa';

async function api(path,opts={}){
  const r=await fetch(path,{headers:H,...opts});
  if(!r.ok) throw new Error(r.status);
  return r.json();
}

// ── LOAD ─────────────────────────────────────────────────────
async function refreshAll(){
  await Promise.all([loadStats(),loadOrgs(),loadSites(),loadDepts(),loadMachines(),loadTickets()]);
  renderTree(); renderOrgCards(); renderDevices(); renderTickets(); renderOverview();
  document.getElementById('clk').textContent=new Date().toLocaleTimeString('it-IT',{hour:'2-digit',minute:'2-digit'});
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

// ── ORG TREE (sidebar) ────────────────────────────────────────
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
              ${sDepts.length?`<span class="tree-chevron" id="schev${s.id}">▶</span>`:''}
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

function toggleTreeOrg(id,el){
  const c=document.getElementById(id);
  const chev=c.previousElementSibling?.querySelector('.tree-chevron');
  if(c){c.classList.toggle('open');if(chev)chev.classList.toggle('open')}
}
function toggleTreeSite(id){
  const c=document.getElementById(id);
  if(c)c.classList.toggle('open');
}

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
  const org=allOrgs.find(o=>o.id===oid);
  if(!org)return;
  const oSites=allSites.filter(s=>s.oid===oid);
  let filteredMachines=allMachines.filter(m=>m.oid===oid);
  let bc=`<span style="color:var(--accent)">${org.name}</span>`;
  if(sid){filteredMachines=filteredMachines.filter(m=>m.sid===sid);const s=allSites.find(x=>x.id===sid);if(s)bc+=` / ${s.name}`}
  if(did){filteredMachines=filteredMachines.filter(m=>m.did===did);const d=allDepts.find(x=>x.id===did);if(d)bc+=` / ${d.name}`}
  document.getElementById('breadcrumb').innerHTML='&nbsp;/&nbsp;'+bc;

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
      <div class="ph">
        <div class="ptitle"><span class="pdot"></span>Device (${filteredMachines.length})</div>
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
function showModal(title, body){
  document.getElementById('modal-title').textContent=title;
  document.getElementById('modal-body').innerHTML=body;
  document.getElementById('modal').classList.add('open');
}
function closeModal(){document.getElementById('modal').classList.remove('open')}

const COLORS=['#00d4aa','#0091ff','#ffa502','#ff4757','#a78bfa','#ffd32a','#2ed573','#ff6b81','#eccc68','#1e90ff'];

function colorSwatches(sel){
  return`<div class="color-swatches">${COLORS.map(c=>`<div class="swatch${c===sel?' sel':''}" style="background:${c}" onclick="selColor='${c}';document.querySelectorAll('.swatch').forEach(s=>s.classList.remove('sel'));this.classList.add('sel')"></div>`).join('')}</div>`;
}

// Nuova Org
function openNewOrg(){
  selColor='#00d4aa';
  showModal('Nuova Organizzazione',`
    <div class="form-row"><label class="form-label">Nome organizzazione</label><input class="form-input" id="f-org-name" placeholder="Es. Emotion Design Srl"></div>
    <div class="form-row"><label class="form-label">Colore</label>${colorSwatches('#00d4aa')}</div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="saveOrg()">Crea Organizzazione</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}
async function saveOrg(){
  const name=document.getElementById('f-org-name').value.trim();
  if(!name){toast('Inserisci il nome','err');return}
  await api('/api/orgs',{method:'POST',body:JSON.stringify({name,color:selColor})});
  closeModal(); toast('Organizzazione creata!'); refreshAll();
}

// Modifica Org
function openEditOrg(oid){
  const o=allOrgs.find(x=>x.id===oid); if(!o)return;
  selColor=o.color;
  showModal(`Modifica — ${o.name}`,`
    <div class="form-row"><label class="form-label">Nome</label><input class="form-input" id="f-org-name" value="${o.name}"></div>
    <div class="form-row"><label class="form-label">Colore</label>${colorSwatches(o.color)}</div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="updateOrg('${oid}')">Salva</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}
async function updateOrg(oid){
  const name=document.getElementById('f-org-name').value.trim();
  await api(`/api/orgs/${oid}`,{method:'PATCH',body:JSON.stringify({name,color:selColor})});
  closeModal(); toast('Salvato!'); refreshAll();
}
async function deleteOrg(oid){
  if(!confirm('Eliminare questa organizzazione?'))return;
  await api(`/api/orgs/${oid}`,{method:'DELETE'});
  toast('Organizzazione eliminata'); refreshAll();
}

// Nuova Sede
function openNewSite(oid){
  showModal('Nuova Sede',`
    <div class="form-row"><label class="form-label">Nome sede</label><input class="form-input" id="f-site-name" placeholder="Es. Sede Milano"></div>
    <div class="form-row"><label class="form-label">Indirizzo</label><input class="form-input" id="f-site-addr" placeholder="Via Roma 1, Milano"></div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="saveSite('${oid}')">Crea Sede</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}
async function saveSite(oid){
  const name=document.getElementById('f-site-name').value.trim();
  const address=document.getElementById('f-site-addr').value.trim();
  if(!name){toast('Inserisci il nome','err');return}
  await api('/api/sites',{method:'POST',body:JSON.stringify({oid,name,address})});
  closeModal(); toast('Sede creata!'); refreshAll();
}
function openEditSite(sid){
  const s=allSites.find(x=>x.id===sid);if(!s)return;
  showModal(`Modifica Sede — ${s.name}`,`
    <div class="form-row"><label class="form-label">Nome</label><input class="form-input" id="f-site-name" value="${s.name}"></div>
    <div class="form-row"><label class="form-label">Indirizzo</label><input class="form-input" id="f-site-addr" value="${s.address||''}"></div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="updateSite('${sid}')">Salva</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}
async function updateSite(sid){
  const name=document.getElementById('f-site-name').value.trim();
  const address=document.getElementById('f-site-addr').value.trim();
  await api(`/api/sites/${sid}`,{method:'PATCH',body:JSON.stringify({name,address})});
  closeModal(); toast('Sede aggiornata!'); refreshAll();
}
async function deleteSite(sid){
  if(!confirm('Eliminare questa sede?'))return;
  await api(`/api/sites/${sid}`,{method:'DELETE'});
  toast('Sede eliminata'); refreshAll();
}

// Nuovo Reparto
function openNewDept(sid,oid){
  showModal('Nuovo Reparto',`
    <div class="form-row"><label class="form-label">Nome reparto</label><input class="form-input" id="f-dept-name" placeholder="Es. Amministrazione"></div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="saveDept('${sid}','${oid}')">Crea Reparto</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
}
async function saveDept(sid,oid){
  const name=document.getElementById('f-dept-name').value.trim();
  if(!name){toast('Inserisci il nome','err');return}
  await api('/api/depts',{method:'POST',body:JSON.stringify({sid,oid,name})});
  closeModal(); toast('Reparto creato!'); refreshAll();
}
async function deleteDept(did){
  if(!confirm('Eliminare questo reparto?'))return;
  await api(`/api/depts/${did}`,{method:'DELETE'});
  toast('Reparto eliminato'); refreshAll();
}

// Assegna Device
function openAssignModal(preOid){
  if(!allMachines.length){toast('Nessun device disponibile','err');return}
  showModal('Assegna Device',`
    <div class="form-row"><label class="form-label">Device</label>
      <select class="form-select" id="f-mid">
        ${allMachines.map(m=>`<option value="${m.id}">${m.pc_name} (${m.user})</option>`).join('')}
      </select>
    </div>
    <div class="form-row"><label class="form-label">Organizzazione</label>
      <select class="form-select" id="f-aoid" onchange="updateSiteSelect()">
        <option value="">— Non assegnato —</option>
        ${allOrgs.map(o=>`<option value="${o.id}"${o.id===preOid?' selected':''}>${o.name}</option>`).join('')}
      </select>
    </div>
    <div class="form-row"><label class="form-label">Sede</label>
      <select class="form-select" id="f-asid" onchange="updateDeptSelect()">
        <option value="">— Nessuna sede —</option>
      </select>
    </div>
    <div class="form-row"><label class="form-label">Reparto</label>
      <select class="form-select" id="f-adid">
        <option value="">— Nessun reparto —</option>
      </select>
    </div>
    <div class="form-actions">
      <button class="btn btn-p" onclick="saveAssign()">Assegna</button>
      <button class="btn btn-g" onclick="closeModal()">Annulla</button>
    </div>`);
  if(preOid) updateSiteSelect();
}

function openAssignDevice(mid){
  openAssignModal();
  setTimeout(()=>{const s=document.getElementById('f-mid');if(s)s.value=mid},50);
}

function updateSiteSelect(){
  const oid=document.getElementById('f-aoid').value;
  const filtered=allSites.filter(s=>s.oid===oid);
  document.getElementById('f-asid').innerHTML=`<option value="">— Nessuna sede —</option>${filtered.map(s=>`<option value="${s.id}">${s.name}</option>`).join('')}`;
  document.getElementById('f-adid').innerHTML=`<option value="">— Nessun reparto —</option>`;
}
function updateDeptSelect(){
  const sid=document.getElementById('f-asid').value;
  const filtered=allDepts.filter(d=>d.sid===sid);
  document.getElementById('f-adid').innerHTML=`<option value="">— Nessun reparto —</option>${filtered.map(d=>`<option value="${d.id}">${d.name}</option>`).join('')}`;
}
async function saveAssign(){
  const mid=document.getElementById('f-mid').value;
  const oid=document.getElementById('f-aoid').value||null;
  const sid=document.getElementById('f-asid').value||null;
  const did=document.getElementById('f-adid').value||null;
  await api(`/api/machines/${mid}/assign`,{method:'PATCH',body:JSON.stringify({oid,sid,did})});
  closeModal(); toast('Device assegnato!'); refreshAll();
}

// Ticket detail
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

// ── VIEWS ─────────────────────────────────────────────────────
function showView(name,el){
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.getElementById(`view-${name}`).classList.add('active');
  if(el){document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));el.classList.add('active')}
  if(name!=='org-detail')document.getElementById('breadcrumb').innerHTML='';
}

// ── DEMO + UTILS ──────────────────────────────────────────────
async function loadDemo(){await api('/api/demo',{method:'POST'});toast('Demo caricata!');refreshAll()}
function toast(msg,type='ok'){
  const el=document.createElement('div');
  el.className='toast';
  el.style.borderColor=type==='err'?'rgba(255,71,87,.4)':'rgba(0,212,170,.3)';
  el.innerHTML=`<span style="color:${type==='err'?'var(--red)':'var(--accent)'}">${type==='err'?'✕':'✓'}</span> ${msg}`;
  document.getElementById('toasts').appendChild(el);
  setTimeout(()=>el.remove(),3200);
}
function clock(){document.getElementById('clk').textContent=new Date().toLocaleTimeString('it-IT',{hour:'2-digit',minute:'2-digit'})}

// ── INIT ──────────────────────────────────────────────────────
refreshAll();
clock();
setInterval(clock,10000);
setInterval(refreshAll,30000);
</script>
</body>
</html>

"""

@app.route("/")
@app.route("/dashboard")
def dashboard():
    page = DASHBOARD_HTML.replace("{{ api_key }}", API_KEY)
    return Response(page, mimetype="text/html")

if __name__ == "__main__":
    print("Uptime Service Dashboard v2 — http://localhost:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)
