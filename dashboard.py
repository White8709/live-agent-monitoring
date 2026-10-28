#!/usr/bin/env python3
"""Numbat record dashboard — zero-dependency live viewer.

Tails Numbat's findings or records NDJSON stream and sends new records to the
browser via Server-Sent Events. Survives file truncation/rotation by keeping
an in-memory history keyed by record id.
"""
import datetime
import http.server
import io
import json
import os
import queue
import threading
import time
import zipfile

DEFAULT_FINDINGS = os.path.expanduser("~/.numbat/findings.ndjson")
DEFAULT_RECORDS = os.path.expanduser("~/.numbat/records.ndjson")


def default_input():
    configured = os.environ.get("NUMBAT_FINDINGS")
    if configured:
        return configured
    try:
        if os.path.getsize(DEFAULT_FINDINGS) == 0 and os.path.getsize(DEFAULT_RECORDS) > 0:
            return DEFAULT_RECORDS
    except OSError:
        try:
            if os.path.getsize(DEFAULT_RECORDS) > 0:
                return DEFAULT_RECORDS
        except OSError:
            pass
    return DEFAULT_FINDINGS


FINDINGS = default_input()
PORT = int(os.environ.get("NUMBAT_DASH_PORT", "8787"))
ARCHIVE_DIR = os.environ.get(
    "NUMBAT_ARCHIVE_DIR", os.path.expanduser("~/.numbat/archive")
)

clients = []
clients_lock = threading.Lock()
history = []
seen = set()
history_lock = threading.Lock()


def record_key(rec):
    return (
        rec.get("finding_id")
        or rec.get("decision_id")
        or json.dumps(rec, sort_keys=True)
    )


def push_frame(frame):
    with clients_lock:
        for q in list(clients):
            try:
                q.put_nowait(frame)
            except Exception:
                pass


def broadcast_record(data):
    push_frame("data: " + data + "\n\n")


def add_line(line):
    line = line.strip()
    if not line:
        return
    try:
        rec = json.loads(line)
    except Exception:
        return
    key = record_key(rec)
    with history_lock:
        if key in seen:
            return
        seen.add(key)
        history.append(rec)
    broadcast_record(json.dumps(rec))


def watcher():
    pos = 0
    inode = None
    while True:
        try:
            st = os.stat(FINDINGS)
            if inode is None:
                inode = st.st_ino
            if st.st_ino != inode or st.st_size < pos:
                # rotated or truncated: reset offset, keep in-memory history
                pos = 0
                inode = st.st_ino
            if st.st_size > pos:
                with open(FINDINGS, "r") as f:
                    f.seek(pos)
                    while True:
                        start = f.tell()
                        line = f.readline()
                        if not line or not line.endswith("\n"):
                            pos = start  # keep partial line for next pass
                            break
                        add_line(line)
        except FileNotFoundError:
            pass
        except Exception:
            pass
        time.sleep(1)


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Numbat — Live Findings</title>
<style>
:root{
  --bg:#0e1116;--panel:#161b22;--panel2:#1c2430;--border:#2a3441;
  --text:#e6edf3;--muted:#8b98a5;--accent:#4c9be8;
  --high:#f85149;--critical:#ff3860;--medium:#d29922;--low:#3fb950;--info:#4c9be8;
}
@media (prefers-color-scheme:light){
  :root{--bg:#f6f8fa;--panel:#fff;--panel2:#f0f3f6;--border:#d0d7de;
  --text:#1f2328;--muted:#636c76;}
}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:var(--bg);color:var(--text)}
header{position:sticky;top:0;z-index:5;background:var(--panel);
  border-bottom:1px solid var(--border);padding:14px 20px;display:flex;
  align-items:center;gap:14px;flex-wrap:wrap}
h1{font-size:16px;margin:0;font-weight:650;letter-spacing:.2px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--low);
  box-shadow:0 0 0 0 rgba(63,185,80,.6);animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(63,185,80,.5)}
  70%{box-shadow:0 0 0 8px rgba(63,185,80,0)}100%{box-shadow:0 0 0 0 rgba(63,185,80,0)}}
.dot.off{background:var(--high);animation:none}
.spacer{flex:1}
.stat{color:var(--muted);font-size:12px}
.stat b{color:var(--text);font-variant-numeric:tabular-nums}
.wrap{max-width:960px;margin:0 auto;padding:20px}
.empty{color:var(--muted);text-align:center;padding:60px 20px;font-size:15px}
.card{background:var(--panel);border:1px solid var(--border);border-left-width:4px;
  border-radius:10px;padding:14px 16px;margin-bottom:12px;animation:in .35s ease}
@keyframes in{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
.card.flash{box-shadow:0 0 0 2px var(--accent)}
.card.sev-high,.card.sev-critical{border-left-color:var(--high)}
.card.sev-medium{border-left-color:var(--medium)}
.card.sev-low{border-left-color:var(--low)}
.card.sev-info{border-left-color:var(--info)}
.card.enforcement{border-left-color:var(--muted);background:var(--panel2)}
.card.activity{border-left-color:var(--accent)}
.card.indicator{border-left-color:var(--medium)}
.row1{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.badge{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px;
  padding:2px 8px;border-radius:20px;color:#fff}
.badge.high,.badge.critical{background:var(--high)}
.badge.medium{background:var(--medium)}
.badge.low{background:var(--low)}
.badge.info{background:var(--info)}
.badge.enf{background:var(--muted)}
.title{font-weight:650;font-size:15px}
.rule{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;
  color:var(--accent);background:var(--panel2);padding:1px 6px;border-radius:5px}
.time{color:var(--muted);font-size:12px;margin-left:auto;font-variant-numeric:tabular-nums}
.meta{margin-top:8px;display:flex;gap:8px;flex-wrap:wrap}
.chip{font-size:11px;color:var(--muted);border:1px solid var(--border);
  padding:1px 7px;border-radius:5px}
.chip b{color:var(--text);font-weight:600}
.cmd{margin-top:10px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:12px;background:var(--bg);border:1px solid var(--border);border-radius:7px;
  padding:9px 11px;white-space:pre-wrap;word-break:break-all;color:var(--text)}
.tag{font-size:10px;color:var(--medium);border:1px solid var(--medium);
  padding:0 6px;border-radius:4px;text-transform:uppercase;letter-spacing:.3px}
.decision{font-weight:650}
.decision.deny{color:var(--high)}
.decision.allow,.decision.no_override{color:var(--low)}
.btn{font-size:12px;font-weight:600;color:var(--text);text-decoration:none;
  background:var(--panel2);border:1px solid var(--border);border-radius:7px;
  padding:5px 11px;cursor:pointer;white-space:nowrap}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn.danger:hover{border-color:var(--high);color:var(--high)}
.toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%) translateY(8px);
  background:var(--panel);border:1px solid var(--border);border-radius:9px;
  padding:11px 18px;font-size:13px;box-shadow:0 8px 30px rgba(0,0,0,.35);
  opacity:0;transition:opacity .3s,transform .3s;pointer-events:none;z-index:20}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.stats{margin-bottom:20px}
.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
@media(max-width:760px){.tiles{grid-template-columns:repeat(2,1fr)}}
.tile{background:var(--panel);border:1px solid var(--border);border-radius:10px;
  padding:13px 15px}
.tile .num{font-size:27px;font-weight:750;font-variant-numeric:tabular-nums;line-height:1}
.tile .lbl{font-size:10.5px;color:var(--muted);margin-top:7px;text-transform:uppercase;
  letter-spacing:.5px}
.tile.hi .num{color:var(--high)}
.tile.md .num{color:var(--medium)}
.tile.ok .num{color:var(--low)}
.stats2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}
@media(max-width:760px){.stats2{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;
  padding:13px 15px}
.sub{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;
  margin-bottom:11px;display:flex;justify-content:space-between;align-items:center}
.sub .muted{text-transform:none;letter-spacing:0;font-size:11px}
.sevbar{display:flex;height:14px;border-radius:7px;overflow:hidden;background:var(--panel2)}
.sevbar span{display:block;height:100%;transition:width .4s ease}
.sevlegend{display:flex;gap:16px;flex-wrap:wrap;margin-top:11px;font-size:12px;color:var(--muted)}
.sevlegend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:6px;
  vertical-align:middle}
.rule-row{display:flex;align-items:center;gap:9px;margin-bottom:8px;font-size:12px}
.rule-row:last-child{margin-bottom:0}
.rule-row .rname{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--accent);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:60%}
.rule-row .bar{height:8px;border-radius:4px;background:var(--accent);min-width:3px;
  transition:width .4s ease}
.rule-row .rcount{margin-left:auto;color:var(--muted);font-variant-numeric:tabular-nums}
</style></head>
<body>
<header>
  <span class="dot" id="dot"></span>
  <h1>Numbat &middot; Live Agent Monitor</h1>
  <div class="spacer"></div>
  <span class="stat">findings <b id="cFind">0</b></span>
  <span class="stat">decisions <b id="cEnf">0</b></span>
  <span class="stat">events <b id="cEvents">0</b></span>
  <span class="stat">indicators <b id="cIndicators">0</b></span>
  <a class="btn" href="archives" target="_blank">Archives</a>
  <a class="btn" href="export.xlsx">&#8681; Export Excel</a>
  <button class="btn danger" id="resetBtn">&#8635; Reset</button>
  <span class="stat" id="conn">connecting&hellip;</span>
</header>
<div class="wrap">
  <section class="stats">
    <div class="tiles">
      <div class="tile"><div class="num" id="sTotal">0</div><div class="lbl">Findings</div></div>
      <div class="tile hi"><div class="num" id="sHigh">0</div><div class="lbl">High / Critical</div></div>
      <div class="tile md"><div class="num" id="sMed">0</div><div class="lbl">Medium</div></div>
      <div class="tile ok"><div class="num" id="sBlocked">0</div><div class="lbl">Blocked</div></div>
      <div class="tile"><div class="num" id="sRules">0</div><div class="lbl">Rules hit</div></div>
      <div class="tile"><div class="num" id="sAgents">0</div><div class="lbl">Agents</div></div>
      <div class="tile"><div class="num" id="sEvents">0</div><div class="lbl">Events</div></div>
      <div class="tile"><div class="num" id="sIndicators">0</div><div class="lbl">Indicators</div></div>
    </div>
    <div class="stats2">
      <div class="panel">
        <div class="sub">Severity mix</div>
        <div class="sevbar" id="sevbar"></div>
        <div class="sevlegend" id="sevlegend"></div>
      </div>
      <div class="panel">
        <div class="sub">Top rules <span class="muted" id="lastSeen"></span></div>
        <div id="rulesList"><span class="stat">none yet</span></div>
      </div>
    </div>
  </section>
  <div id="empty" class="empty">Waiting for agent activity&hellip; events and detections will appear here in real time.</div>
  <div id="feedNote" class="stat" style="display:none;margin-bottom:10px"></div>
  <div id="list"></div>
</div>
<div class="toast" id="toast"></div>
<script>
const list=document.getElementById('list'), empty=document.getElementById('empty');
const dot=document.getElementById('dot'), conn=document.getElementById('conn');
const all=[]; let lastTs=null;
const maxCards=200;
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function fmt(ts){if(!ts)return'';const d=new Date(ts);return isNaN(d)?esc(ts):d.toLocaleString();}
function recordType(rec){
  if(rec.record_type)return rec.record_type;
  return rec.decision_id?'enforcement':'finding';
}
function relTime(ts){
  if(!ts)return'';
  const s=Math.max(0,(Date.now()-new Date(ts).getTime())/1000);
  if(s<60)return Math.floor(s)+'s ago';
  if(s<3600)return Math.floor(s/60)+'m ago';
  if(s<86400)return Math.floor(s/3600)+'h ago';
  return Math.floor(s/86400)+'d ago';
}
function renderCard(rec,flash){
  empty.style.display='none';
  const card=document.createElement('div');
  card.className='card'+(flash?' flash':'');
  const type=recordType(rec);
  if(type==='event'){
    card.classList.add('activity');
    const event=esc(rec.event_type||'event');
    const tool=esc(rec.tool_name||rec.mcp_tool||'');
    const actor=esc(rec.actor||rec.source_agent||'');
    const command=rec.command||'';
    const decision=rec.approval_decision||rec.decision||'';
    card.innerHTML=`<div class="row1">
      <span class="badge info">event</span>
      <span class="title">${event}</span>
      <span class="time">${fmt(rec.timestamp)}</span></div>
      <div class="meta">
        ${actor?`<span class="chip">agent <b>${actor}</b></span>`:''}
        ${tool?`<span class="chip">tool <b>${tool}</b></span>`:''}
        ${decision?`<span class="chip">decision <b>${esc(decision)}</b></span>`:''}
      </div>
      ${command?`<div class="cmd">${esc(command)}</div>`:''}`;
  }else if(type==='indicator'){
    card.classList.add('indicator');
    const kind=esc(rec.type||'indicator'), value=esc(rec.value||'');
    card.innerHTML=`<div class="row1">
      <span class="badge medium">indicator</span>
      <span class="title">${kind}: ${value}</span>
      <span class="time">${fmt(rec.last_seen||rec.timestamp)}</span></div>
      <div class="meta">
        ${rec.count!=null?`<span class="chip">count <b>${esc(rec.count)}</b></span>`:''}
        ${rec.source_agent?`<span class="chip">agent <b>${esc(rec.source_agent)}</b></span>`:''}
        ${rec.first_seen?`<span class="chip">first seen <b>${fmt(rec.first_seen)}</b></span>`:''}
      </div>`;
  }else if(type==='diagnostic'||type==='scan_summary'){
    card.classList.add('activity');
    const level=esc(rec.level||type), message=esc(rec.message||rec.status||'');
    card.innerHTML=`<div class="row1">
      <span class="badge info">${level}</span>
      <span class="title">${type==='diagnostic'?'Numbat diagnostic':'Scan summary'}</span>
      <span class="time">${fmt(rec.timestamp)}</span></div>
      ${message?`<div class="meta"><span class="chip">${message}</span></div>`:''}`;
  }else if(type==='enforcement'){
    card.classList.add('enforcement');
    const dec=esc(rec.decision||'?'), mode=esc(rec.mode||''), rules=(rec.rule_ids||[]).map(esc).join(', ');
    card.innerHTML=`<div class="row1">
      <span class="badge enf">decision</span>
      <span class="decision ${dec}">${dec}</span>
      <span class="time">${fmt(rec.timestamp)}</span></div>
      <div class="meta">
        ${mode?`<span class="chip">mode <b>${mode}</b></span>`:''}
        ${rules?`<span class="chip">rules <b>${rules}</b></span>`:''}
        ${rec.reason?`<span class="chip">reason <b>${esc(rec.reason)}</b></span>`:''}
        ${rec.tool_name?`<span class="chip">tool <b>${esc(rec.tool_name)}</b></span>`:''}
      </div>`;
  }else{
    const sev=(rec.severity||'info').toLowerCase();
    card.classList.add('sev-'+sev);
    const tags=(rec.tags||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join(' ');
    card.innerHTML=`<div class="row1">
      <span class="badge ${sev}">${esc(sev)}</span>
      <span class="title">${esc(rec.title||rec.rule_id||'Finding')}</span>
      <span class="time">${fmt(rec.timestamp||rec.detected_at)}</span></div>
      <div class="meta">
        <span class="rule">${esc(rec.rule_id||'')}${rec.rule_version?' v'+esc(rec.rule_version):''}</span>
        ${rec.observed_actor?`<span class="chip">actor <b>${esc(rec.observed_actor)}</b></span>`:''}
        ${rec.source_agent?`<span class="chip">agent <b>${esc(rec.source_agent)}</b></span>`:''}
        ${rec.confidence?`<span class="chip">confidence <b>${esc(rec.confidence)}</b></span>`:''}
        ${tags}
      </div>
      ${rec.observed_command?`<div class="cmd">${esc(rec.observed_command)}</div>`:''}`;
  }
  list.insertBefore(card,list.firstChild);
}
function updateStats(){
  const findings=all.filter(r=>recordType(r)==='finding');
  const decisions=all.filter(r=>recordType(r)==='enforcement');
  const events=all.filter(r=>recordType(r)==='event');
  const indicators=all.filter(r=>recordType(r)==='indicator');
  const sev={critical:0,high:0,medium:0,low:0,info:0};
  const rules={}; const agents=new Set(); lastTs=null;
  findings.forEach(r=>{
    let s=(r.severity||'info').toLowerCase(); if(sev[s]==null)s='info'; sev[s]++;
    rules[r.rule_id||'?']=(rules[r.rule_id||'?']||0)+1;
  });
  all.forEach(r=>{
    if(r.source_agent)agents.add(r.source_agent);
    const t=r.timestamp||r.detected_at||r.last_seen;
    if(t&&(!lastTs||t>lastTs))lastTs=t;
  });
  const blocked=decisions.filter(d=>(d.decision||'')==='deny').length;
  const set=(id,v)=>document.getElementById(id).textContent=v;
  set('sTotal',findings.length); set('sHigh',sev.high+sev.critical);
  set('sMed',sev.medium); set('sBlocked',blocked);
  set('sRules',Object.keys(rules).length); set('sAgents',agents.size);
  set('cFind',findings.length); set('cEnf',decisions.length);
  set('sEvents',events.length); set('cEvents',events.length);
  set('sIndicators',indicators.length); set('cIndicators',indicators.length);
  const tot=findings.length||1;
  const segs=[['high/critical',sev.high+sev.critical,'var(--high)'],
    ['medium',sev.medium,'var(--medium)'],['low',sev.low,'var(--low)'],
    ['info',sev.info,'var(--info)']];
  document.getElementById('sevbar').innerHTML=segs.map(([n,c,col])=>
    c?`<span style="width:${(c/tot*100).toFixed(2)}%;background:${col}" title="${n}: ${c}"></span>`:'').join('');
  document.getElementById('sevlegend').innerHTML=segs.map(([n,c,col])=>
    `<span><i style="background:${col}"></i>${n} ${c}</span>`).join('');
  const top=Object.entries(rules).sort((a,b)=>b[1]-a[1]).slice(0,4);
  const max=top.length?top[0][1]:1;
  document.getElementById('rulesList').innerHTML=top.length?top.map(([id,c])=>
    `<div class="rule-row"><span class="rname">${esc(id)}</span>`+
    `<span class="bar" style="width:${Math.round(c/max*120)}px"></span>`+
    `<span class="rcount">${c}</span></div>`).join(''):'<span class="stat">none yet</span>';
  document.getElementById('lastSeen').textContent=lastTs?('· last '+relTime(lastTs)):'';
}
function addRec(rec,flash){
  all.push(rec); renderCard(rec,flash);
  while(list.children.length>maxCards)list.removeChild(list.lastChild);
  updateStats();
}
let toastT;
function toast(msg){const t=document.getElementById('toast');t.textContent=msg;
  t.classList.add('show');clearTimeout(toastT);
  toastT=setTimeout(()=>t.classList.remove('show'),4500);}
document.getElementById('resetBtn').onclick=()=>{
  if(!confirm('Reset live records?\\n\\nCurrent records are archived first (retrievable via Archives), then cleared from the live view.'))return;
  fetch('reset',{method:'POST'}).then(r=>r.json()).then(res=>{
    toast(res.count?('Archived '+res.count+' record'+(res.count>1?'s':'')+
      (res.archived?' → '+res.archived:'')):'Already empty — nothing to archive');
  }).catch(()=>toast('Reset failed'));
};
fetch('history').then(r=>r.json()).then(arr=>{
  all.push(...arr);
  arr.slice(-maxCards).forEach(r=>renderCard(r,false));
  if(arr.length>maxCards){
    const note=document.getElementById('feedNote');
    note.textContent='Showing the latest '+maxCards+' records; summary counts include the full in-memory history.';
    note.style.display='block';
  }
  updateStats();
}).catch(()=>{});
setInterval(()=>{document.getElementById('lastSeen').textContent=lastTs?('· last '+relTime(lastTs)):'';},5000);
const es=new EventSource('events');
es.onopen=()=>{dot.classList.remove('off');conn.textContent='live';};
es.onerror=()=>{dot.classList.add('off');conn.textContent='reconnecting…';};
es.onmessage=e=>{try{addRec(JSON.parse(e.data),true);}catch(_){}};
es.addEventListener('reset',()=>{all.length=0;list.innerHTML='';
  empty.style.display='';document.getElementById('feedNote').style.display='none';updateStats();});
</script>
</body></html>
"""

ARCHIVES_TMPL = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Numbat — Archives</title>
<style>
:root{--bg:#0e1116;--panel:#161b22;--panel2:#1c2430;--border:#2a3441;
  --text:#e6edf3;--muted:#8b98a5;--accent:#4c9be8}
@media(prefers-color-scheme:light){:root{--bg:#f6f8fa;--panel:#fff;--panel2:#f0f3f6;
  --border:#d0d7de;--text:#1f2328;--muted:#636c76}}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  background:var(--bg);color:var(--text)}
header{background:var(--panel);border-bottom:1px solid var(--border);padding:14px 20px;
  display:flex;align-items:center;gap:14px}
h1{font-size:16px;margin:0;font-weight:650}
.spacer{flex:1}
a.back{font-size:12px;color:var(--accent);text-decoration:none}
.wrap{max-width:820px;margin:0 auto;padding:24px 20px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);
  border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:11px 14px;font-size:13px;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;
  background:var(--panel2)}
tr:last-child td{border-bottom:none}
td.num{font-variant-numeric:tabular-nums;color:var(--muted)}
a.dl{color:var(--accent);text-decoration:none;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
a.dl:hover{text-decoration:underline}
</style></head>
<body>
<header><h1>Numbat &middot; Archived Records</h1><div class="spacer"></div>
<a class="back" href="/">&larr; back to live dashboard</a></header>
<div class="wrap">
<table><thead><tr><th>Archive file</th><th>Records</th><th>Size</th></tr></thead>
<tbody>{{ROWS}}</tbody></table>
</div></body></html>
"""


COLUMNS = [
    ("Time", lambda r: r.get("timestamp") or r.get("detected_at") or r.get("last_seen") or ""),
    ("Type", lambda r: r.get("record_type") or r.get("event_type") or r.get("type", "")),
    ("Severity", lambda r: r.get("severity") or r.get("level", "")),
    ("Rule", lambda r: r.get("rule_id") or ", ".join(r.get("rule_ids", []))),
    ("Rule version", lambda r: r.get("rule_version", "")),
    ("Title", lambda r: r.get("title") or r.get("message", "")),
    ("Actor", lambda r: r.get("observed_actor") or r.get("actor", "")),
    ("Agent", lambda r: r.get("source_agent", "")),
    ("Confidence", lambda r: r.get("confidence", "")),
    ("MITRE tags", lambda r: ", ".join(r.get("tags", []))),
    ("Decision", lambda r: r.get("decision") or r.get("approval_decision", "")),
    ("Mode", lambda r: r.get("mode", "")),
    ("Reason", lambda r: r.get("reason") or r.get("approval_reason", "")),
    ("Tool", lambda r: r.get("tool_name") or r.get("mcp_tool", "")),
    ("Command", lambda r: r.get("observed_command") or r.get("command", "")),
    ("Session", lambda r: r.get("session_id", "")),
    ("ID", lambda r: r.get("finding_id") or r.get("decision_id") or r.get("event_id") or r.get("sample_event_id") or ""),
    ("Indicator value", lambda r: r.get("value", "")),
    ("Indicator count", lambda r: r.get("count", "")),
]


def _xesc(v):
    s = "" if v is None else str(v)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # strip control chars XML 1.0 forbids (except tab/newline/return)
    return "".join(
        c for c in s if c in "\t\n\r" or ord(c) >= 0x20
    )


def _col(n):
    s = ""
    n += 1
    while n:
        n, rem = divmod(n - 1, 26)
        s = chr(65 + rem) + s
    return s


def build_xlsx():
    with history_lock:
        rows = [[hdr for hdr, _ in COLUMNS]]
        for rec in history:
            rows.append([fn(rec) for _, fn in COLUMNS])

    sheet = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
        "<sheetData>",
    ]
    for ri, row in enumerate(rows, start=1):
        cells = []
        for ci, val in enumerate(row):
            ref = "%s%d" % (_col(ci), ri)
            cells.append(
                '<c r="%s" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>'
                % (ref, _xesc(val))
            )
        sheet.append('<row r="%d">%s</row>' % (ri, "".join(cells)))
    sheet.append("</sheetData></worksheet>")
    sheet_xml = "".join(sheet)

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        "</Types>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Findings" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        "</Relationships>"
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        z.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return buf.getvalue()


def do_reset():
    """Archive current in-memory history to a timestamped file, then clear
    both the in-memory history and the live findings file."""
    with history_lock:
        records = list(history)
        history.clear()
        seen.clear()
    archived = None
    if records:
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        archived = "findings-%s.ndjson" % datetime.datetime.now().strftime(
            "%Y%m%d-%H%M%S"
        )
        with open(os.path.join(ARCHIVE_DIR, archived), "w") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")
    try:
        open(FINDINGS, "w").close()  # truncate live file; watcher resets offset
    except Exception:
        pass
    push_frame("event: reset\ndata: {}\n\n")
    return {"archived": archived, "count": len(records)}


def list_archives():
    out = []
    try:
        names = sorted(os.listdir(ARCHIVE_DIR), reverse=True)
    except FileNotFoundError:
        names = []
    for name in names:
        if not name.endswith(".ndjson"):
            continue
        path = os.path.join(ARCHIVE_DIR, name)
        try:
            with open(path) as f:
                n = sum(1 for _ in f)
            size = os.path.getsize(path)
        except OSError:
            continue
        out.append({"name": name, "records": n, "size": size})
    return out


def render_archives_html():
    rows = []
    for a in list_archives():
        kb = "%.1f KB" % (a["size"] / 1024.0)
        rows.append(
            '<tr><td><a class="dl" href="archive/%s">%s</a></td>'
            '<td class="num">%d</td><td class="num">%s</td></tr>'
            % (a["name"], a["name"], a["records"], kb)
        )
    body = "".join(rows) or (
        '<tr><td colspan="3" style="color:var(--muted)">No archives yet — '
        "use Reset on the dashboard to create one.</td></tr>"
    )
    return ARCHIVES_TMPL.replace("{{ROWS}}", body)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def handle(self):
        try:
            super().handle()
        except ConnectionResetError:
            # A browser may close a connection before sending a full request.
            # Treat that like the disconnects handled in the SSE endpoint.
            pass

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._send(200, "text/html; charset=utf-8", PAGE.encode())
        elif path == "/history":
            with history_lock:
                body = json.dumps(history).encode()
            self._send(200, "application/json", body)
        elif path == "/archives":
            self._send(200, "text/html; charset=utf-8", render_archives_html().encode())
        elif path.startswith("/archive/"):
            name = os.path.basename(path[len("/archive/"):])
            fpath = os.path.join(ARCHIVE_DIR, name)
            if name.endswith(".ndjson") and os.path.isfile(fpath):
                with open(fpath, "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.send_header(
                    "Content-Disposition", 'attachment; filename="%s"' % name
                )
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self._send(404, "text/plain", b"not found")
        elif path == "/export.xlsx":
            body = build_xlsx()
            fname = "numbat-findings-%s.xlsx" % datetime.datetime.now().strftime(
                "%Y%m%d-%H%M%S"
            )
            self.send_response(200)
            self.send_header(
                "Content-Type",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
            self.send_header(
                "Content-Disposition", 'attachment; filename="%s"' % fname
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = queue.Queue()
            with clients_lock:
                clients.append(q)
            try:
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                while True:
                    try:
                        frame = q.get(timeout=15)
                    except queue.Empty:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        continue
                    self.wfile.write(frame.encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ValueError):
                pass
            finally:
                with clients_lock:
                    if q in clients:
                        clients.remove(q)
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/reset":
            try:
                n = int(self.headers.get("Content-Length", 0) or 0)
                if n:
                    self.rfile.read(n)
            except Exception:
                pass
            res = do_reset()
            self._send(200, "application/json", json.dumps(res).encode())
        else:
            self._send(404, "text/plain", b"not found")


def main():
    threading.Thread(target=watcher, daemon=True).start()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print("numbat dashboard: http://127.0.0.1:%d  (watching %s)" % (PORT, FINDINGS))
    httpd.serve_forever()


if __name__ == "__main__":
    main()
