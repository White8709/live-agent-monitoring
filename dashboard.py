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
from urllib.parse import parse_qs, urlsplit

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

TRANSLATIONS = {
    "en": {
        "dashboard_title": "Numbat — Live Agent Monitor",
        "dashboard_heading": "Numbat · Live Agent Monitor",
        "archives_title": "Numbat — Archived Records",
        "archives_heading": "Numbat · Archived Records",
        "language": "Language",
        "findings": "findings",
        "decisions": "decisions",
        "events": "events",
        "indicators": "indicators",
        "archives": "Archives",
        "export_excel": "Export Excel",
        "reset": "Reset",
        "tile_findings": "Findings",
        "tile_high_critical": "High / Critical",
        "tile_medium": "Medium",
        "tile_blocked": "Blocked",
        "tile_rules": "Rules hit",
        "tile_agents": "Agents",
        "tile_events": "Events",
        "tile_indicators": "Indicators",
        "clear_filters": "Show all",
        "agent_filter_label": "Filter by agent",
        "agent_options": "Select agents",
        "no_agents": "No agents available",
        "no_filter_results": "No records match the selected filters.",
        "selected_agent_count": "{n} selected",
        "severity_mix": "Severity mix",
        "top_rules": "Top rules",
        "none_yet": "none yet",
        "empty_activity": "Waiting for agent activity… events and detections will appear here in real time.",
        "feed_note": "Showing the latest {limit} matching records; summary counts include all loaded records.",
        "connecting": "connecting…",
        "live": "live",
        "reconnecting": "reconnecting…",
        "label_agent": "agent",
        "label_actor": "actor",
        "label_tool": "tool",
        "label_decision": "decision",
        "label_mode": "mode",
        "label_rules": "rules",
        "label_reason": "reason",
        "label_confidence": "confidence",
        "label_count": "count",
        "label_first_seen": "first seen",
        "label_rule": "rule",
        "label_command": "command",
        "diagnostic_title": "Numbat diagnostic",
        "scan_summary": "Scan summary",
        "last_seen": "· last {time}",
        "relative_seconds": "{n}s ago",
        "relative_minutes": "{n}m ago",
        "relative_hours": "{n}h ago",
        "relative_days": "{n}d ago",
        "severity_title": "{name}: {count}",
        "confirm_reset": "Reset live records?\n\nCurrent records are archived first (retrievable via Archives), then cleared from the live view.",
        "toast_archived_one": "Archived {count} record{archive_suffix}",
        "toast_archived_many": "Archived {count} records{archive_suffix}",
        "archive_suffix": " → {archived}",
        "toast_empty": "Already empty — nothing to archive",
        "toast_reset_failed": "Reset failed",
        "back_to_dashboard": "Back to live dashboard",
        "archive_file": "Archive file",
        "archive_records": "Records",
        "archive_size": "Size",
        "archives_empty": "No archives yet — use Reset on the dashboard to create one.",
        "xlsx_headers": [
            "Time", "Type", "Severity", "Rule", "Rule version", "Title",
            "Actor", "Agent", "Confidence", "MITRE tags", "Decision",
            "Mode", "Reason", "Tool", "Command", "Session", "ID",
            "Indicator value", "Indicator count",
        ],
        "xlsx_sheet_name": "Records",
        "record_types": {
            "event": "Event", "finding": "Finding", "enforcement": "Decision",
            "indicator": "Indicator", "diagnostic": "Diagnostic",
            "scan_summary": "Scan summary",
        },
        "severities": {
            "critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "info": "Info",
        },
        "decisions_map": {
            "allow": "Allow", "deny": "Deny", "no_override": "No override",
            "asked": "Asked",
        },
        "event_types": {
            "session.start": "Session started", "session.end": "Session ended",
            "prompt.user": "User prompt", "command.exec": "Command execution",
            "command.result": "Command result", "tool.call": "Tool call",
            "tool.result": "Tool result", "permission.requested": "Permission requested",
            "file.write": "File write", "file.delete": "File deletion",
            "message.assistant": "Assistant message",
        },
        "indicator_types": {
            "domain": "Domain", "url": "URL", "email": "Email",
            "ipv4": "IPv4 address", "ipv6": "IPv6 address",
            "md5": "MD5 hash", "sha1": "SHA-1 hash", "sha256": "SHA-256 hash",
        },
        "diagnostic_levels": {"info": "Info", "warn": "Warning", "error": "Error"},
    },
    "zh-TW": {
        "dashboard_title": "Numbat — AI 代理程式即時監看",
        "dashboard_heading": "Numbat・AI 代理程式即時監看",
        "archives_title": "Numbat — 封存紀錄",
        "archives_heading": "Numbat・封存紀錄",
        "language": "語言",
        "findings": "偵測結果",
        "decisions": "決策",
        "events": "事件",
        "indicators": "指標",
        "archives": "封存紀錄",
        "export_excel": "匯出 Excel",
        "reset": "重設",
        "tile_findings": "偵測結果",
        "tile_high_critical": "高／嚴重",
        "tile_medium": "中",
        "tile_blocked": "已封鎖",
        "tile_rules": "觸發規則",
        "tile_agents": "代理程式",
        "tile_events": "事件",
        "tile_indicators": "指標",
        "clear_filters": "顯示全部",
        "agent_filter_label": "依代理程式篩選",
        "agent_options": "選取代理程式",
        "no_agents": "目前沒有代理程式",
        "no_filter_results": "沒有符合篩選條件的紀錄。",
        "selected_agent_count": "已選取 {n} 個",
        "severity_mix": "嚴重程度分布",
        "top_rules": "常見觸發規則",
        "none_yet": "目前沒有",
        "empty_activity": "等待代理程式活動中……事件與偵測結果會即時顯示。",
        "feed_note": "僅顯示符合篩選條件的最新 {limit} 筆紀錄；統計包含目前載入的全部紀錄。",
        "connecting": "連線中……",
        "live": "即時連線",
        "reconnecting": "重新連線中……",
        "label_agent": "代理程式",
        "label_actor": "操作者",
        "label_tool": "工具",
        "label_decision": "決策",
        "label_mode": "模式",
        "label_rules": "規則",
        "label_reason": "原因",
        "label_confidence": "信心程度",
        "label_count": "次數",
        "label_first_seen": "首次出現",
        "label_rule": "規則",
        "label_command": "指令",
        "diagnostic_title": "Numbat 診斷訊息",
        "scan_summary": "掃描摘要",
        "last_seen": "・最近活動：{time}",
        "relative_seconds": "{n} 秒前",
        "relative_minutes": "{n} 分鐘前",
        "relative_hours": "{n} 小時前",
        "relative_days": "{n} 天前",
        "severity_title": "{name}：{count}",
        "confirm_reset": "要重設目前的紀錄嗎？\n\n系統會先封存紀錄，再清除即時清單；封存檔可在「封存紀錄」頁下載。",
        "toast_archived_one": "已封存 {count} 筆紀錄{archive_suffix}",
        "toast_archived_many": "已封存 {count} 筆紀錄{archive_suffix}",
        "archive_suffix": "（{archived}）",
        "toast_empty": "目前沒有紀錄可封存。",
        "toast_reset_failed": "重設失敗。",
        "back_to_dashboard": "返回即時儀表板",
        "archive_file": "封存檔案",
        "archive_records": "紀錄筆數",
        "archive_size": "檔案大小",
        "archives_empty": "目前沒有封存紀錄。按下主頁的「重設」會建立封存紀錄。",
        "xlsx_headers": [
            "時間", "類型", "嚴重程度", "規則", "規則版本", "標題",
            "操作者", "代理程式", "信心程度", "MITRE 標籤", "決策",
            "模式", "原因", "工具", "指令", "工作階段", "ID",
            "指標值", "指標次數",
        ],
        "xlsx_sheet_name": "紀錄",
        "record_types": {
            "event": "事件", "finding": "偵測結果", "enforcement": "管制決策",
            "indicator": "指標", "diagnostic": "診斷", "scan_summary": "掃描摘要",
        },
        "severities": {
            "critical": "嚴重", "high": "高", "medium": "中",
            "low": "低", "info": "資訊",
        },
        "decisions_map": {
            "allow": "允許", "deny": "拒絕", "no_override": "未覆寫",
            "asked": "待確認",
        },
        "event_types": {
            "session.start": "工作階段開始", "session.end": "工作階段結束",
            "prompt.user": "使用者提示", "command.exec": "執行指令",
            "command.result": "指令結果", "tool.call": "工具呼叫",
            "tool.result": "工具結果", "permission.requested": "要求權限",
            "file.write": "檔案寫入", "file.delete": "檔案刪除",
            "message.assistant": "助理訊息",
        },
        "indicator_types": {
            "domain": "網域", "url": "網址", "email": "電子郵件",
            "ipv4": "IPv4 位址", "ipv6": "IPv6 位址",
            "md5": "MD5 雜湊", "sha1": "SHA-1 雜湊", "sha256": "SHA-256 雜湊",
        },
        "diagnostic_levels": {"info": "資訊", "warn": "警告", "error": "錯誤"},
    },
}

NON_TAIWAN_TERMS = (
    "用户", "信息", "默認", "网络", "網絡", "服务器", "服務器", "数据", "數據",
    "視頻", "软件", "軟件", "鼠標", "打印", "链接", "鏈接", "质量", "質量",
    "激活", "加載", "保存", "界面", "用戶",
)


def normalize_language(language):
    return language if language in TRANSLATIONS else "en"


I18N_SCRIPT = r"""
<script>
const translationCatalog=__TRANSLATION_CATALOG__;
const languageStorageKey='numbat-dashboard-language';
let activeLanguage='en';
function t(key,values={}){
  const template=translationCatalog[activeLanguage][key]??translationCatalog.en[key]??key;
  return String(template).replace(/\{([\w]+)\}/g,(_,name)=>
    Object.prototype.hasOwnProperty.call(values,name)?String(values[name]):'{'+name+'}');
}
function enumLabel(group,value){
  return translationCatalog[activeLanguage][group]?.[value]||value;
}
function chooseInitialLanguage(savedLanguage,browserLocale){
  if(Object.prototype.hasOwnProperty.call(translationCatalog,savedLanguage))return savedLanguage;
  return browserLocale==='zh-TW'?'zh-TW':'en';
}
function setLanguage(language,persist=true){
  if(!Object.prototype.hasOwnProperty.call(translationCatalog,language))return;
  activeLanguage=language;
  if(persist){try{sessionStorage.setItem(languageStorageKey,language);}catch(_){}}
  document.documentElement.lang=language;
  document.querySelectorAll('[data-i18n]').forEach(node=>{node.textContent=t(node.dataset.i18n);});
  document.querySelectorAll('[data-i18n-aria-label]').forEach(node=>{
    node.setAttribute('aria-label',t(node.dataset.i18nAriaLabel));
  });
  const picker=document.getElementById('languageSelect');
  if(picker)picker.value=language;
  window.dispatchEvent(new CustomEvent('numbat-language-change',{detail:{language}}));
}
let initialLanguage='en';
try{
  const savedLanguage=sessionStorage.getItem(languageStorageKey);
  initialLanguage=chooseInitialLanguage(savedLanguage,navigator.language);
}catch(_){initialLanguage=chooseInitialLanguage(null,navigator.language);}
window.NumbatI18n={t,enumLabel,chooseInitialLanguage,get language(){return activeLanguage;},setLanguage};
const languagePicker=document.getElementById('languageSelect');
if(languagePicker)languagePicker.addEventListener('change',()=>setLanguage(languagePicker.value));
setLanguage(initialLanguage,false);
</script>
"""


def render_template(template):
    catalog = json.dumps(TRANSLATIONS, ensure_ascii=False)
    catalog = catalog.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    runtime = I18N_SCRIPT.replace("__TRANSLATION_CATALOG__", catalog)
    return template.replace("{{I18N_SCRIPT}}", runtime)

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
<title data-i18n="dashboard_title">Numbat — Live Agent Monitor</title>
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
.language-wrap{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:12px}
.language-select{font:inherit;color:var(--text);background:var(--panel2);
  border:1px solid var(--border);border-radius:7px;padding:5px 8px}
.stat{color:var(--muted);font-size:12px}
.stat b{color:var(--text);font-variant-numeric:tabular-nums}
.stat-filter{display:inline-flex;align-items:center;gap:5px;color:var(--muted);
  background:transparent;border:1px solid transparent;border-radius:7px;
  padding:4px 6px;font:inherit;white-space:nowrap;cursor:pointer}
.stat-filter b{color:var(--text);font-variant-numeric:tabular-nums}
.stat-filter:hover,.stat-filter:focus-visible,.stat-filter[aria-pressed="true"]{
  border-color:var(--accent);background:var(--panel2);color:var(--accent)}
.stat-filter:focus-visible,.filter-tile:focus-visible,.agent-menu input:focus-visible{
  outline:2px solid var(--accent);outline-offset:2px}
.filter-clear[hidden]{display:none}
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
.filter-tile{display:block;width:100%;color:var(--text);font:inherit;text-align:left;
  cursor:pointer;transition:border-color .15s,background .15s}
.filter-tile:hover,.filter-tile[aria-pressed="true"]{
  border-color:var(--accent);background:var(--panel2)}
.filter-selection{font-size:11px;color:var(--accent);margin-top:6px}
.agent-filter{position:relative;min-width:0}
.agent-menu{position:absolute;right:0;top:calc(100% + 6px);z-index:12;
  width:min(320px,calc(100vw - 40px));max-height:300px;overflow:auto;
  padding:12px;background:var(--panel);border:1px solid var(--border);
  border-radius:9px;box-shadow:0 8px 28px rgba(0,0,0,.35)}
.agent-menu[hidden]{display:none}
.agent-menu fieldset{margin:0;padding:0;border:0}
.agent-menu legend{font-size:12px;font-weight:650;margin-bottom:8px}
.agent-options{display:grid;gap:4px}
.agent-options label{display:flex;align-items:center;gap:8px;padding:5px 4px;
  border-radius:5px;cursor:pointer;overflow-wrap:anywhere}
.agent-options label:hover{background:var(--panel2)}
.agent-options input{accent-color:var(--accent)}
.agent-empty{color:var(--muted);font-size:12px;padding:5px 4px}
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
  <h1 data-i18n="dashboard_heading">Numbat &middot; Live Agent Monitor</h1>
  <div class="spacer"></div>
  <span class="language-wrap"><label for="languageSelect" data-i18n="language">Language</label>
    <select class="language-select" id="languageSelect" data-i18n-aria-label="language">
      <option value="en">English</option><option value="zh-TW">繁體中文（台灣）</option>
    </select></span>
  <button class="stat-filter" type="button" data-filter-type="finding" aria-pressed="false"><span data-i18n="findings">findings</span> <b id="cFind">0</b></button>
  <button class="stat-filter" type="button" data-filter-type="enforcement" aria-pressed="false"><span data-i18n="decisions">decisions</span> <b id="cEnf">0</b></button>
  <button class="stat-filter" type="button" data-filter-type="event" aria-pressed="false"><span data-i18n="events">events</span> <b id="cEvents">0</b></button>
  <button class="stat-filter" type="button" data-filter-type="indicator" aria-pressed="false"><span data-i18n="indicators">indicators</span> <b id="cIndicators">0</b></button>
  <button class="btn filter-clear" id="clearFilters" type="button" data-i18n="clear_filters" hidden>Show all</button>
  <a class="btn" href="archives" target="_blank" rel="noopener" data-i18n="archives">Archives</a>
  <a class="btn" id="exportBtn" href="export.xlsx" data-i18n="export_excel">Export Excel</a>
  <button class="btn danger" id="resetBtn" data-i18n="reset">Reset</button>
  <span class="stat" id="conn" data-i18n="connecting">connecting&hellip;</span>
</header>
<div class="wrap">
  <section class="stats">
    <div class="tiles">
      <button class="tile filter-tile" type="button" data-filter-type="finding" aria-pressed="false"><div class="num" id="sTotal">0</div><div class="lbl" data-i18n="tile_findings">Findings</div></button>
      <button class="tile filter-tile hi" type="button" data-filter-severity="high" aria-pressed="false"><div class="num" id="sHigh">0</div><div class="lbl" data-i18n="tile_high_critical">High / Critical</div></button>
      <button class="tile filter-tile md" type="button" data-filter-severity="medium" aria-pressed="false"><div class="num" id="sMed">0</div><div class="lbl" data-i18n="tile_medium">Medium</div></button>
      <button class="tile filter-tile ok" type="button" id="blockedFilter" aria-pressed="false"><div class="num" id="sBlocked">0</div><div class="lbl" data-i18n="tile_blocked">Blocked</div></button>
      <button class="tile filter-tile" type="button" id="rulesFilter" aria-pressed="false"><div class="num" id="sRules">0</div><div class="lbl" data-i18n="tile_rules">Rules hit</div></button>
      <div class="agent-filter">
        <button class="tile filter-tile agent-filter-button" type="button" id="agentsFilter"
          aria-pressed="false" aria-expanded="false" aria-controls="agentFilterPanel">
          <div class="num" id="sAgents">0</div><div class="lbl" data-i18n="tile_agents">Agents</div>
          <div class="filter-selection" id="selectedAgentCount" hidden></div>
        </button>
        <div class="agent-menu" id="agentFilterPanel" role="group"
          aria-label="Filter by agent" data-i18n-aria-label="agent_filter_label" hidden>
          <fieldset><legend data-i18n="agent_options">Select agents</legend>
            <div class="agent-options" id="agentFilterOptions">
              <div class="agent-empty" data-i18n="no_agents">No agents available</div>
            </div>
          </fieldset>
        </div>
      </div>
      <button class="tile filter-tile" type="button" data-filter-type="event" aria-pressed="false"><div class="num" id="sEvents">0</div><div class="lbl" data-i18n="tile_events">Events</div></button>
      <button class="tile filter-tile" type="button" data-filter-type="indicator" aria-pressed="false"><div class="num" id="sIndicators">0</div><div class="lbl" data-i18n="tile_indicators">Indicators</div></button>
    </div>
    <div class="stats2">
      <div class="panel">
        <div class="sub" data-i18n="severity_mix">Severity mix</div>
        <div class="sevbar" id="sevbar"></div>
        <div class="sevlegend" id="sevlegend"></div>
      </div>
      <div class="panel">
        <div class="sub"><span data-i18n="top_rules">Top rules</span> <span class="muted" id="lastSeen"></span></div>
        <div id="rulesList"><span class="stat" data-i18n="none_yet">none yet</span></div>
      </div>
    </div>
  </section>
  <div id="empty" class="empty" data-i18n="empty_activity">Waiting for agent activity&hellip; events and detections will appear here in real time.</div>
  <div id="feedNote" class="stat" style="display:none;margin-bottom:10px"></div>
  <div id="list"></div>
</div>
<div class="toast" id="toast"></div>
{{I18N_SCRIPT}}
<script>
const list=document.getElementById('list'), empty=document.getElementById('empty');
const dot=document.getElementById('dot'), conn=document.getElementById('conn');
const all=[]; let lastTs=null;
const maxCards=200;
const i18n=window.NumbatI18n;
const filters={types:new Set(),severities:new Set(),blocked:false,rules:false,agents:new Set()};
const agentFilter=document.querySelector('.agent-filter');
const agentFilterButton=document.getElementById('agentsFilter');
const agentFilterPanel=document.getElementById('agentFilterPanel');
const agentFilterOptions=document.getElementById('agentFilterOptions');
let agentOptionsSignature='';
let activeToast=null;
const esc=s=>String(s==null?'':s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function fmt(ts){if(!ts)return'';const d=new Date(ts);return isNaN(d)?esc(ts):d.toLocaleString(i18n.language);}
function recordType(rec){
  if(rec.record_type)return rec.record_type;
  return rec.decision_id?'enforcement':'finding';
}
function agentIdentity(rec){
  const value=rec.source_agent||(recordType(rec)==='event'?rec.actor:'');
  return value==null?'':String(value);
}
function matchesFilters(rec){
  const type=recordType(rec);
  if(filters.types.size&&!filters.types.has(type))return false;
  if(filters.severities.size){
    const severity=String(rec.severity||'').toLowerCase();
    const severityGroup=severity==='high'||severity==='critical'?'high':
      severity==='medium'?'medium':'';
    if(!filters.severities.has(severityGroup))return false;
  }
  if(filters.blocked&&!(type==='enforcement'&&rec.decision==='deny'))return false;
  if(filters.rules){
    const ruleIds=Array.isArray(rec.rule_ids)?rec.rule_ids:[rec.rule_ids];
    if(!rec.rule_id&&!ruleIds.some(value=>value!=null&&String(value).trim()))return false;
  }
  if(filters.agents.size&&!filters.agents.has(agentIdentity(rec)))return false;
  return true;
}
function activeFilters(){
  return filters.types.size>0||filters.severities.size>0||filters.blocked||
    filters.rules||filters.agents.size>0;
}
function updateAgentOptions(){
  const values=new Set(all.map(agentIdentity).filter(Boolean));
  filters.agents.forEach(value=>values.add(value));
  const agents=Array.from(values).sort((a,b)=>a.localeCompare(b,i18n.language));
  const signature=JSON.stringify([i18n.language,agents]);
  if(signature!==agentOptionsSignature){
    agentFilterOptions.innerHTML=agents.length?agents.map(agent=>
      `<label><input type="checkbox" value="${esc(agent)}" data-agent-value="${esc(agent)}">`+
      `<span>${esc(agent)}</span></label>`).join(''):
      `<div class="agent-empty">${i18n.t('no_agents')}</div>`;
    agentOptionsSignature=signature;
  }
  agentFilterOptions.querySelectorAll('input[data-agent-value]').forEach(input=>{
    input.checked=filters.agents.has(input.value);
  });
}
function updateFilterControls(){
  document.querySelectorAll('[data-filter-type]').forEach(button=>
    button.setAttribute('aria-pressed',String(filters.types.has(button.dataset.filterType))));
  document.querySelectorAll('[data-filter-severity]').forEach(button=>
    button.setAttribute('aria-pressed',String(filters.severities.has(button.dataset.filterSeverity))));
  document.getElementById('blockedFilter').setAttribute('aria-pressed',String(filters.blocked));
  document.getElementById('rulesFilter').setAttribute('aria-pressed',String(filters.rules));
  agentFilterButton.setAttribute('aria-pressed',String(filters.agents.size>0));
  const selectedCount=document.getElementById('selectedAgentCount');
  selectedCount.hidden=filters.agents.size===0;
  if(filters.agents.size)selectedCount.textContent=
    i18n.t('selected_agent_count',{n:filters.agents.size});
  document.getElementById('clearFilters').hidden=!activeFilters();
  updateAgentOptions();
}
function filteredRecords(){return all.filter(matchesFilters);}
function updateEmptyState(matchCount){
  if(matchCount){empty.style.display='none';return;}
  empty.style.display='';
  empty.textContent=all.length?i18n.t('no_filter_results'):i18n.t('empty_activity');
}
function relTime(ts){
  if(!ts)return'';
  const s=Math.max(0,(Date.now()-new Date(ts).getTime())/1000);
  if(s<60)return i18n.t('relative_seconds',{n:Math.floor(s)});
  if(s<3600)return i18n.t('relative_minutes',{n:Math.floor(s/60)});
  if(s<86400)return i18n.t('relative_hours',{n:Math.floor(s/3600)});
  return i18n.t('relative_days',{n:Math.floor(s/86400)});
}
function renderCard(rec,flash){
  empty.style.display='none';
  const card=document.createElement('div');
  card.className='card'+(flash?' flash':'');
  const type=recordType(rec);
  if(type==='event'){
    card.classList.add('activity');
    const event=esc(i18n.enumLabel('event_types',rec.event_type||'event'));
    const tool=esc(rec.tool_name||rec.mcp_tool||'');
    const actor=esc(rec.actor||rec.source_agent||'');
    const command=rec.command||'';
    const decision=rec.approval_decision||rec.decision||'';
    card.innerHTML=`<div class="row1">
      <span class="badge info">${esc(i18n.enumLabel('record_types','event'))}</span>
      <span class="title">${event}</span>
      <span class="time">${fmt(rec.timestamp)}</span></div>
      <div class="meta">
        ${actor?`<span class="chip">${i18n.t('label_agent')} <b>${actor}</b></span>`:''}
        ${tool?`<span class="chip">${i18n.t('label_tool')} <b>${tool}</b></span>`:''}
        ${decision?`<span class="chip">${i18n.t('label_decision')} <b>${esc(i18n.enumLabel('decisions_map',decision))}</b></span>`:''}
      </div>
      ${command?`<div class="cmd"><span>${i18n.t('label_command')}</span>: ${esc(command)}</div>`:''}`;
  }else if(type==='indicator'){
    card.classList.add('indicator');
    const kind=esc(rec.type?i18n.enumLabel('indicator_types',rec.type):
      i18n.enumLabel('record_types','indicator'));
    const value=esc(rec.value||'');
    card.innerHTML=`<div class="row1">
      <span class="badge medium">${esc(i18n.enumLabel('record_types','indicator'))}</span>
      <span class="title">${kind}: ${value}</span>
      <span class="time">${fmt(rec.last_seen||rec.timestamp)}</span></div>
      <div class="meta">
        ${rec.count!=null?`<span class="chip">${i18n.t('label_count')} <b>${esc(rec.count)}</b></span>`:''}
        ${rec.source_agent?`<span class="chip">${i18n.t('label_agent')} <b>${esc(rec.source_agent)}</b></span>`:''}
        ${rec.first_seen?`<span class="chip">${i18n.t('label_first_seen')} <b>${fmt(rec.first_seen)}</b></span>`:''}
      </div>`;
  }else if(type==='diagnostic'||type==='scan_summary'){
    card.classList.add('activity');
    const level=esc(i18n.enumLabel('diagnostic_levels',rec.level||''));
    const message=esc(rec.message||rec.status||'');
    card.innerHTML=`<div class="row1">
      <span class="badge info">${level||esc(i18n.enumLabel('record_types',type))}</span>
      <span class="title">${esc(i18n.enumLabel('record_types',type))}</span>
      <span class="time">${fmt(rec.timestamp)}</span></div>
      ${message?`<div class="meta"><span class="chip">${message}</span></div>`:''}`;
  }else if(type==='enforcement'){
    card.classList.add('enforcement');
    const decision=rec.decision||'?';
    const dec=esc(i18n.enumLabel('decisions_map',decision));
    const mode=esc(rec.mode||''), rules=(rec.rule_ids||[]).map(esc).join(', ');
    card.innerHTML=`<div class="row1">
      <span class="badge enf">${esc(i18n.enumLabel('record_types','enforcement'))}</span>
      <span class="decision ${esc(decision)}">${dec}</span>
      <span class="time">${fmt(rec.timestamp)}</span></div>
      <div class="meta">
        ${mode?`<span class="chip">${i18n.t('label_mode')} <b>${mode}</b></span>`:''}
        ${rules?`<span class="chip">${i18n.t('label_rules')} <b>${rules}</b></span>`:''}
        ${rec.reason?`<span class="chip">${i18n.t('label_reason')} <b>${esc(rec.reason)}</b></span>`:''}
        ${rec.tool_name?`<span class="chip">${i18n.t('label_tool')} <b>${esc(rec.tool_name)}</b></span>`:''}
      </div>`;
  }else{
    const severity=String(rec.severity||'info').toLowerCase();
    const sev=esc(i18n.enumLabel('severities',severity));
    const severityClass=['critical','high','medium','low','info'].includes(severity)?severity:'info';
    card.classList.add('sev-'+severityClass);
    const tags=(rec.tags||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join(' ');
    card.innerHTML=`<div class="row1">
      <span class="badge ${severityClass}">${sev}</span>
      <span class="title">${esc(rec.title||rec.rule_id||i18n.enumLabel('record_types','finding'))}</span>
      <span class="time">${fmt(rec.timestamp||rec.detected_at)}</span></div>
      <div class="meta">
        <span class="rule">${rec.rule_id?i18n.t('label_rule')+' ':''}${esc(rec.rule_id||'')}${rec.rule_version?' v'+esc(rec.rule_version):''}</span>
        ${rec.observed_actor?`<span class="chip">${i18n.t('label_actor')} <b>${esc(rec.observed_actor)}</b></span>`:''}
        ${rec.source_agent?`<span class="chip">${i18n.t('label_agent')} <b>${esc(rec.source_agent)}</b></span>`:''}
        ${rec.confidence?`<span class="chip">${i18n.t('label_confidence')} <b>${esc(rec.confidence)}</b></span>`:''}
        ${tags}
      </div>
      ${rec.observed_command?`<div class="cmd"><span>${i18n.t('label_command')}</span>: ${esc(rec.observed_command)}</div>`:''}`;
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
  const segs=[[
    i18n.enumLabel('severities','high')+' / '+i18n.enumLabel('severities','critical'),
    sev.high+sev.critical,'var(--high)'],
    [i18n.enumLabel('severities','medium'),sev.medium,'var(--medium)'],
    [i18n.enumLabel('severities','low'),sev.low,'var(--low)'],
    [i18n.enumLabel('severities','info'),sev.info,'var(--info)']];
  document.getElementById('sevbar').innerHTML=segs.map(([n,c,col])=>
    c?`<span style="width:${(c/tot*100).toFixed(2)}%;background:${col}" title="${i18n.t('severity_title',{name:n,count:c})}"></span>`:'').join('');
  document.getElementById('sevlegend').innerHTML=segs.map(([n,c,col])=>
    `<span><i style="background:${col}"></i>${n} ${c}</span>`).join('');
  const top=Object.entries(rules).sort((a,b)=>b[1]-a[1]).slice(0,4);
  const max=top.length?top[0][1]:1;
  document.getElementById('rulesList').innerHTML=top.length?top.map(([id,c])=>
    `<div class="rule-row"><span class="rname">${esc(id)}</span>`+
    `<span class="bar" style="width:${Math.round(c/max*120)}px"></span>`+
    `<span class="rcount">${c}</span></div>`).join(''):
    `<span class="stat">${i18n.t('none_yet')}</span>`;
  document.getElementById('lastSeen').textContent=lastTs?
    i18n.t('last_seen',{time:relTime(lastTs)}):'';
}
function addRec(rec,flash){
  all.push(rec);
  updateAgentOptions();
  if(matchesFilters(rec)){
    renderCard(rec,flash);
    while(list.children.length>maxCards)list.removeChild(list.lastChild);
  }
  const matchCount=filteredRecords().length;
  updateEmptyState(matchCount); updateFeedNote(matchCount); updateStats();
}
let toastT;
function toast(key,values={}){
  activeToast={key,values};
  const t=document.getElementById('toast');t.textContent=i18n.t(key,values);
  t.classList.add('show');clearTimeout(toastT);
  toastT=setTimeout(()=>t.classList.remove('show'),4500);}
function updateFeedNote(matchCount){
  const note=document.getElementById('feedNote');
  note.style.display=matchCount>maxCards?'block':'none';
  if(matchCount>maxCards)note.textContent=i18n.t('feed_note',{limit:maxCards});
}
function renderCurrentCards(){
  const matching=filteredRecords();
  list.innerHTML='';
  matching.slice(-maxCards).forEach(r=>renderCard(r,false));
  updateEmptyState(matching.length);
  updateFeedNote(matching.length);
}
function updateExportLink(){
  document.getElementById('exportBtn').href='export.xlsx?lang='+encodeURIComponent(i18n.language);
}
let connectionState='connecting';
function updateConnection(){conn.textContent=i18n.t(connectionState);}
function applyFilters(){
  updateFilterControls();
  renderCurrentCards();
}
document.querySelectorAll('[data-filter-type]').forEach(button=>button.addEventListener('click',()=>{
  const type=button.dataset.filterType;
  if(filters.types.has(type))filters.types.delete(type);else filters.types.add(type);
  applyFilters();
}));
document.querySelectorAll('[data-filter-severity]').forEach(button=>button.addEventListener('click',()=>{
  const severity=button.dataset.filterSeverity;
  if(filters.severities.has(severity))filters.severities.delete(severity);
  else filters.severities.add(severity);
  applyFilters();
}));
document.getElementById('blockedFilter').addEventListener('click',()=>{
  filters.blocked=!filters.blocked; applyFilters();
});
document.getElementById('rulesFilter').addEventListener('click',()=>{
  filters.rules=!filters.rules; applyFilters();
});
agentFilterButton.addEventListener('click',()=>{
  const expanded=agentFilterButton.getAttribute('aria-expanded')==='true';
  agentFilterPanel.hidden=expanded;
  agentFilterButton.setAttribute('aria-expanded',String(!expanded));
  if(!expanded){
    const firstOption=agentFilterOptions.querySelector('input');
    if(firstOption)firstOption.focus();
  }
});
agentFilterOptions.addEventListener('change',event=>{
  const input=event.target.closest('input[data-agent-value]');
  if(!input)return;
  if(input.checked)filters.agents.add(input.value);else filters.agents.delete(input.value);
  applyFilters();
});
document.addEventListener('click',event=>{
  if(!agentFilter.contains(event.target)){
    agentFilterPanel.hidden=true;
    agentFilterButton.setAttribute('aria-expanded','false');
  }
});
document.addEventListener('keydown',event=>{
  if(event.key==='Escape'&&!agentFilterPanel.hidden){
    agentFilterPanel.hidden=true;
    agentFilterButton.setAttribute('aria-expanded','false');
    agentFilterButton.focus();
  }
});
document.getElementById('clearFilters').addEventListener('click',()=>{
  filters.types.clear(); filters.severities.clear(); filters.agents.clear();
  filters.blocked=false; filters.rules=false;
  agentFilterPanel.hidden=true; agentFilterButton.setAttribute('aria-expanded','false');
  applyFilters();
});
window.addEventListener('numbat-language-change',()=>{
  updateFilterControls(); renderCurrentCards(); updateStats(); updateExportLink(); updateConnection();
  if(activeToast)document.getElementById('toast').textContent=i18n.t(activeToast.key,activeToast.values);
});
updateExportLink();
updateFilterControls();
document.getElementById('resetBtn').onclick=()=>{
  if(!confirm(i18n.t('confirm_reset')))return;
  fetch('reset',{method:'POST'}).then(r=>r.json()).then(res=>{
    if(!res.count){toast('toast_empty');return;}
    const suffix=res.archived?i18n.t('archive_suffix',{archived:res.archived}):'';
    toast(res.count===1?'toast_archived_one':'toast_archived_many',
      {count:res.count,archive_suffix:suffix});
  }).catch(()=>toast('toast_reset_failed'));
};
fetch('history').then(r=>r.json()).then(arr=>{
  all.push(...arr);
  updateAgentOptions(); renderCurrentCards(); updateStats();
}).catch(()=>{});
setInterval(()=>{
  document.getElementById('lastSeen').textContent=lastTs?i18n.t('last_seen',{time:relTime(lastTs)}):'';
},5000);
const es=new EventSource('events');
es.onopen=()=>{dot.classList.remove('off');connectionState='live';updateConnection();};
es.onerror=()=>{dot.classList.add('off');connectionState='reconnecting';updateConnection();};
es.onmessage=e=>{try{addRec(JSON.parse(e.data),true);}catch(_){}};
es.addEventListener('reset',()=>{all.length=0;list.innerHTML='';
  updateAgentOptions();renderCurrentCards();updateStats();});
</script>
</body></html>
"""

ARCHIVES_TMPL = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title data-i18n="archives_title">Numbat — Archived Records</title>
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
.language-wrap{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:12px}
.language-select{font:inherit;color:var(--text);background:var(--panel2);
  border:1px solid var(--border);border-radius:7px;padding:5px 8px}
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
<header><h1 data-i18n="archives_heading">Numbat &middot; Archived Records</h1><div class="spacer"></div>
<span class="language-wrap"><label for="languageSelect" data-i18n="language">Language</label>
  <select class="language-select" id="languageSelect" data-i18n-aria-label="language">
    <option value="en">English</option><option value="zh-TW">繁體中文（台灣）</option>
  </select></span>
<a class="back" href="/" data-i18n="back_to_dashboard">&larr; Back to live dashboard</a></header>
<div class="wrap">
<table><thead><tr><th data-i18n="archive_file">Archive file</th><th data-i18n="archive_records">Records</th><th data-i18n="archive_size">Size</th></tr></thead>
<tbody>{{ROWS}}</tbody></table>
</div>{{I18N_SCRIPT}}</body></html>
"""


XLSX_COLUMNS = [
    lambda r: r.get("timestamp") or r.get("detected_at") or r.get("last_seen") or "",
    lambda r: r.get("record_type") or r.get("event_type") or r.get("type", ""),
    lambda r: r.get("severity") or r.get("level", ""),
    lambda r: r.get("rule_id") or ", ".join(r.get("rule_ids", [])),
    lambda r: r.get("rule_version", ""),
    lambda r: r.get("title") or r.get("message", ""),
    lambda r: r.get("observed_actor") or r.get("actor", ""),
    lambda r: r.get("source_agent", ""),
    lambda r: r.get("confidence", ""),
    lambda r: ", ".join(r.get("tags", [])),
    lambda r: r.get("decision") or r.get("approval_decision", ""),
    lambda r: r.get("mode", ""),
    lambda r: r.get("reason") or r.get("approval_reason", ""),
    lambda r: r.get("tool_name") or r.get("mcp_tool", ""),
    lambda r: r.get("observed_command") or r.get("command", ""),
    lambda r: r.get("session_id", ""),
    lambda r: r.get("finding_id") or r.get("decision_id") or r.get("event_id") or r.get("sample_event_id") or "",
    lambda r: r.get("value", ""),
    lambda r: r.get("count", ""),
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


def build_xlsx(language="en"):
    language = normalize_language(language)
    with history_lock:
        rows = [TRANSLATIONS[language]["xlsx_headers"]]
        for rec in history:
            rows.append([fn(rec) for fn in XLSX_COLUMNS])

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
        '<sheets><sheet name="%s" sheetId="1" r:id="rId1"/></sheets></workbook>'
        % _xesc(TRANSLATIONS[language]["xlsx_sheet_name"])
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
        '<tr><td colspan="3" style="color:var(--muted)" data-i18n="archives_empty">'
        'No archives yet — use Reset on the dashboard to create one.</td></tr>'
    )
    return render_template(ARCHIVES_TMPL.replace("{{ROWS}}", body))


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
        request = urlsplit(self.path)
        path = request.path
        if path == "/":
            self._send(200, "text/html; charset=utf-8", render_template(PAGE).encode())
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
            language = parse_qs(request.query).get("lang", ["en"])[0]
            body = build_xlsx(language)
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
