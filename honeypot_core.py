"""
Shared helpers for the honeypot: IP handling, command risk labels, and state I/O.
Kept in a small module so app.py stays readable and logic is easy to test or extend.
"""
from __future__ import annotations

import json
import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

STATE_FILE = os.environ.get("HONEYPOT_STATE_FILE", "honeypot_state.json")

# Brute-force heuristics (tunable)
LOGIN_WINDOW_MINUTES = int(os.environ.get("HONEYPOT_LOGIN_WINDOW_MIN", "15"))
LOGIN_ATTEMPT_THRESHOLD = int(os.environ.get("HONEYPOT_LOGIN_THRESHOLD", "8"))

DEFAULT_STATE: dict[str, Any] = {
    "ip_request_counts": {},  # ip -> int
    "login_attempts": {},     # ip -> list of ISO timestamps (recent)
    "ip_flags": {},           # ip -> list of human-readable flag strings
    "ip_geo": {},             # ip -> { country, countryCode, cached_at, source }
    "attacker_profiles": {},  # ip -> profile snapshot
    "sessions": {},           # session_id -> session telemetry
    "alert_delivery_history": {},  # alert signature -> ISO timestamp
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_client_ip(request) -> str:
    """
    Prefer X-Forwarded-For when behind a reverse proxy; take the first hop.
    Fall back to remote_addr. Never trust client-supplied headers on the open
    internet without configuring trusted proxies — here we document that for lab use.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            return parts[0]
    if request.remote_addr:
        return request.remote_addr
    return "unknown"


def load_state() -> dict[str, Any]:
    if not os.path.isfile(STATE_FILE):
        return json.loads(json.dumps(DEFAULT_STATE))
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return json.loads(json.dumps(DEFAULT_STATE))
    merged = json.loads(json.dumps(DEFAULT_STATE))
    merged.update(data)
    for key in DEFAULT_STATE:
        if key not in merged or not isinstance(merged[key], type(DEFAULT_STATE[key])):
            merged[key] = json.loads(json.dumps(DEFAULT_STATE[key]))
    return merged


def save_state(state: dict[str, Any]) -> None:
    tmp = STATE_FILE + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, STATE_FILE)
    except OSError as exc:
        # Deployment environments may have restricted filesystem writes.
        # Keep request handling alive even when persistence is unavailable.
        logging.getLogger(__name__).warning("State persistence failed: %s", exc)
        try:
            if os.path.isfile(tmp):
                os.remove(tmp)
        except OSError:
            pass


def prune_old_login_attempts(state: dict[str, Any]) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=LOGIN_WINDOW_MINUTES)
    attempts: dict[str, list] = state.get("login_attempts") or {}
    for ip, stamps in list(attempts.items()):
        kept = []
        for s in stamps:
            try:
                t = datetime.fromisoformat(s.replace("Z", "+00:00"))
                if t.tzinfo is None:
                    t = t.replace(tzinfo=timezone.utc)
                if t >= cutoff:
                    kept.append(s)
            except ValueError:
                continue
        attempts[ip] = kept
        if not kept:
            del attempts[ip]


def record_request(state: dict[str, Any], ip: str) -> None:
    counts = state.setdefault("ip_request_counts", {})
    counts[ip] = int(counts.get(ip, 0)) + 1


def _to_set_list(values: list[str], new_value: str, max_items: int = 8) -> list[str]:
    out = [v for v in values if v]
    if new_value and new_value not in out:
        out.append(new_value)
    if len(out) > max_items:
        out = out[-max_items:]
    return out


def normalize_user_agent(user_agent: str | None) -> tuple[str, str]:
    ua = (user_agent or "").lower()
    browser = "Other"
    device = "Desktop"
    if "edg/" in ua:
        browser = "Edge"
    elif "chrome/" in ua and "edg/" not in ua:
        browser = "Chrome"
    elif "firefox/" in ua:
        browser = "Firefox"
    elif "safari/" in ua and "chrome/" not in ua:
        browser = "Safari"
    elif "curl/" in ua:
        browser = "curl"
    elif "python-requests" in ua:
        browser = "python-requests"

    if "bot" in ua or "spider" in ua or "crawler" in ua:
        device = "Bot"
    elif "mobile" in ua or "android" in ua or "iphone" in ua:
        device = "Mobile"
    elif "tablet" in ua or "ipad" in ua:
        device = "Tablet"
    return browser, device


def update_attacker_profile(state: dict[str, Any], ip: str, user_agent: str, path: str) -> None:
    profiles = state.setdefault("attacker_profiles", {})
    p = profiles.setdefault(
        ip,
        {
            "attacker_id": f"attacker::{ip}",
            "first_seen": utc_now_iso(),
            "last_seen": utc_now_iso(),
            "hit_count": 0,
            "paths": [],
            "user_agents": [],
            "browsers": [],
            "devices": [],
        },
    )
    p["last_seen"] = utc_now_iso()
    p["hit_count"] = int(p.get("hit_count", 0)) + 1
    p["paths"] = _to_set_list(list(p.get("paths") or []), path, max_items=12)
    p["user_agents"] = _to_set_list(list(p.get("user_agents") or []), user_agent[:180], max_items=6)
    browser, device = normalize_user_agent(user_agent)
    p["browsers"] = _to_set_list(list(p.get("browsers") or []), browser, max_items=4)
    p["devices"] = _to_set_list(list(p.get("devices") or []), device, max_items=4)


def ensure_session(state: dict[str, Any], session_id: str | None, ip: str, user_agent: str) -> str:
    sid = (session_id or "").strip() or f"s-{uuid4().hex[:20]}"
    sessions = state.setdefault("sessions", {})
    s = sessions.setdefault(
        sid,
        {
            "session_id": sid,
            "ip": ip,
            "started_at": utc_now_iso(),
            "last_seen": utc_now_iso(),
            "actions": 0,
            "user_agent": user_agent[:180],
            "browser": normalize_user_agent(user_agent)[0],
            "device": normalize_user_agent(user_agent)[1],
        },
    )
    s["last_seen"] = utc_now_iso()
    s["actions"] = int(s.get("actions", 0)) + 1
    return sid


def session_duration_seconds(session_row: dict[str, Any]) -> int:
    try:
        st = datetime.fromisoformat(str(session_row.get("started_at", "")).replace("Z", "+00:00"))
        en = datetime.fromisoformat(str(session_row.get("last_seen", "")).replace("Z", "+00:00"))
        if st.tzinfo is None:
            st = st.replace(tzinfo=timezone.utc)
        if en.tzinfo is None:
            en = en.replace(tzinfo=timezone.utc)
        return max(0, int((en - st).total_seconds()))
    except Exception:
        return 0


def record_login_attempt(state: dict[str, Any], ip: str, username: str) -> bool:
    """
    Append a login attempt and set flags if threshold exceeded in the window.
    Returns True if this attempt triggered (or reinforced) a brute-force flag.
    """
    prune_old_login_attempts(state)
    attempts = state.setdefault("login_attempts", {})
    stamps = attempts.setdefault(ip, [])
    stamps.append(utc_now_iso())
    prune_old_login_attempts(state)
    stamps = attempts.get(ip, [])
    flagged = len(stamps) >= LOGIN_ATTEMPT_THRESHOLD
    if flagged:
        flags = state.setdefault("ip_flags", {})
        fl = flags.setdefault(ip, [])
        msg = f"possible_brute_force_{len(stamps)}_logins_in_{LOGIN_WINDOW_MINUTES}m"
        if msg not in fl:
            fl.append(msg)
    return flagged


_DANGEROUS_PATTERNS = [
    (r"\brm\s+(-rf|-fr|-r)\b", "destructive file removal (rm)"),
    (r"\bdel(\s+/|\s+\\\\)\b", "recursive or forced delete (Windows)"),
    (r"\bformat\b", "disk format"),
    (r"\bshutdown\b|\breboot\b", "system power control"),
    (r"\breg(\.exe)?\s+(add|delete|import)\b", "registry modification"),
    (r"Invoke-Expression|IEX\b", "PowerShell code execution"),
    (r"\bbitsadmin\b", "file transfer / persistence vector"),
    (r"\bcertutil\s+-urlcache\b", "download via certutil"),
    (r"powershell\s+.*-enc", "encoded PowerShell"),
    (r"\bwget\b|\bcurl\b", "download tool (often abuse)"),
    (r"\bnet\s+user\b|\bnet\s+localgroup\b", "user/group changes"),
    (r"\bcd\s+\\\\|\\\\[^\s]+\\[^\\]+\$", "UNC path access"),
    (r">\s*[/\\]|^\s*echo\s+.*>", "output redirection (possible overwrite)"),
    (r";\s*\w+|&&|\|\|", "command chaining"),
    (r"`|\$\(", "command substitution"),
    (r"\bchmod\s+777\b|\bicacls\b", "permission manipulation"),
    (r"\bpasswd\b|\bchpasswd\b", "credential change attempts"),
    (r"\bnetsh\s+advfirewall\b", "firewall tampering"),
    (r"\bvssadmin\s+delete\b", "shadow copy deletion"),
    (r"\bsc\s+(create|config)\b", "service persistence"),
]

_SUSPICIOUS_PATTERNS = [
    (r"\bwhoami\b|\bid\b", "identity discovery"),
    (r"\bipconfig\b|\bifconfig\b", "network config discovery"),
    (r"\bnetstat\b|\bss\s+-", "network connections"),
    (r"\btasklist\b|\bps\b", "process listing"),
    (r"\btype\s+|\bcat\s+", "file content read"),
    (r"\bscp\b|\bftp\b", "file transfer"),
    (r"\bwmic\b", "WMI enumeration"),
    (r"\bsysteminfo\b", "system profiling"),
    (r"\bhostname\b|\bgetmac\b", "host discovery"),
    (r"\bdir\s+/s\b|\bfindstr\b", "file discovery sweep"),
    (r"\broute\s+print\b|\barp\s+-a\b", "network mapping"),
]

_ATTACK_TECHNIQUES = [
    (r"\bwhoami\b|\bid\b|\bsysteminfo\b|\bhostname\b|\bgetmac\b|\bwmic\b", ("T1082", "System Information Discovery")),
    (r"\bipconfig\b|\bifconfig\b|\bnetstat\b|\broute\s+print\b|\barp\s+-a\b", ("T1016", "Network Discovery")),
    (r"\btype\s+|\bcat\s+|\bfindstr\b|\bdir\s+/s\b", ("T1083", "File and Directory Discovery")),
    (r"\bcurl\b|\bwget\b|\bcertutil\s+-urlcache\b|\bbitsadmin\b", ("T1105", "Ingress Tool Transfer")),
    (r"\bnet\s+user\b|\bnet\s+localgroup\b|\bpasswd\b|\bchpasswd\b", ("T1098", "Account Manipulation")),
    (r"\breg(\.exe)?\s+(add|delete|import)\b|\bnetsh\s+advfirewall\b", ("T1562", "Impair Defenses")),
    (r"\bsc\s+(create|config)\b", ("T1543", "Create or Modify System Process")),
    (r"\bdel\b|\brm\b|\bformat\b|\bvssadmin\s+delete\b", ("T1485", "Data Destruction")),
]


def classify_command(cmd: str | None) -> tuple[str, str]:
    """
    Returns (level, reason) where level is 'safe' | 'suspicious' | 'dangerous'.
    Heuristic only — tune patterns for your lab OS and threat model.
    """
    if not cmd or not str(cmd).strip():
        return "safe", "empty"
    s = str(cmd).strip()
    low = s.lower()

    for pat, reason in _DANGEROUS_PATTERNS:
        if re.search(pat, low, re.IGNORECASE):
            return "dangerous", reason

    for pat, reason in _SUSPICIOUS_PATTERNS:
        if re.search(pat, low, re.IGNORECASE):
            return "suspicious", reason

    if low in ("dir", "cd", "ls", "pwd", "df"):
        return "safe", "common benign command"
    if re.match(r"^echo\s+\S+$", low):
        return "safe", "simple echo"

    if len(low) <= 32 and not re.search(r"[;&|`$()<>]", low):
        return "safe", "short simple command"

    return "suspicious", "unusual or complex pattern"


def map_attack_techniques(cmd: str | None, risk_level: str | None = None) -> list[dict[str, str]]:
    if not cmd:
        return []
    s = str(cmd).strip().lower()
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for pat, (tid, name) in _ATTACK_TECHNIQUES:
        if re.search(pat, s, re.IGNORECASE) and tid not in seen:
            seen.add(tid)
            out.append({"id": tid, "name": name})
    if not out and risk_level in ("suspicious", "dangerous"):
        out.append({"id": "T1059", "name": "Command and Scripting Interpreter"})
    return out


def read_log_lines_tail(log_path: str, max_bytes: int = 256_000) -> list[str]:
    """Return log file lines from the end up to max_bytes for UI display."""
    if not os.path.isfile(log_path):
        return []
    try:
        with open(log_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            start = max(0, size - max_bytes)
            f.seek(start)
            chunk = f.read().decode("utf-8", errors="replace")
    except OSError:
        return []
    lines = chunk.splitlines()
    if start > 0 and lines:
        lines = lines[1:]
    return lines


def event_datetime(e: dict[str, Any]) -> datetime | None:
    """Parse event timestamp for timeline charts (Mongo may store datetime or ISO string)."""
    t = e.get("ts")
    if isinstance(t, datetime):
        return t if t.tzinfo else t.replace(tzinfo=timezone.utc)
    if isinstance(t, str):
        try:
            dt = datetime.fromisoformat(t.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def hourly_timeline(events: list[dict[str, Any]], hours: int = 24) -> tuple[list[str], list[int]]:
    """UTC hour buckets for Chart.js — one bar per hour in the window."""
    hours = max(1, min(hours, 168))
    end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(hours=hours - 1)
    bucket_counts: dict[datetime, int] = defaultdict(int)
    for e in events:
        dt = event_datetime(e)
        if not dt:
            continue
        hb = dt.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        if hb < start or hb > end:
            continue
        bucket_counts[hb] += 1
    labels: list[str] = []
    counts: list[int] = []
    h = start
    while h <= end:
        labels.append(h.strftime("%d %H:00 UTC"))
        counts.append(bucket_counts.get(h, 0))
        h += timedelta(hours=1)
    return labels, counts


def aggregate_analytics(events: list[dict[str, Any]]) -> dict[str, Any]:
    command_counts: dict[str, int] = {}
    total_commands = 0
    risk_counts = {"safe": 0, "suspicious": 0, "dangerous": 0}
    by_ip_commands: dict[str, int] = {}
    login_by_ip: dict[str, int] = {}
    session_actions: dict[str, int] = {}
    technique_counts: dict[str, int] = {}

    for e in events:
        et = e.get("type")
        if et == "command":
            total_commands += 1
            c = (e.get("command") or "").strip() or "(empty)"
            command_counts[c] = command_counts.get(c, 0) + 1
            lvl = e.get("risk_level") or "safe"
            if lvl in risk_counts:
                risk_counts[lvl] += 1
            ip = e.get("ip") or "unknown"
            by_ip_commands[ip] = by_ip_commands.get(ip, 0) + 1
            sid = (e.get("session_id") or "").strip()
            if sid:
                session_actions[sid] = session_actions.get(sid, 0) + 1
            for t in (e.get("attack_techniques") or []):
                tid = str((t or {}).get("id") or "").strip()
                name = str((t or {}).get("name") or "").strip()
                if not tid:
                    continue
                label = f"{tid} · {name}" if name else tid
                technique_counts[label] = technique_counts.get(label, 0) + 1
        elif et == "login_attempt":
            ip = e.get("ip") or "unknown"
            login_by_ip[ip] = login_by_ip.get(ip, 0) + 1
            sid = (e.get("session_id") or "").strip()
            if sid:
                session_actions[sid] = session_actions.get(sid, 0) + 1

    top_commands = sorted(command_counts.items(), key=lambda x: -x[1])[:15]

    country_rollups: dict[str, tuple[str, int]] = {}
    for e in events:
        code = (str(e.get("country_code") or "")).strip()
        if not code or code in ("??", "LAN"):
            continue
        label = (e.get("country") or code) or code
        prev = country_rollups.get(code, (label, 0))
        country_rollups[code] = (prev[0], prev[1] + 1)
    top_countries = sorted(country_rollups.items(), key=lambda x: -x[1][1])[:10]

    t_labels, t_counts = hourly_timeline(events, hours=24)
    bar_labels = [c[0][:36] + ("…" if len(c[0]) > 36 else "") for c in top_commands[:12]]
    bar_data = [c[1] for c in top_commands[:12]]

    total_logins = sum(login_by_ip.values())
    return {
        "total_commands": total_commands,
        "total_logins": total_logins,
        "total_interactions": total_commands + total_logins,
        "top_commands": top_commands,
        "risk_counts": risk_counts,
        "unique_ips_commands": len(by_ip_commands),
        "top_ips_by_commands": sorted(by_ip_commands.items(), key=lambda x: -x[1])[:10],
        "login_by_ip": sorted(login_by_ip.items(), key=lambda x: -x[1])[:10],
        "top_sessions": sorted(session_actions.items(), key=lambda x: -x[1])[:12],
        "top_techniques": sorted(technique_counts.items(), key=lambda x: -x[1])[:12],
        "chart_timeline_labels": t_labels,
        "chart_timeline_data": t_counts,
        "chart_country_labels": [x[1][0] for x in top_countries],
        "chart_country_data": [x[1][1] for x in top_countries],
        "chart_command_labels": bar_labels,
        "chart_command_data": bar_data,
    }


def generate_alerts(state: dict[str, Any], events: list[dict[str, Any]], max_alerts: int = 20) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    seen: set[str] = set()
    now = datetime.now(timezone.utc)

    for ip, flags in (state.get("ip_flags") or {}).items():
        for f in flags:
            key = f"bf::{ip}::{f}"
            if key in seen:
                continue
            seen.add(key)
            alerts.append(
                {
                    "severity": "high",
                    "kind": "brute_force",
                    "ip": ip,
                    "message": f"Brute-force indicator on {ip}: {f}",
                    "ts": utc_now_iso(),
                }
            )

    cmd_burst: dict[tuple[str, str], int] = {}
    for e in events[-400:]:
        if e.get("type") != "command":
            continue
        ip = str(e.get("ip") or "unknown")
        cmd = str(e.get("command") or "").strip().lower()
        if not cmd:
            continue
        k = (ip, cmd)
        cmd_burst[k] = cmd_burst.get(k, 0) + 1

        if e.get("risk_level") == "dangerous":
            key = f"danger::{ip}::{cmd}"
            if key not in seen:
                seen.add(key)
                alerts.append(
                    {
                        "severity": "critical",
                        "kind": "dangerous_command",
                        "ip": ip,
                        "message": f"Dangerous command from {ip}: {cmd[:80]}",
                        "ts": str(e.get("ts") or utc_now_iso()),
                    }
                )

    for (ip, cmd), n in cmd_burst.items():
        if n >= 5:
            key = f"repeat::{ip}::{cmd}"
            if key in seen:
                continue
            seen.add(key)
            alerts.append(
                {
                    "severity": "medium",
                    "kind": "repeat_command",
                    "ip": ip,
                    "message": f"Repeated command ({n}x) from {ip}: {cmd[:72]}",
                    "ts": utc_now_iso(),
                }
            )

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    alerts.sort(key=lambda a: (sev_rank.get(a.get("severity", "low"), 9), a.get("ts", "")))
    return alerts[:max_alerts]
