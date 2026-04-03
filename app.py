from __future__ import annotations

import logging
import os
import subprocess
import time
import json
from urllib import request as urlrequest

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for

from honeypot_core import (
    LOGIN_ATTEMPT_THRESHOLD,
    LOGIN_WINDOW_MINUTES,
    aggregate_analytics,
    classify_command,
    ensure_session,
    generate_alerts,
    get_client_ip,
    load_state,
    map_attack_techniques,
    record_login_attempt,
    record_request,
    save_state,
    session_duration_seconds,
    update_attacker_profile,
)
from honeypot_geo import geo_snapshot_for_ip, record_geo_if_needed, refresh_geo_and_get_snapshot
from honeypot_storage import (
    append_event,
    get_log_lines_tail,
    read_events_filtered,
    read_events_tail,
    setup_application_logging,
    using_mongodb,
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change_me_in_production")
ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "").strip()
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
WS_ENABLED = False
sock = None
try:
    from flask_sock import Sock

    sock = Sock(app)
    WS_ENABLED = True
except Exception:
    WS_ENABLED = False

LOG_PATH = os.environ.get("HONEYPOT_LOG_FILE", "honeypot.log")
LOG_BACKEND = setup_application_logging(LOG_PATH)


def _with_state(mutator):
    """Load JSON state, apply mutator, save. Used to avoid races in simple lab deployments."""
    state = load_state()
    mutator(state)
    save_state(state)
    return state


def _post_json(url: str, payload: dict) -> bool:
    if not url:
        return False
    data = json.dumps(payload).encode("utf-8")
    req = urlrequest.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urlrequest.urlopen(req, timeout=3) as resp:
            return 200 <= int(resp.status) < 300
    except Exception:
        return False


def _deliver_alerts(state: dict, alerts: list[dict]) -> dict:
    hist = state.setdefault("alert_delivery_history", {})
    stats = {"sent": 0, "deduped": 0, "failed": 0}
    for a in alerts:
        sev = str(a.get("severity") or "")
        if sev not in ("critical", "high"):
            continue
        sig = f"{a.get('kind','')}/{a.get('ip','')}/{a.get('message','')[:120]}"
        if sig in hist:
            stats["deduped"] += 1
            continue
        payload = {
            "source": "honeypot-soc",
            "severity": sev,
            "kind": a.get("kind"),
            "ip": a.get("ip"),
            "message": a.get("message"),
            "timestamp": a.get("ts"),
        }
        ok = _post_json(ALERT_WEBHOOK_URL, payload)
        if SLACK_WEBHOOK_URL:
            slack_payload = {"text": f"[{sev.upper()}] {payload['message']}"}
            ok = _post_json(SLACK_WEBHOOK_URL, slack_payload) or ok
        if ok:
            hist[sig] = str(a.get("ts") or "")
            stats["sent"] += 1
        else:
            stats["failed"] += 1
    state["alert_delivery_stats"] = stats
    return stats


@app.before_request
def track_request():
    """Increment per-IP request counters (persisted). Omit static assets if added later."""
    ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "") or ""

    def bump(s):
        record_request(s, ip)
        update_attacker_profile(s, ip, user_agent, request.path)
        sid = ensure_session(s, session.get("sid"), ip, user_agent)
        session["sid"] = sid

    state = _with_state(bump)
    session["attacker_id"] = f"attacker::{ip}"
    if ip in (state.get("attacker_profiles") or {}):
        session["last_profile_ip"] = ip


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        ip = get_client_ip(request)
        ua = request.headers.get("User-Agent", "") or ""

        logging.info("Login attempt -> Username: %s, Password: %s, IP: %s", username, password, ip)

        def register_login(s):
            record_geo_if_needed(s, ip)
            flagged = record_login_attempt(s, ip, username or "")
            snap = geo_snapshot_for_ip(s, ip)
            sid = ensure_session(s, session.get("sid"), ip, ua)
            session["sid"] = sid
            append_event(
                {
                    "type": "login_attempt",
                    "ip": ip,
                    "attacker_id": f"attacker::{ip}",
                    "session_id": sid,
                    "user_agent": ua[:180],
                    "browser": s.get("sessions", {}).get(sid, {}).get("browser"),
                    "device": s.get("sessions", {}).get(sid, {}).get("device"),
                    "username": username,
                    "brute_force_flag": flagged,
                    "country": snap.get("country"),
                    "country_code": snap.get("countryCode"),
                }
            )

        _with_state(register_login)

        return redirect(url_for("admin"))

    return render_template("login.html")


@app.route("/admin")
def admin():
    state = load_state()
    ip = get_client_ip(request)
    counts = state.get("ip_request_counts") or {}
    my_requests = counts.get(ip, 0)
    top_ips = sorted(counts.items(), key=lambda x: -x[1])[:8]
    geo = state.get("ip_geo") or {}
    events = read_events_tail(500)
    summary = aggregate_analytics(events)
    alerts = generate_alerts(state, events)
    delivery_stats = _with_state(lambda s: _deliver_alerts(s, alerts)).get("alert_delivery_stats") or {}
    recent_events = events[-25:]
    profiles = state.get("attacker_profiles") or {}
    top_attackers = sorted(profiles.items(), key=lambda x: -(x[1].get("hit_count") or 0))[:8]
    sessions = state.get("sessions") or {}
    top_sessions = sorted(
        sessions.values(),
        key=lambda x: -(x.get("actions") or 0),
    )[:8]
    return render_template(
        "admin.html",
        my_ip=ip,
        my_requests=my_requests,
        top_ips=top_ips,
        summary=summary,
        ip_flags=state.get("ip_flags") or {},
        ip_geo=geo,
        alerts=alerts,
        recent_events=recent_events,
        top_attackers=top_attackers,
        top_sessions=top_sessions,
        session_duration_seconds=session_duration_seconds,
        login_threshold=LOGIN_ATTEMPT_THRESHOLD,
        login_window=LOGIN_WINDOW_MINUTES,
        mongodb_enabled=using_mongodb(),
        ws_enabled=WS_ENABLED,
        alert_delivery_stats=delivery_stats,
    )


@app.route("/logs")
def view_logs():
    f_type = (request.args.get("type") or "").strip() or None
    f_risk = (request.args.get("risk") or "").strip() or None
    f_ip = (request.args.get("ip") or "").strip() or None
    f_country = (request.args.get("country") or "").strip() or None
    f_attack = (request.args.get("attack_id") or "").strip().upper() or None
    lines = get_log_lines_tail(LOG_PATH, max_lines=600)
    filtered_events = read_events_filtered(
        max_lines=250,
        event_type=f_type,
        risk_level=f_risk,
        ip=f_ip,
        country=f_country,
        attack_id=f_attack,
    )
    return render_template(
        "logs.html",
        log_lines=lines,
        filtered_events=filtered_events,
        log_path=LOG_PATH if LOG_BACKEND == "file" else "MongoDB · honeypot_logs",
        log_backend=LOG_BACKEND,
    )


@app.route("/analytics")
def analytics():
    state = load_state()
    f_type = (request.args.get("type") or "").strip() or None
    f_risk = (request.args.get("risk") or "").strip() or None
    f_ip = (request.args.get("ip") or "").strip() or None
    f_country = (request.args.get("country") or "").strip() or None
    f_attack = (request.args.get("attack_id") or "").strip().upper() or None
    since_minutes = request.args.get("since_minutes")
    try:
        since_minutes_i = int(since_minutes) if since_minutes else None
    except ValueError:
        since_minutes_i = None
    events = read_events_filtered(
        max_lines=5000,
        event_type=f_type,
        risk_level=f_risk,
        ip=f_ip,
        country=f_country,
        since_minutes=since_minutes_i,
        attack_id=f_attack,
    )
    agg = aggregate_analytics(events)
    counts = state.get("ip_request_counts") or {}
    return render_template(
        "analytics.html",
        agg=agg,
        ip_request_counts=sorted(counts.items(), key=lambda x: -x[1])[:20],
        ip_flags=state.get("ip_flags") or {},
        login_attempts=state.get("login_attempts") or {},
        active_filters={
            "type": f_type or "",
            "risk": f_risk or "",
            "ip": f_ip or "",
            "country": f_country or "",
            "attack_id": f_attack or "",
            "since_minutes": str(since_minutes_i or ""),
        },
        log_backend=LOG_BACKEND,
        mongodb_enabled=using_mongodb(),
    )


@app.route("/attacker/<path:ip_addr>")
def attacker_detail(ip_addr: str):
    state = load_state()
    events = read_events_filtered(max_lines=1200, ip=ip_addr)
    profile = (state.get("attacker_profiles") or {}).get(ip_addr) or {}
    sessions = [
        s for s in (state.get("sessions") or {}).values() if str(s.get("ip") or "") == ip_addr
    ]
    sessions.sort(key=lambda x: -(x.get("actions") or 0))
    return render_template(
        "attacker_detail.html",
        ip_addr=ip_addr,
        profile=profile,
        sessions=sessions[:20],
        events=events[-100:],
        session_duration_seconds=session_duration_seconds,
        ip_geo=(state.get("ip_geo") or {}).get(ip_addr) or {},
        mongodb_enabled=using_mongodb(),
    )


@app.route("/logout")
def logout():
    return redirect(url_for("home"))


@app.route("/vulnerable", methods=["GET"])
def vulnerable():
    cmd = request.args.get("cmd")
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent", "") or ""
    output = "No command provided"
    risk_level, risk_reason = "safe", ""

    if cmd:
        risk_level, risk_reason = classify_command(cmd)
        display_cmd = cmd
        snap = refresh_geo_and_get_snapshot(load_state, save_state, ip)
        state = load_state()
        sid = ensure_session(state, session.get("sid"), ip, ua)
        save_state(state)
        session["sid"] = sid
        try:
            if cmd == "ls":
                display_cmd = "dir"
                cmd = "dir"
            elif cmd == "pwd":
                display_cmd = "cd"
                cmd = "cd"
            elif cmd == "df":
                display_cmd = "wmic logicaldisk get size,freespace,caption"
                cmd = "wmic logicaldisk get size,freespace,caption"

            logging.info(
                "Received command: %s | IP: %s | risk=%s (%s)",
                display_cmd,
                ip,
                risk_level,
                risk_reason,
            )
            append_event(
                {
                    "type": "command",
                    "ip": ip,
                    "attacker_id": f"attacker::{ip}",
                    "session_id": sid,
                    "user_agent": ua[:180],
                    "browser": state.get("sessions", {}).get(sid, {}).get("browser"),
                    "device": state.get("sessions", {}).get(sid, {}).get("device"),
                    "command": request.args.get("cmd") or "",
                    "executed_as": display_cmd,
                    "risk_level": risk_level,
                    "risk_reason": risk_reason,
                    "attack_techniques": map_attack_techniques(request.args.get("cmd") or "", risk_level),
                    "country": snap.get("country"),
                    "country_code": snap.get("countryCode"),
                }
            )

            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            output = (result.stdout or "") + (result.stderr or "")
            logging.info("Command output (truncated): %s", (output[:500] + "…") if len(output) > 500 else output)

        except Exception as e:
            output = f"Error: {str(e)}"
            logging.exception("Error executing command")

    return render_template(
        "vulnerable.html",
        output=output,
        risk_level=risk_level,
        risk_reason=risk_reason,
        raw_cmd=request.args.get("cmd") or "",
    )


@app.route("/backup.zip")
def decoy_backup():
    ip = get_client_ip(request)
    append_event(
        {
            "type": "deception_hit",
            "ip": ip,
            "path": "/backup.zip",
            "risk_level": "dangerous",
            "risk_reason": "sensitive decoy file accessed",
            "attacker_id": f"attacker::{ip}",
            "session_id": session.get("sid"),
        }
    )
    return ("PK\x03\x04FakeBackupArchive", 200, {"Content-Type": "application/octet-stream"})


@app.route("/config/.env")
def decoy_env():
    ip = get_client_ip(request)
    append_event(
        {
            "type": "deception_hit",
            "ip": ip,
            "path": "/config/.env",
            "risk_level": "dangerous",
            "risk_reason": ".env decoy probe",
            "attacker_id": f"attacker::{ip}",
            "session_id": session.get("sid"),
        }
    )
    fake = "DB_PASSWORD=prod_shadow_42\nAPI_KEY=canary_demo_key\nDEBUG=false\n"
    return (fake, 200, {"Content-Type": "text/plain; charset=utf-8"})


@app.route("/admin/export")
def decoy_admin_export():
    ip = get_client_ip(request)
    append_event(
        {
            "type": "deception_hit",
            "ip": ip,
            "path": "/admin/export",
            "risk_level": "dangerous",
            "risk_reason": "admin data export decoy probe",
            "attacker_id": f"attacker::{ip}",
            "session_id": session.get("sid"),
        }
    )
    return jsonify({"status": "queued", "message": "Export is processing. Contact security team."})


@app.route("/api/events/recent")
def api_recent_events():
    events = read_events_tail(40)
    return jsonify(events[-20:])


@app.route("/events/stream")
def events_stream():
    def generate():
        last_marker = None
        initialized = False
        while True:
            events = read_events_tail(40)
            if not initialized:
                if events:
                    last = events[-1]
                    last_marker = f"{last.get('ts','')}|{last.get('type','')}|{last.get('ip','')}"
                initialized = True
                time.sleep(2.0)
                continue
            for e in events:
                marker = f"{e.get('ts','')}|{e.get('type','')}|{e.get('ip','')}"
                if last_marker is not None and marker == last_marker:
                    continue
                if last_marker is not None and marker < last_marker:
                    continue
                last_marker = marker
                payload = json.dumps(e)
                yield f"data: {payload}\n\n"
            time.sleep(2.0)

    return Response(generate(), mimetype="text/event-stream")


if WS_ENABLED and sock is not None:
    @sock.route("/ws/events")
    def ws_events(ws):
        last_marker = None
        while True:
            events = read_events_tail(50)
            for e in events:
                marker = f"{e.get('ts','')}|{e.get('type','')}|{e.get('ip','')}"
                if last_marker is not None and marker <= last_marker:
                    continue
                last_marker = marker
                try:
                    ws.send(json.dumps(e))
                except Exception:
                    return
            time.sleep(1.5)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
