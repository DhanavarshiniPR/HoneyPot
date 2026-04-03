"""
Persistence layer: JSONL files (default) or MongoDB when MONGODB_URI is set.
Application log lines go to honeypot.log or the honeypot_logs collection respectively.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

EVENTS_FILE = os.environ.get("HONEYPOT_EVENTS_FILE", "events.jsonl")
MONGODB_URI = os.environ.get("MONGODB_URI", "").strip()
MONGODB_DB = os.environ.get("MONGODB_DB", "honeypot")

_mongo_client = None
_mongo_db = None


def using_mongodb() -> bool:
    return bool(MONGODB_URI)


def _get_mongo():
    global _mongo_client, _mongo_db
    if _mongo_db is not None:
        return _mongo_db
    try:
        from pymongo import MongoClient
    except ImportError as e:
        raise RuntimeError("pymongo is required when MONGODB_URI is set. pip install pymongo") from e
    _mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
    _mongo_db = _mongo_client[MONGODB_DB]
    _mongo_db.events.create_index([("ts", -1)])
    _mongo_db.honeypot_logs.create_index([("ts", -1)])
    return _mongo_db


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_now() -> str:
    return _utc_now().isoformat()


def _event_ts_for_mongo(ts: str | datetime | None) -> datetime:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, str):
        try:
            t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            return t
        except ValueError:
            pass
    return _utc_now()


def _normalize_event_doc(doc: dict[str, Any]) -> dict[str, Any]:
    out = dict(doc)
    if "_id" in out:
        out["_id"] = str(out["_id"])
    t = out.get("ts")
    if isinstance(t, datetime):
        out["ts"] = t.isoformat()
    return out


def append_event(event: dict[str, Any]) -> None:
    event = dict(event)
    event.setdefault("ts", _iso_now())
    if using_mongodb():
        db = _get_mongo()
        row = dict(event)
        row["ts"] = _event_ts_for_mongo(row.get("ts"))
        db.events.insert_one(row)
        return
    line = json.dumps(event, ensure_ascii=False) + "\n"
    with open(EVENTS_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def read_events_tail(max_lines: int = 2000) -> list[dict[str, Any]]:
    if max_lines < 1:
        return []
    if using_mongodb():
        db = _get_mongo()
        cur = db.events.find().sort("ts", -1).limit(max_lines)
        rows = [_normalize_event_doc(d) for d in cur]
        rows.reverse()
        return rows
    if not os.path.isfile(EVENTS_FILE):
        return []
    try:
        with open(EVENTS_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return []
    tail = lines[-max_lines:]
    out: list[dict[str, Any]] = []
    for line in tail:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _as_utc_datetime(ts: Any) -> datetime | None:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, str):
        try:
            d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _event_matches(
    e: dict[str, Any],
    event_type: str | None = None,
    risk_level: str | None = None,
    ip: str | None = None,
    country: str | None = None,
    since_minutes: int | None = None,
    attack_id: str | None = None,
) -> bool:
    if event_type and str(e.get("type") or "") != event_type:
        return False
    if risk_level and str(e.get("risk_level") or "") != risk_level:
        return False
    if ip and str(e.get("ip") or "") != ip:
        return False
    if country:
        c = str(e.get("country") or "")
        cc = str(e.get("country_code") or "")
        if country.lower() not in c.lower() and country.lower() != cc.lower():
            return False
    if since_minutes and since_minutes > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=since_minutes)
        dt = _as_utc_datetime(e.get("ts"))
        if not dt or dt < cutoff:
            return False
    if attack_id:
        wanted = attack_id.upper()
        matched = False
        for t in (e.get("attack_techniques") or []):
            tid = str((t or {}).get("id") or "").upper()
            if tid == wanted:
                matched = True
                break
        if not matched:
            return False
    return True


def read_events_filtered(
    max_lines: int = 2000,
    event_type: str | None = None,
    risk_level: str | None = None,
    ip: str | None = None,
    country: str | None = None,
    since_minutes: int | None = None,
    attack_id: str | None = None,
) -> list[dict[str, Any]]:
    if max_lines < 1:
        return []
    if using_mongodb():
        db = _get_mongo()
        query: dict[str, Any] = {}
        if event_type:
            query["type"] = event_type
        if risk_level:
            query["risk_level"] = risk_level
        if ip:
            query["ip"] = ip
        if country:
            query["$or"] = [{"country": {"$regex": country, "$options": "i"}}, {"country_code": country.upper()}]
        if since_minutes and since_minutes > 0:
            query["ts"] = {"$gte": datetime.now(timezone.utc) - timedelta(minutes=since_minutes)}
        if attack_id:
            query["attack_techniques.id"] = attack_id.upper()
        cur = db.events.find(query).sort("ts", -1).limit(max_lines)
        rows = [_normalize_event_doc(d) for d in cur]
        rows.reverse()
        return rows

    events = read_events_tail(max_lines=max_lines * 3)
    out = [
        e
        for e in events
        if _event_matches(
            e,
            event_type=event_type,
            risk_level=risk_level,
            ip=ip,
            country=country,
            since_minutes=since_minutes,
            attack_id=attack_id,
        )
    ]
    if len(out) > max_lines:
        out = out[-max_lines:]
    return out


class MongoLogHandler(logging.Handler):
    """Writes log records to MongoDB collection honeypot_logs."""

    def __init__(self) -> None:
        super().__init__()
        self.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            db = _get_mongo()
            db.honeypot_logs.insert_one(
                {
                    "ts": _utc_now(),
                    "level": record.levelname,
                    "message": self.format(record),
                    "logger": record.name,
                }
            )
        except Exception:
            self.handleError(record)


def setup_application_logging(log_path: str, level: int = logging.INFO) -> str:
    """
    Configure root logger: MongoDB honeypot_logs if MONGODB_URI set, else file at log_path.
    Returns 'mongodb' or 'file' for UI hints.
    """
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    if using_mongodb():
        try:
            _get_mongo()
            root.addHandler(MongoLogHandler())
            return "mongodb"
        except Exception as exc:
            logging.basicConfig(
                filename=log_path,
                level=level,
                format="%(asctime)s - %(message)s",
            )
            logging.getLogger(__name__).warning(
                "MongoDB logging unavailable (%s); fell back to file %s", exc, log_path
            )
            return "file"

    logging.basicConfig(
        filename=log_path,
        level=level,
        format="%(asctime)s - %(message)s",
    )
    return "file"


def get_log_lines_tail(log_path: str, max_lines: int = 500, max_bytes: int = 256_000) -> list[str]:
    """Lines for the View Logs page (newest chunk when using Mongo: last max_lines)."""
    if using_mongodb():
        try:
            db = _get_mongo()
            cur = db.honeypot_logs.find().sort("ts", -1).limit(max_lines)
            lines = []
            for d in cur:
                msg = d.get("message") or ""
                lines.append(msg.rstrip("\n"))
            lines.reverse()
            return lines
        except Exception:
            pass
    return _read_file_log_tail(log_path, max_bytes)


def _read_file_log_tail(log_path: str, max_bytes: int) -> list[str]:
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
