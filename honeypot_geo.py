"""
Optional IP → country resolution using ip-api.com (free tier, HTTP, rate limited).
Results are cached in honeypot state to limit external calls. Private IPs are labeled locally.
"""
from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

GEO_CACHE_HOURS = int(os.environ.get("HONEYPOT_GEO_CACHE_HOURS", "24"))
GEO_DISABLED = os.environ.get("HONEYPOT_GEO_DISABLED", "").lower() in ("1", "true", "yes")


def _is_reserved_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0].strip())
        return bool(
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        return True


def _geo_ttl_expired(cached_at: str | None) -> bool:
    if not cached_at:
        return True
    try:
        t = datetime.fromisoformat(cached_at.replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) > t + timedelta(hours=GEO_CACHE_HOURS)
    except ValueError:
        return True


def _fetch_ip_api(ip: str) -> dict[str, Any]:
    """
    ip-api.com free endpoint (non-SSL). Acceptable for lab / prototyping only.
    See https://ip-api.com/docs/legal — respect rate limits (45 req/min per IP).
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode"
    req = urllib.request.Request(url, headers={"User-Agent": "HoneypotLab/1.0"})
    with urllib.request.urlopen(req, timeout=4) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def record_geo_if_needed(state: dict[str, Any], ip: str) -> None:
    """
    Mutate state: state['ip_geo'][ip] = { country, countryCode, cached_at, source }.
    Skips lookup for reserved IPs and when GEO_DISABLED=1.
    """
    if GEO_DISABLED or not ip or ip == "unknown":
        return

    bucket = state.setdefault("ip_geo", {})
    existing = bucket.get(ip)
    if existing and not _geo_ttl_expired(existing.get("cached_at")):
        return

    if _is_reserved_ip(ip):
        bucket[ip] = {
            "country": "Private / local network",
            "countryCode": "LAN",
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "source": "local",
        }
        return

    try:
        data = _fetch_ip_api(ip)
        if data.get("status") != "success":
            bucket[ip] = {
                "country": data.get("message") or "Lookup failed",
                "countryCode": "??",
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "source": "ip-api",
            }
            return
        bucket[ip] = {
            "country": data.get("country") or "Unknown",
            "countryCode": data.get("countryCode") or "??",
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "source": "ip-api",
        }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        bucket[ip] = {
            "country": "Unavailable (offline / rate limit)",
            "countryCode": "??",
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "source": "error",
        }


def geo_snapshot_for_ip(state: dict[str, Any], ip: str) -> dict[str, Any]:
    """Safe read for attaching to events or templates."""
    return dict((state.get("ip_geo") or {}).get(ip) or {})


def refresh_geo_and_get_snapshot(load_state_fn, save_state_fn, ip: str) -> dict[str, Any]:
    """Load state, resolve geo into cache, save, return snapshot for this IP."""
    state = load_state_fn()
    record_geo_if_needed(state, ip)
    save_state_fn(state)
    return geo_snapshot_for_ip(state, ip)
