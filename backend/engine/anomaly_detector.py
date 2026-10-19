"""Forensic Anomaly Detection Engine: Hybrid Rule-Based & Statistical IsolationForest."""

from collections import defaultdict
from datetime import datetime, time as dtime, timedelta, timezone
import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from backend.schemas import Case, Event, Anomaly

# Indian Standard Time (UTC+05:30)
IST = timezone(timedelta(hours=5, minutes=30))

# Configurable standard working hours in IST (09:30 - 18:30)
WORK_HOUR_START = dtime(9, 30)
WORK_HOUR_END = dtime(18, 30)


def parse_utc_to_ist(ts_str: str) -> datetime:
    """Parses ISO timestamp string and converts to Indian Standard Time."""
    clean_str = ts_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(clean_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(IST)


def is_off_hours_ist(dt_ist: datetime) -> bool:
    """Checks if datetime falls outside business hours (09:30 - 18:30 IST) or on weekends."""
    # Weekday check: Monday is 0, Sunday is 6
    if dt_ist.weekday() >= 5:  # Saturday or Sunday
        return True
    t = dt_ist.time()
    return t < WORK_HOUR_START or t > WORK_HOUR_END


def extract_ip_address(text: str) -> Optional[str]:
    """Finds IPv4 address in text or returns None."""
    match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
    return match.group(0) if match else None


_INTERNAL_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_external_public_ip(ip_str: str) -> bool:
    """Checks if an IP string is an external IP (outside RFC1918 enterprise LAN and loopback)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Any IP not inside internal corporate ranges is external/public
        return not any(ip in net for net in _INTERNAL_NETS)
    except ValueError:
        return False


def run_rule_based_anomalies(case: Case) -> List[Anomaly]:
    """Applies domain-specific forensic rules for Indian cyber crime investigations."""
    anomalies: List[Anomaly] = []
    events = case.events
    if not events:
        return anomalies

    parsed_events: List[Tuple[Event, datetime]] = []
    for e in events:
        try:
            parsed_events.append((e, parse_utc_to_ist(e.timestamp_utc)))
        except Exception:
            continue

    parsed_events.sort(key=lambda x: x[1])

    # -------------------------------------------------------------------------
    # Rule 1: USB connect followed by file_copy within 15 minutes
    # -------------------------------------------------------------------------
    usb_events = [(e, dt) for e, dt in parsed_events if e.action == "usb_connect"]
    for u_evt, u_dt in usb_events:
        copies = [
            (e, dt) for e, dt in parsed_events
            if e.action == "file_copy" and u_dt <= dt <= (u_dt + timedelta(minutes=15))
        ]
        if copies:
            c_evts = [c[0].event_id for c in copies]
            target_files = ", ".join({c[0].object for c in copies})
            anom_id = f"ANOM-RULE-USB-{u_evt.event_id}"
            anomalies.append(Anomaly(
                anomaly_id=anom_id,
                event_ids=[u_evt.event_id] + c_evts,
                type="usb_file_copy",
                score=0.96,
                explanation=(
                    f"Peripheral '{u_evt.object}' attached at {u_dt.strftime('%H:%M:%S IST')} "
                    f"followed by data copy of '{target_files}' within {int((copies[0][1] - u_dt).total_seconds() / 60)} minutes."
                ),
                detection_method="rule_based",
                suggested_finding=(
                    f"Unauthorized external data transfer: Actor '{copies[0][0].actor}' connected removable USB storage "
                    f"and copied '{target_files}' ({', '.join(c_evts)})."
                ),
            ))

    # -------------------------------------------------------------------------
    # Rule 2: Deletion or Log Clearing after file_copy within 15 minutes
    # -------------------------------------------------------------------------
    copy_events = [(e, dt) for e, dt in parsed_events if e.action == "file_copy"]
    for c_evt, c_dt in copy_events:
        deletions = [
            (e, dt) for e, dt in parsed_events
            if (e.action == "file_delete" or "log" in e.object.lower() or "cleared" in str(e.details).lower())
            and c_dt <= dt <= (c_dt + timedelta(minutes=15))
        ]
        if deletions:
            d_evts = [d[0].event_id for d in deletions]
            del_targets = ", ".join({d[0].object for d in deletions})
            anom_id = f"ANOM-RULE-DEL-{c_evt.event_id}"
            anomalies.append(Anomaly(
                anomaly_id=anom_id,
                event_ids=[c_evt.event_id] + d_evts,
                type="deletion_after_copy",
                score=0.94,
                explanation=(
                    f"Anti-forensics indicator: Data movement of '{c_evt.object}' was followed within "
                    f"{int((deletions[0][1] - c_dt).total_seconds() / 60)} minutes by deletion/clearing of '{del_targets}'."
                ),
                detection_method="rule_based",
                suggested_finding=(
                    f"Anti-forensic log tampering / deletion occurred following file copy: '{del_targets}' deleted ({', '.join(d_evts)})."
                ),
            ))

    # -------------------------------------------------------------------------
    # Rule 3: First-seen external public IP in remote access or network connections
    # -------------------------------------------------------------------------
    seen_external_ips: Set[str] = set()
    for e, dt in parsed_events:
        src_ip = e.details.get("source_ip") or extract_ip_address(e.object)
        if src_ip and is_external_public_ip(src_ip) and src_ip not in seen_external_ips:
            seen_external_ips.add(src_ip)
            anom_id = f"ANOM-RULE-IP-{e.event_id}"
            anomalies.append(Anomaly(
                anomaly_id=anom_id,
                event_ids=[e.event_id],
                type="first_seen_external_ip",
                score=0.91,
                explanation=(
                    f"Untrusted network ingress: First occurrence of external public IP '{src_ip}' "
                    f"in {e.action} log on workstation at {dt.strftime('%H:%M:%S IST')}."
                ),
                detection_method="rule_based",
                suggested_finding=(
                    f"Inbound remote connection established from unknown external public IP {src_ip} ({e.event_id})."
                ),
            ))

    # -------------------------------------------------------------------------
    # Rule 4: Bulk file copy bursts (>= 2 file copy events in 5 minutes)
    # -------------------------------------------------------------------------
    i = 0
    burst_handled: Set[str] = set()
    while i < len(copy_events):
        curr_evt, curr_dt = copy_events[i]
        if curr_evt.event_id in burst_handled:
            i += 1
            continue

        burst = [
            (e, dt) for e, dt in copy_events[i:]
            if dt <= curr_dt + timedelta(minutes=5)
        ]
        if len(burst) >= 2:
            burst_ids = [b[0].event_id for b in burst]
            burst_files = ", ".join({b[0].object for b in burst})
            burst_handled.update(burst_ids)
            anomalies.append(Anomaly(
                anomaly_id=f"ANOM-RULE-BURST-{curr_evt.event_id}",
                event_ids=burst_ids,
                type="bulk_file_copy",
                score=0.88,
                explanation=(
                    f"Rapid exfiltration burst: {len(burst)} files ({burst_files}) copied in under 5 minutes."
                ),
                detection_method="rule_based",
                suggested_finding=(
                    f"Bulk file copy burst detected involving multiple corporate assets: {burst_files} ({', '.join(burst_ids)})."
                ),
            ))
        i += 1

    # -------------------------------------------------------------------------
    # Rule 5: Off-hours activity cluster (IST business hours: 09:30 - 18:30)
    # -------------------------------------------------------------------------
    off_hours_by_actor: Dict[str, List[Tuple[Event, datetime]]] = defaultdict(list)
    for e, dt in parsed_events:
        # Ignore system daemon heartbeats from dominating off-hours noise
        if e.actor in ("system_daemon", "ntp_client"):
            continue
        if is_off_hours_ist(dt):
            off_hours_by_actor[e.actor].append((e, dt))

    for actor, evts in off_hours_by_actor.items():
        # Focus on significant user actions: logins, usb, copy, delete
        critical_off_hours = [
            x for x in evts if x[0].action in ("login", "usb_connect", "file_copy", "file_delete")
        ]
        if len(critical_off_hours) >= 2:
            evt_ids = [x[0].event_id for x in critical_off_hours]
            time_span = f"{critical_off_hours[0][1].strftime('%H:%M')} to {critical_off_hours[-1][1].strftime('%H:%M IST')}"
            anomalies.append(Anomaly(
                anomaly_id=f"ANOM-RULE-OFFHOURS-{actor}-{critical_off_hours[0][0].event_id}",
                event_ids=evt_ids[:6],
                type="off_hours_activity",
                score=0.82,
                explanation=(
                    f"Suspicious off-hours activity: Actor '{actor}' generated {len(critical_off_hours)} critical events "
                    f"between {time_span} (outside standard 09:30-18:30 IST window)."
                ),
                detection_method="rule_based",
                suggested_finding=(
                    f"Late-night activity by actor '{actor}' during off-hours ({time_span}) without documented shift authorization."
                ),
            ))

    # -------------------------------------------------------------------------
    # Rule 6: Repeated failed logins
    # -------------------------------------------------------------------------
    failed_logins = [
        (e, dt) for e, dt in parsed_events
        if e.action == "login" and (
            e.details.get("status") in ("FAILED", "FAILURE")
            or "fail" in str(e.details).lower()
            or e.details.get("event_id") == 4625
        )
    ]
    if len(failed_logins) >= 3:
        anom_id = f"ANOM-RULE-FAIL-LOGIN-{failed_logins[0][0].event_id}"
        anomalies.append(Anomaly(
            anomaly_id=anom_id,
            event_ids=[f[0].event_id for f in failed_logins],
            type="repeated_failed_logins",
            score=0.85,
            explanation=f"Multiple consecutive authentication failures ({len(failed_logins)} attempts) detected.",
            detection_method="rule_based",
            suggested_finding="Brute-force credential attacks or password guessing suspected.",
        ))

    return anomalies


def run_statistical_anomalies(case: Case) -> List[Anomaly]:
    """Extracts per-actor behavioural metrics and runs an IsolationForest to uncover outliers."""
    events = case.events
    if not events:
        return []

    parsed: List[Tuple[Event, datetime]] = []
    for e in events:
        try:
            parsed.append((e, parse_utc_to_ist(e.timestamp_utc)))
        except Exception:
            continue

    if not parsed:
        return []

    # Aggregate metrics per actor
    actor_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "event_count": 0,
        "timestamps": [],
        "distinct_objects": set(),
        "off_hours_count": 0,
        "total_bytes": 0,
        "sensitive_actions": 0,
        "event_ids": [],
    })

    for e, dt in parsed:
        actor = e.actor
        st = actor_stats[actor]
        st["event_count"] += 1
        st["timestamps"].append(dt)
        st["distinct_objects"].add(e.object)
        st["event_ids"].append(e.event_id)
        if is_off_hours_ist(dt):
            st["off_hours_count"] += 1

        # Extract bytes if present
        b = (
            e.details.get("bytes_transferred")
            or e.details.get("bytes_in", 0) + e.details.get("bytes_out", 0)
            or 0
        )
        if isinstance(b, (int, float)):
            st["total_bytes"] += b

        if e.action in ("usb_connect", "file_copy", "file_delete"):
            st["sensitive_actions"] += 1

    actors = list(actor_stats.keys())
    if len(actors) < 3:
        # Statistical outlier model requires multiple actors to establish a baseline
        return []

    # Build feature matrix
    feature_rows = []
    for act in actors:
        st = actor_stats[act]
        t_min = min(st["timestamps"])
        t_max = max(st["timestamps"])
        hours_active = max((t_max - t_min).total_seconds() / 3600.0, 0.5)
        events_per_hour = st["event_count"] / hours_active
        off_hours_ratio = st["off_hours_count"] / max(st["event_count"], 1)

        feature_rows.append([
            events_per_hour,
            len(st["distinct_objects"]),
            off_hours_ratio,
            np.log1p(st["total_bytes"]),
            st["sensitive_actions"],
        ])

    X = np.array(feature_rows)

    # Isolation Forest with deterministic seed
    iso = IsolationForest(
        n_estimators=100,
        contamination=0.25,
        random_state=42,
    )
    preds = iso.fit_predict(X)
    scores = iso.score_samples(X)  # lower = more abnormal

    anomalies: List[Anomaly] = []
    for idx, act in enumerate(actors):
        # Ignore automated network daemons
        if act in ("system_daemon", "network_gateway"):
            continue

        if preds[idx] == -1:  # Outlier
            raw_score = scores[idx]
            # Normalize to [0.70, 0.98]
            norm_score = round(float(np.clip(0.70 + (np.abs(raw_score) * 0.4), 0.70, 0.98)), 2)
            st = actor_stats[act]
            key_events = [
                e.event_id for e, dt in parsed
                if e.actor == act and (is_off_hours_ist(dt) or e.action in ("usb_connect", "file_copy", "file_delete"))
            ]
            if not key_events:
                key_events = st["event_ids"][:5]

            anomalies.append(Anomaly(
                anomaly_id=f"ANOM-STAT-ISO-{act}",
                event_ids=key_events[:8],
                type="statistical_actor_outlier",
                score=norm_score,
                explanation=(
                    f"Statistical Behavioural Outlier: Actor '{act}' deviated significantly from peer baseline "
                    f"in off-hours activity ({st['off_hours_count']}/{st['event_count']} events), "
                    f"sensitive operations ({st['sensitive_actions']}), and data transfer volume ({st['total_bytes']:,} bytes)."
                ),
                detection_method="statistical_isolation_forest",
                suggested_finding=(
                    f"Anomalous telemetry profile for actor '{act}' indicating high-probability insider threat deviation."
                ),
            ))

    return anomalies


def run_anomaly_detection(case: Case) -> List[Anomaly]:
    """Combines rule-based and statistical anomaly detection and returns ranked anomalies."""
    rule_anomalies = run_rule_based_anomalies(case)
    stat_anomalies = run_statistical_anomalies(case)

    combined = rule_anomalies + stat_anomalies
    # Sort primarily by score descending
    combined.sort(key=lambda a: a.score, reverse=True)
    return combined
