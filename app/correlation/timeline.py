"""Unified timeline with optional per-evidence clock-skew adjustment."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        # Accept "2024-01-15T10:30:00Z" or with offset
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return None


def build_timeline(
    events: list[dict],
    evidence_map: dict[str, dict],
    *,
    bucket_seconds: int = 60,
    skew_map: dict[str, float] | None = None,
) -> dict[str, Any]:
    """
    Build a unified timeline.

    skew_map: evidence_id -> seconds to ADD to that source's normalized_time
              (positive = source clock was behind real time).

    Returns:
      buckets: [{start, end, count, events: [...]}]
      sources: [{evidence_id, filename, event_count, min_time, max_time, skew_applied}]
      clock_skew_demo: sample pairs that look concurrent after skew adjustment
    """
    skew_map = skew_map or {}
    enriched = []
    sources: dict[str, dict] = {}

    for e in events:
        eid = e.get("evidence_id") or ""
        nt = _parse_ts(e.get("normalized_time"))
        skew = float(skew_map.get(eid, 0) or 0)
        adjusted = nt + timedelta(seconds=skew) if nt is not None else None
        row = {
            **e,
            "adjusted_time": adjusted.isoformat().replace("+00:00", "Z") if adjusted else None,
            "skew_seconds": skew,
            "filename": (evidence_map.get(eid) or {}).get("filename") or e.get("source_ref") or eid,
        }
        enriched.append(row)

        src = sources.setdefault(eid, {
            "evidence_id": eid,
            "filename": row["filename"],
            "event_count": 0,
            "min_time": None,
            "max_time": None,
            "skew_applied": skew,
            "time_qualities": set(),
        })
        src["event_count"] += 1
        if e.get("time_quality"):
            src["time_qualities"].add(e["time_quality"])
        if adjusted:
            iso = adjusted.isoformat().replace("+00:00", "Z")
            if src["min_time"] is None or iso < src["min_time"]:
                src["min_time"] = iso
            if src["max_time"] is None or iso > src["max_time"]:
                src["max_time"] = iso

    # Sort by adjusted time (nulls last)
    enriched.sort(key=lambda r: (r["adjusted_time"] is None, r["adjusted_time"] or "", r.get("event_id") or ""))

    # Bucket
    buckets: list[dict] = []
    if bucket_seconds < 1:
        bucket_seconds = 1
    current_start = None
    current_events: list = []

    def flush():
        nonlocal current_start, current_events
        if current_start is None:
            return
        end = current_start + timedelta(seconds=bucket_seconds)
        buckets.append({
            "start": current_start.isoformat().replace("+00:00", "Z"),
            "end": end.isoformat().replace("+00:00", "Z"),
            "count": len(current_events),
            "events": current_events,
        })
        current_events = []

    for row in enriched:
        t = _parse_ts(row["adjusted_time"])
        if t is None:
            # orphan bucket for untimed events — append at end later
            continue
        # floor to bucket
        epoch = int(t.replace(tzinfo=timezone.utc).timestamp())
        floored = datetime.fromtimestamp(epoch - (epoch % bucket_seconds), tz=timezone.utc)
        if current_start is None or floored != current_start:
            flush()
            current_start = floored
        # slim event for payload size
        current_events.append({
            "event_id": row.get("event_id"),
            "event_type": row.get("event_type"),
            "summary": row.get("summary"),
            "normalized_time": row.get("normalized_time"),
            "adjusted_time": row.get("adjusted_time"),
            "original_time": row.get("original_time"),
            "time_quality": row.get("time_quality"),
            "evidence_id": row.get("evidence_id"),
            "filename": row.get("filename"),
            "source_ref": row.get("source_ref"),
            "entities": row.get("entities") or [],
        })
    flush()

    untimed = [
        {
            "event_id": r.get("event_id"),
            "event_type": r.get("event_type"),
            "summary": r.get("summary"),
            "evidence_id": r.get("evidence_id"),
            "filename": r.get("filename"),
            "time_quality": r.get("time_quality"),
        }
        for r in enriched if r["adjusted_time"] is None
    ]

    # Clock-skew demo: find pairs of events from different sources within 5s after adjustment
    # that were > 30s apart before adjustment (illustrative)
    by_time = [r for r in enriched if r["adjusted_time"]]
    demo_pairs = []
    for i, a in enumerate(by_time):
        if len(demo_pairs) >= 8:
            break
        ta = _parse_ts(a["adjusted_time"])
        for b in by_time[i + 1: i + 40]:
            if a["evidence_id"] == b["evidence_id"]:
                continue
            tb = _parse_ts(b["adjusted_time"])
            if not ta or not tb:
                continue
            adj_delta = abs((tb - ta).total_seconds())
            if adj_delta > 5:
                continue
            oa = _parse_ts(a.get("normalized_time"))
            ob = _parse_ts(b.get("normalized_time"))
            raw_delta = abs((ob - oa).total_seconds()) if oa and ob else None
            if raw_delta is not None and raw_delta > 30:
                demo_pairs.append({
                    "a": {"event_id": a["event_id"], "summary": a.get("summary"), "filename": a["filename"],
                          "normalized_time": a.get("normalized_time"), "adjusted_time": a["adjusted_time"]},
                    "b": {"event_id": b["event_id"], "summary": b.get("summary"), "filename": b["filename"],
                          "normalized_time": b.get("normalized_time"), "adjusted_time": b["adjusted_time"]},
                    "raw_delta_seconds": round(raw_delta, 1),
                    "adjusted_delta_seconds": round(adj_delta, 1),
                })
                break

    source_list = []
    for s in sources.values():
        s["time_qualities"] = sorted(s["time_qualities"])
        source_list.append(s)
    source_list.sort(key=lambda x: x["filename"] or x["evidence_id"])

    return {
        "bucket_seconds": bucket_seconds,
        "total_events": len(events),
        "buckets": buckets,
        "untimed": untimed,
        "sources": source_list,
        "clock_skew_demo": demo_pairs,
        "skew_map": skew_map,
    }
