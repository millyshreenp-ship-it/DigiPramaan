"""Investigator query interface — structured filters over events."""
from __future__ import annotations

import json
from typing import Any


def run_investigator_query(
    conn,
    case_id: str,
    *,
    q: str = "",
    event_types: list[str] | None = None,
    entity: str = "",
    entity_type: str = "",
    evidence_id: str = "",
    time_from: str = "",
    time_to: str = "",
    time_quality: str = "",
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    """
    Flexible investigator search. All filters are optional and AND-combined.
    Returns events plus facet counts for progressive refinement.
    """
    sql = "FROM events WHERE case_id=?"
    args: list[Any] = [case_id]

    if q:
        sql += " AND (summary LIKE ? OR raw LIKE ? OR source_ref LIKE ?)"
        like = f"%{q}%"
        args += [like, like, like]
    if event_types:
        placeholders = ",".join("?" * len(event_types))
        sql += f" AND event_type IN ({placeholders})"
        args += list(event_types)
    if evidence_id:
        sql += " AND evidence_id=?"
        args.append(evidence_id)
    if time_from:
        sql += " AND normalized_time >= ?"
        args.append(time_from)
    if time_to:
        sql += " AND normalized_time <= ?"
        args.append(time_to)
    if time_quality:
        sql += " AND time_quality=?"
        args.append(time_quality)
    if entity:
        # entities stored as JSON array; SQLite LIKE is enough for prototype
        sql += " AND entities LIKE ?"
        args.append(f"%{entity}%")
    if entity_type:
        sql += " AND entities LIKE ?"
        args.append(f'%"type": "{entity_type}"%')

    total = conn.execute("SELECT COUNT(*) " + sql, args).fetchone()[0]
    rows = conn.execute(
        "SELECT * " + sql + " ORDER BY normalized_time, event_id LIMIT ? OFFSET ?",
        args + [max(1, min(limit, 5000)), max(0, offset)],
    ).fetchall()

    # Facets (unfiltered by the narrow criteria so the UI can show available values)
    facets = {
        "event_types": [
            {"value": r[0], "count": r[1]}
            for r in conn.execute(
                "SELECT event_type, COUNT(*) c FROM events WHERE case_id=? GROUP BY event_type ORDER BY c DESC",
                (case_id,),
            )
        ],
        "time_qualities": [
            {"value": r[0], "count": r[1]}
            for r in conn.execute(
                "SELECT COALESCE(time_quality,'(none)'), COUNT(*) c FROM events WHERE case_id=? GROUP BY 1 ORDER BY c DESC",
                (case_id,),
            )
        ],
        "evidence": [
            {"value": r[0], "label": r[1], "count": r[2]}
            for r in conn.execute(
                """SELECT e.evidence_id, COALESCE(ev.filename, e.evidence_id), COUNT(*)
                   FROM events e LEFT JOIN evidence ev ON ev.evidence_id = e.evidence_id
                   WHERE e.case_id=? GROUP BY e.evidence_id ORDER BY 3 DESC""",
                (case_id,),
            )
        ],
    }

    # Collect entity values for the entity filter UI
    entity_samples: dict[str, int] = {}
    for r in conn.execute(
        "SELECT entities FROM events WHERE case_id=? AND entities IS NOT NULL AND entities != '[]' LIMIT 2000",
        (case_id,),
    ):
        try:
            ents = json.loads(r[0] or "[]")
        except Exception:
            continue
        for ent in ents:
            if isinstance(ent, dict):
                val = str(ent.get("value") or ent.get("name") or "")
                et = str(ent.get("type") or "entity")
            else:
                val, et = str(ent), "entity"
            if val:
                key = f"{et}:{val}"
                entity_samples[key] = entity_samples.get(key, 0) + 1
    top_entities = sorted(entity_samples.items(), key=lambda x: -x[1])[:40]
    facets["entities"] = [
        {"value": k.split(":", 1)[1], "entity_type": k.split(":", 1)[0], "count": c}
        for k, c in top_entities
    ]

    out = []
    for r in rows:
        d = dict(r)
        d["fields"] = json.loads(d.get("fields") or "{}")
        d["entities"] = json.loads(d.get("entities") or "[]")
        out.append(d)

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "events": out,
        "facets": facets,
        "filters_applied": {
            "q": q or None,
            "event_types": event_types or None,
            "entity": entity or None,
            "entity_type": entity_type or None,
            "evidence_id": evidence_id or None,
            "time_from": time_from or None,
            "time_to": time_to or None,
            "time_quality": time_quality or None,
        },
    }
