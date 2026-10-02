"""Basic evidence graph: nodes (evidence, events, entities) + edges (contains, mentions, sequential, co-entity)."""
from __future__ import annotations

from collections import defaultdict
from typing import Any


def build_graph(
    events: list[dict],
    evidence_list: list[dict],
    *,
    max_events: int = 500,
    sequential_window_seconds: float = 120.0,
) -> dict[str, Any]:
    """
    Produce a simple node/edge graph suitable for a force-directed or hierarchical view.

    Node types: evidence | event | entity
    Edge types: contains (evidence→event) | mentions (event→entity) | sequential (event→event)
                | same_entity (event↔event via shared entity)
    """
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    edge_keys: set[str] = set()

    def add_node(nid: str, ntype: str, label: str, **extra):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "label": label, **extra}
        else:
            nodes[nid].update({k: v for k, v in extra.items() if v is not None})

    def add_edge(src: str, dst: str, etype: str, **extra):
        key = f"{src}|{dst}|{etype}"
        if key in edge_keys:
            return
        edge_keys.add(key)
        edges.append({"source": src, "target": dst, "type": etype, **extra})

    # Evidence nodes
    for ev in evidence_list:
        eid = ev["evidence_id"]
        add_node(
            eid,
            "evidence",
            ev.get("filename") or eid,
            integrity_status=ev.get("integrity_status"),
            source_type=ev.get("source_type"),
            size=ev.get("size"),
        )

    # Limit events for prototype payload size
    sorted_events = sorted(
        events,
        key=lambda e: (e.get("normalized_time") or "", e.get("event_id") or ""),
    )
    if len(sorted_events) > max_events:
        sorted_events = sorted_events[:max_events]

    # Event + entity nodes, contains/mentions edges
    entity_to_events: dict[str, list[str]] = defaultdict(list)

    for e in sorted_events:
        evid = e.get("event_id") or ""
        parent = e.get("evidence_id") or ""
        label = (e.get("summary") or e.get("event_type") or evid)[:80]
        add_node(
            evid,
            "event",
            label,
            event_type=e.get("event_type"),
            normalized_time=e.get("normalized_time"),
            time_quality=e.get("time_quality"),
            evidence_id=parent,
        )
        if parent:
            add_edge(parent, evid, "contains")

        entities = e.get("entities") or []
        if isinstance(entities, str):
            try:
                import json
                entities = json.loads(entities)
            except Exception:
                entities = []
        for ent in entities:
            if isinstance(ent, dict):
                etype = ent.get("type") or "entity"
                value = str(ent.get("value") or ent.get("name") or "")
            else:
                etype, value = "entity", str(ent)
            if not value:
                continue
            nid = f"ENT:{etype}:{value}"
            add_node(nid, "entity", value, entity_type=etype)
            add_edge(evid, nid, "mentions")
            entity_to_events[nid].append(evid)

    # Same-entity links between events (cap per entity)
    for ent_id, ev_ids in entity_to_events.items():
        uniq = list(dict.fromkeys(ev_ids))
        for i, a in enumerate(uniq[:12]):
            for b in uniq[i + 1: 12]:
                add_edge(a, b, "same_entity", via=ent_id)

    # Sequential edges within the same evidence source (time-ordered, within window)
    by_evidence: dict[str, list] = defaultdict(list)
    for e in sorted_events:
        if e.get("normalized_time") and e.get("event_id"):
            by_evidence[e.get("evidence_id") or ""].append(e)

    def parse_ts(s):
        if not s:
            return None
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            from datetime import datetime
            return datetime.fromisoformat(s)
        except Exception:
            return None

    for parent, elist in by_evidence.items():
        elist.sort(key=lambda x: x.get("normalized_time") or "")
        for i in range(len(elist) - 1):
            a, b = elist[i], elist[i + 1]
            ta, tb = parse_ts(a.get("normalized_time")), parse_ts(b.get("normalized_time"))
            if ta and tb:
                delta = (tb - ta).total_seconds()
                if 0 <= delta <= sequential_window_seconds:
                    add_edge(
                        a["event_id"],
                        b["event_id"],
                        "sequential",
                        delta_seconds=round(delta, 2),
                    )

    # Summary stats
    type_counts = defaultdict(int)
    for n in nodes.values():
        type_counts[n["type"]] += 1
    edge_type_counts = defaultdict(int)
    for e in edges:
        edge_type_counts[e["type"]] += 1

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "stats": {
            "node_counts": dict(type_counts),
            "edge_counts": dict(edge_type_counts),
            "events_included": len(sorted_events),
            "events_total": len(events),
            "truncated": len(sorted_events) < len(events),
        },
    }
