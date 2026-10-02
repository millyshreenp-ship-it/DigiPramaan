"""Filesystem metadata: Sleuth Kit 'body file' (mactime) format.

    MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

Produced by `fls -m` / `tsk_gettimes` / `find -printf`-style tooling. Epoch seconds are UTC, so the times are
exact. Each file yields up to four MACB events (Modified, Accessed, Changed, Born) -- the classic
forensic timeline primitive for answering "when was this file touched?"."""
import re
from datetime import datetime, timezone
from pathlib import Path
from .base import BaseParser, ParseContext, ParsedEvent, ParseResult, register, iter_lines, to_utc_iso

LABELS = (("atime", "fs_accessed", "A"), ("mtime", "fs_modified", "M"),
          ("ctime", "fs_changed", "C"), ("crtime", "fs_created", "B"))

def _ok(parts):
    return len(parts) == 11 and re.fullmatch(r"-?\d+", parts[6] or "") and all(re.fullmatch(r"-?\d*", p) for p in parts[7:11])

@register
class BodyfileParser(BaseParser):
    name = "tsk_bodyfile"
    version = "0.1.0"
    artifact_type = "filesystem.mactime"
    description = "Sleuth Kit body file: MACB timestamps for every file on a filesystem"

    def can_parse(self, path, ctx, head):
        lines = [l for l in head.splitlines() if l.strip()][:20]
        if not lines:
            return 0.0
        return sum(1 for l in lines if _ok(l.split("|"))) / len(lines)

    def parse(self, path: Path, ctx: ParseContext) -> ParseResult:
        res = ParseResult(events=[])
        for n, line in iter_lines(path):
            if not line.strip() or line.startswith("#"):
                continue
            res.lines_total += 1
            parts = line.split("|")
            if not _ok(parts):
                res.lines_unparsed += 1
                continue
            name, inode, size = parts[1], parts[2], int(parts[6])
            for idx, (label, etype, flag) in zip((7, 8, 9, 10), LABELS):
                raw_t = parts[idx]
                if raw_t in ("", "0", "-1"):
                    continue
                dt = datetime.fromtimestamp(int(raw_t), tz=timezone.utc)
                res.events.append(ParsedEvent(
                    event_type=etype, summary=f"[{flag}] {name}", original_time=raw_t,
                    normalized_time=to_utc_iso(dt), timezone="UTC", uncertainty_seconds=0.0,
                    time_quality="exact", source_ref=f"line {n}", raw=line[:1000],
                    fields={"path": name, "inode": inode, "size": size, "mode": parts[3],
                            "uid": parts[4], "gid": parts[5], "macb": flag, "md5": parts[0] if parts[0] != "0" else None},
                    entities=[{"type": "file", "value": name}]))
                if len(res.events) >= ctx.max_events:
                    res.notes.append(f"Stopped at max_events={ctx.max_events}.")
                    return res
        res.notes.append("Epoch times are UTC. Filesystem timestamps reflect the source device's clock at write time; "
                         "clock-skew reconciliation is applied downstream in the timeline engine.")
        return res
