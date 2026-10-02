"""Pluggable parser framework.

To add a parser (browser history, registry, EXIF, PCAP...):
    1. subclass BaseParser, set name/version/artifact_type,
    2. implement can_parse() -> confidence 0..1 and parse() -> ParseResult,
    3. decorate with @register.
Nothing else needs to change; the API and UI discover parsers from the registry.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

@dataclass
class ParseContext:
    filename: str
    tz: str = "Asia/Kolkata"              # timezone to assume for sources that carry none (e.g. syslog)
    assume_year: int | None = None        # syslog omits the year
    max_events: int = 200_000

@dataclass
class ParsedEvent:
    event_type: str
    summary: str
    original_time: str | None             # verbatim from source
    normalized_time: str | None           # ISO-8601 UTC
    timezone: str | None
    uncertainty_seconds: float | None
    time_quality: str                     # exact | assumed_tz | assumed_year_tz | missing
    source_ref: str                       # "line 42"
    raw: str
    fields: dict = field(default_factory=dict)
    entities: list[dict] = field(default_factory=list)   # [{"type":"ip","value":"1.2.3.4"}, ...]

@dataclass
class ParseResult:
    events: list[ParsedEvent]
    notes: list[str] = field(default_factory=list)       # assumptions + skipped-line stats, shown to investigator
    lines_total: int = 0
    lines_unparsed: int = 0

class BaseParser:
    name = "base"
    version = "0.0.0"
    artifact_type = "generic"
    description = ""
    def can_parse(self, path: Path, ctx: ParseContext, head: str) -> float:
        raise NotImplementedError
    def parse(self, path: Path, ctx: ParseContext) -> ParseResult:
        raise NotImplementedError

_REGISTRY: dict[str, BaseParser] = {}

def register(cls):
    inst = cls()
    _REGISTRY[inst.name] = inst
    return cls

def all_parsers() -> list[BaseParser]:
    return list(_REGISTRY.values())

def get_parser(name: str) -> BaseParser | None:
    return _REGISTRY.get(name)

def read_head(path: Path, n: int = 8192) -> str:
    with open(path, "rb") as f:
        return f.read(n).decode("utf-8", errors="replace")

def detect(path: Path, ctx: ParseContext) -> tuple[BaseParser | None, float]:
    head = read_head(path)
    best, score = None, 0.0
    for p in _REGISTRY.values():
        s = p.can_parse(path, ctx, head)
        if s > score:
            best, score = p, s
    return (best, score) if score >= 0.5 else (None, score)

def to_utc_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def localize(naive: datetime, tz_name: str) -> datetime:
    return naive.replace(tzinfo=ZoneInfo(tz_name))

def iter_lines(path: Path):
    """Yield (line_number, text). Reads bytes and decodes leniently so bad bytes never abort a parse."""
    with open(path, "rb") as f:
        for i, b in enumerate(f, 1):
            yield i, b.decode("utf-8", errors="replace").rstrip("\r\n")
