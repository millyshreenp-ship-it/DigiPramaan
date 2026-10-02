"""Apache / Nginx 'combined' access log parser. Timestamps include a UTC offset, so they are exact."""
import re
from datetime import datetime
from pathlib import Path
from .base import BaseParser, ParseContext, ParsedEvent, ParseResult, register, iter_lines, to_utc_iso

RX = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)(?: (?P<proto>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')

@register
class AccessLogParser(BaseParser):
    name = "web_access_log"
    version = "0.1.0"
    artifact_type = "log.web_access"
    description = "Apache/Nginx combined access log (requests, status codes, client IPs)"

    def can_parse(self, path, ctx, head):
        lines = [l for l in head.splitlines() if l.strip()][:20]
        if not lines:
            return 0.0
        return sum(1 for l in lines if RX.match(l)) / len(lines)

    def parse(self, path: Path, ctx: ParseContext) -> ParseResult:
        res = ParseResult(events=[])
        for n, line in iter_lines(path):
            if not line.strip():
                continue
            res.lines_total += 1
            m = RX.match(line)
            if not m:
                res.lines_unparsed += 1
                continue
            try:
                dt = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                res.lines_unparsed += 1
                continue
            status = int(m.group("status"))
            ents = [{"type": "ip", "value": m.group("ip")}, {"type": "url", "value": m.group("path")}]
            if m.group("user") != "-":
                ents.append({"type": "account", "value": m.group("user")})
            res.events.append(ParsedEvent(
                event_type="http_request",
                summary=f'{m.group("ip")} {m.group("method")} {m.group("path")} -> {status}'[:240],
                original_time=m.group("ts"), normalized_time=to_utc_iso(dt), timezone=str(dt.tzinfo),
                uncertainty_seconds=0.0, time_quality="exact", source_ref=f"line {n}", raw=line[:1000],
                fields={"client_ip": m.group("ip"), "method": m.group("method"), "path": m.group("path"),
                        "status": status, "bytes": None if m.group("size") == "-" else int(m.group("size")),
                        "user_agent": m.group("ua"), "referrer": m.group("ref")},
                entities=ents))
            if len(res.events) >= ctx.max_events:
                res.notes.append(f"Stopped at max_events={ctx.max_events}.")
                break
        return res
