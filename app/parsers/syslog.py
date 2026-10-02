"""Linux syslog / auth.log parser (BSD syslog and RFC 3339 variants).

Highlights forensically useful events: SSH logins/failures, sudo, USB device attach, session open/close.
Classic syslog timestamps carry NO year and NO timezone, so those are assumptions: they are recorded in
time_quality + parse notes, never silently hidden."""
import re
from datetime import datetime
from pathlib import Path
from .base import (BaseParser, ParseContext, ParsedEvent, ParseResult, register,
                   iter_lines, localize, to_utc_iso)

BSD = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\s(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$")
ISO = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s(?P<host>\S+)\s(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$")

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
RULES = [
    ("ssh_login_success", re.compile(rf"Accepted (?P<method>\w+) for (?P<user>\S+) from {IP} port (?P<port>\d+)")),
    ("ssh_login_failed",  re.compile(rf"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from {IP} port (?P<port>\d+)")),
    ("ssh_invalid_user",  re.compile(rf"Invalid user (?P<user>\S+) from {IP}")),
    ("sudo_command",      re.compile(r"(?P<user>\S+)\s*:.*COMMAND=(?P<command>.+)$")),
    ("session_opened",    re.compile(r"session opened for user (?P<user>\S+)")),
    ("session_closed",    re.compile(r"session closed for user (?P<user>\S+)")),
    ("usb_attached",      re.compile(r"usb [\d.-]+: (?:New USB device found|Product: (?P<product>.+)|Manufacturer: (?P<mfr>.+)|SerialNumber: (?P<serial>.+))")),
    ("usb_storage",       re.compile(r"(?:usb-storage|sd \d+:\d+:\d+:\d+: \[(?P<dev>sd\w+)\])")),
    ("user_added",        re.compile(r"new user: name=(?P<user>[^,]+)")),
    ("cron_job",          re.compile(r"\((?P<user>\S+)\) CMD \((?P<command>.+)\)")),
]

@register
class SyslogParser(BaseParser):
    name = "syslog"
    version = "0.1.0"
    artifact_type = "log.syslog"
    description = "Linux syslog / auth.log (SSH, sudo, USB, cron, sessions)"

    def can_parse(self, path, ctx, head):
        lines = [l for l in head.splitlines() if l.strip()][:20]
        if not lines:
            return 0.0
        hits = sum(1 for l in lines if BSD.match(l) or ISO.match(l))
        return hits / len(lines) * (1.0 if "access" not in ctx.filename.lower() else 0.6)

    def parse(self, path: Path, ctx: ParseContext) -> ParseResult:
        year = ctx.assume_year or datetime.now().year
        res = ParseResult(events=[])
        bsd_seen = iso_naive_seen = False
        for n, line in iter_lines(path):
            if not line.strip():
                continue
            res.lines_total += 1
            m = BSD.match(line)
            iso = None
            if m:
                bsd_seen = True
            else:
                iso = ISO.match(line)
                m = iso
            if not m:
                res.lines_unparsed += 1
                continue
            ts = m.group("ts")
            try:
                if iso:
                    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        iso_naive_seen = True
                        dt, quality, tzname = localize(dt, ctx.tz), "assumed_tz", ctx.tz
                    else:
                        quality, tzname = "exact", str(dt.tzinfo)
                    unc = 0.0
                else:
                    naive = datetime.strptime(f"{year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S")
                    dt, quality, tzname, unc = localize(naive, ctx.tz), "assumed_year_tz", ctx.tz, 0.0
                norm = to_utc_iso(dt)
            except ValueError:
                res.lines_unparsed += 1
                continue

            msg, proc = m.group("msg"), m.group("proc")
            etype, fields, ents = "syslog_message", {}, []
            for rule_type, rx in RULES:
                hit = rx.search(msg)
                if hit and (rule_type != "usb_attached" or "usb" in msg) and (rule_type != "sudo_command" or proc == "sudo"):
                    etype = rule_type
                    fields = {k: v for k, v in hit.groupdict().items() if v}
                    break
            fields.update(host=m.group("host"), process=proc)
            if m.group("pid"):
                fields["pid"] = m.group("pid")
            if "ip" in fields:
                ents.append({"type": "ip", "value": fields["ip"]})
            if "user" in fields:
                ents.append({"type": "account", "value": fields["user"]})
            ents.append({"type": "host", "value": m.group("host")})
            res.events.append(ParsedEvent(
                event_type=etype, summary=f"{proc}: {msg}"[:240], original_time=ts, normalized_time=norm,
                timezone=tzname, uncertainty_seconds=unc, time_quality=quality,
                source_ref=f"line {n}", raw=line[:1000], fields=fields, entities=ents))
            if len(res.events) >= ctx.max_events:
                res.notes.append(f"Stopped at max_events={ctx.max_events}.")
                break
        if bsd_seen:
            res.notes.append(f"Source timestamps have no year or timezone. Assumed year {year} and timezone {ctx.tz}. "
                             "Original text preserved in original_time; confirm both with the device owner/acquisition notes.")
        if iso_naive_seen:
            res.notes.append(f"Some ISO timestamps had no offset; assumed {ctx.tz}.")
        return res
