# Evidence Intake & Integrity

The Acquire -> Preserve -> Verify -> Parse module of the AI-Powered Indigenous Digital Forensics Investigation Framework.
A self-contained web application: sign-in, role-based access, evidence vault, hash verification, pluggable parsers, hash-chained custody log.

## Run
```bash
./run.sh                      # http://127.0.0.1:8000, first visit creates the administrator account
docker compose up --build     # or: containerised, data in a named volume
python3 -m pytest tests -q    # 21 tests
```
`samples_for_testing/` holds three small logs (one fictional case) for trying the parsers. They are not loaded automatically.

## Configuration (environment variables)
| Variable | Default | Meaning |
|---|---|---|
| `FORENSIC_DATA_DIR` | `./data` | Database and evidence vault location. Back this up. |
| `FORENSIC_MAX_UPLOAD_BYTES` | 10 GiB | Per-file upload limit. |
| `FORENSIC_SESSION_TTL` | 28800 | Session lifetime in seconds. |
| `FORENSIC_COOKIE_SECURE` | 0 | Set to 1 when served over HTTPS. |

## What it does
- **Accounts and roles.** Passwords are scrypt-hashed (10+ characters), sessions are HttpOnly SameSite=Strict cookies, state-changing calls require a CSRF header, login locks after 5 failures per 15 min.
  admin: everything + users. investigator: open cases, add/parse evidence. examiner: add/parse evidence. supervisor: open cases. reviewer, auditor: read-only. Everyone can verify and read the custody log.
- **Acquire.** Any file type, streamed in 1 MiB chunks (no RAM limit on image size), SHA-256 and SHA-512 in one pass, optional acquirer-declared hash checked on receipt, duplicate detection per case, custodian/method/notes recorded. The vault copy is stored read-only under a generated name.
- **Verify.** Re-hash on demand or for the whole case; changed characters are highlighted; missing files are detected. Every result goes into the custody log. Printable per-item integrity record and a self-hashing case manifest (JSON).
- **Parse.** Verify-before-parse gate. Plugins: `syslog` (SSH, sudo, USB, cron), `web_access_log`, `tsk_bodyfile` (MACB). Original timestamps are preserved verbatim; assumed year/timezone are labelled in `time_quality` and in notes. Re-parsing replaces derived events and keeps the old artifact record as superseded. Every artifact records parser version, derived hash and the master hash it came from.
- **Search and export.** Event search, type filter, paging, CSV export with spreadsheet-formula neutralisation.
- **Chain of custody.** Every login, acquisition, verification, parse and export is a hash-linked entry attributed to a named user. Editing a past row breaks the chain and is reported.

## API for other modules
- `GET /api/cases/{id}/events` returns `event_id, event_type, summary, original_time, normalized_time (UTC), timezone, uncertainty_seconds, time_quality, source_ref, raw, fields, entities[]`.
- `GET /api/cases/{id}/evidence`, `GET /api/cases/{id}/custody`, `GET /api/cases/{id}/manifest`.
- In Python: `custody.append(conn, actor=, action=, case_id=, evidence_id=, detail=)` and `auth.require("role", ...)`.
- Add a parser: subclass `BaseParser` in `app/parsers/`, implement `can_parse` and `parse`, decorate with `@register`, import it in `app/parsers/__init__.py`.


## Timeline & Correlation (prototype)

Three investigator-facing views built on the normalized events API:

1. **Unified timeline** (`GET /api/cases/{id}/timeline`)  
   Time-bucketed view of all parsed events across evidence sources. Optional per-source **clock-skew** offsets (`?skew=EVID-…:120,EVID-…:-30`) shift timestamps for demo/reconciliation; the UI surfaces pairs that only align after correction.

2. **Evidence graph** (`GET /api/cases/{id}/graph`)  
   Nodes: evidence, events, entities. Edges: `contains`, `mentions`, `sequential` (same source, within a time window), `same_entity`. Force-directed layout runs entirely in the browser (no CDN).

3. **Investigator query** (`GET /api/cases/{id}/query`)  
   Structured search with free text, entity/type, time range, time quality, evidence source, and multi-select event types. Facets support progressive refinement.

UI tabs: **Timeline**, **Evidence graph**, **Investigator query** (alongside the existing Parsed events list).

## Trust Layer (Case Management & Audit)

A unified RBAC, case lifecycle, immutable audit trail, and synthetic "Digital Twin" sandbox.

1. **Case Management & RBAC**  
   Cases progress through a strict lifecycle (`Open` -> `Under Analysis` -> `Pending Legal Review` -> `Closed`). Legal hold locks metadata. Strict RBAC assigns users to cases as `lead`, `investigator`, `supervisor`, `reviewer`, or `auditor`. Investigators can only *request* case closure; supervisors must *approve* it.

2. **Immutable Audit Trail**  
   Every action (login, case changes, evidence intake) is hash-chained. The trail is anchored in a Merkle Tree (`tools/verify_audit.py` can verify offline). Supports JSON/CSV exports and generates a cryptographically sound PDF Certificate of Integrity. An interactive "Simulate Tamper" button demonstrates the chain breaking.

3. **Synthetic Sandbox**  
   A "Digital Twin" approach to test AI detectors against injected adversarial artifacts (e.g. clock skew, forged DNS) without executing untrusted code or altering the master evidence chain. Proves isolation via an unchanged Master Manifest hash.

## Deploying for real use
1. Serve behind an HTTPS reverse proxy (nginx/Caddy) and set `FORENSIC_COOKIE_SECURE=1`. Do not expose plain HTTP on a network.
2. Put `FORENSIC_DATA_DIR` on encrypted storage and back it up; the database and vault must be backed up together.
3. Run a single server process (SQLite and the in-memory login throttle are per-process).

## Known limits
- Read-only file permissions are a safeguard only; the hash check is what proves integrity. For WORM guarantees use immutable object storage.
- Disk images (E01/dd), PCAP, browser, registry and mobile artifacts are not parsed yet (preserved and hashed, but no parser).
- No password-recovery flow: an admin resets passwords. No MFA.
- The integrity record reports technical facts only. Admissibility under BSA Section 63 is a legal determination for counsel.
