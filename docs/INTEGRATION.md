# Integration Contract for Teammates

## Shared Identifiers
- Cases: `CASE-YYYYMMDD-[4hex]`
- Evidence: `EV-[10hex]`
- Artifacts: `ART-[10hex]`
- Events: `EVT-[12hex]`

## Protected Endpoints (RBAC)
When writing a new case-scoped endpoint, you must use the `get_case_or_403` dependency to ensure the user is assigned to the case (or `LEGACY_OPEN_ACCESS` is enabled) and holds the required permission.

**Snippet:**
```python
from .auth import get_case_or_403

@app.get("/api/cases/{case_id}/findings")
def get_findings(case_id: str, case: dict = Depends(get_case_or_403("finding:read"))):
    # 'case' contains the case metadata. 
    # If the user lacks access, FastAPI will automatically return 403.
    pass
```

## Permission Matrix
Roles map to these permission strings:
- `case:create`, `case:read`, `case:assign`, `case:update`, `case:close`
- `evidence:upload`, `evidence:read`
- `finding:write`
- `sandbox:run`
- `audit:read`, `audit:verify`, `audit:export`
- `user:manage`

*See `/api/permissions` or the UI matrix for exact role-to-permission mappings.*

## Audit Action Naming
When writing to the custody log via `custody.append`, use standard action names:
- Use ALL_CAPS for system/security events (`LOGIN_FAILED`, `ACCESS_DENIED`).
- Use `snake_case` for normal lifecycle events (`case_created`, `evidence_acquired`, `artifact_parsed`).
- Detail JSON should ideally contain exactly what changed (e.g. `diff` for updates) and relevant hashes.

## Sandbox Integration (Person 3)
If you build an anomaly detector, wire it into the Sandbox Engine by swapping out the fallback rule-based detector in `app.sandbox.detect(events)`.
Your detection results should log to the audit trail as `sandbox_run` with the findings in the detail payload.

## Frontend Tabs
To register a new tab in `static/index.html`:
1. Add `<button class="tab" role="tab" data-tab="yourtab">Name</button>` in `<nav>`.
2. Add `<section id="paneYourtab" hidden>...</section>` inside `<main>`.
3. Update `showTab(t)` in the script to unhide your pane when `t === "yourtab"`.
