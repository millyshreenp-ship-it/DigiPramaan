# Person 4 Notes & Assumptions

## General Assumptions
- The application natively targets Linux (`python:3.12-slim` in Docker). I encountered a timezone issue on Windows during testing, which I resolved locally by installing `tzdata`. I won't force `tzdata` into `requirements.txt` unless requested, as `slim` Linux distributions typically handle `ZoneInfo` fine, but I'll note it here just in case.
- `LEGACY_OPEN_ACCESS` environment variable will be introduced. It will default to `0` (strict assignment). When set to `1`, the platform behaves as it currently does: any active user sees all cases.
- Migration Backfill: Implemented via a post-`init_db` hook. It will find all existing cases and all active users, and idempotently assign users to cases corresponding to their global role equivalents (e.g., admins/investigators as leads, examiners as examiners). This ensures no existing data or users are locked out after the upgrade.
- Ed25519 Keys: For the prototype, the private key will be generated dynamically on first run if missing, and placed in `FORENSIC_DATA_DIR/keys/`.
