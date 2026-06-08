---
inclusion: auto
---

# OnboardOffboard App — Project Notes

## Overview
An onboarding/offboarding automation tool that integrates with Active Directory and Microsoft 365. It provides a web UI and CLI for managing user lifecycle (create, clone, delete accounts) with license assignment based on job roles.

## Current Status
- Project is in active development
- Web UI with Flask (onboard, clone, delete flows)
- AD client for user management
- M365 client for license operations
- YAML-based configuration and job role definitions

## Key Decisions
- Offboarding find/restore (Step 2 of `_offboard_m365_user` in web.py) must poll the
  Entra directory recycle bin with retries. Removal from `/users` and appearance in
  `/directory/deletedItems` are NOT atomic during a hybrid AD-sync delete; a one-shot
  check fails if it runs a moment too early.
- Recycle-bin lookups go through `M365Client.find_deleted_user`, which paginates via
  `_request_all` (deletedItems returns only 100/page by default) and uses a server-side
  `$filter` with a full-scan fallback.

## In Progress / Next Steps
<!-- Update this section at the end of each session -->

## Notes
### Offboarding "not found in active users or deleted items" failure (Jason.Sames, 2026-06-06)
- Root cause: after AD sync propagated the deletion, the user was gone from active users
  but had not yet appeared in deletedItems. The old code checked deletedItems exactly once
  (no retry) and read only the first page (no pagination), so it raised RuntimeError and
  aborted. Manual restore made the account cloud-only, so the retry succeeded via the
  active-user path and never touched the fragile deletedItems lookup.
- Fix: Step 2 now polls the recycle bin for up to 5 min (20s interval) and uses the new
  paginated `find_deleted_user`. See web.py `_offboard_m365_user` and m365_client.py.
