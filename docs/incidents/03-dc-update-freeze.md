# Incident 03 — Domain controller frozen during a cumulative update

**Type**: real, during phase 2 · **Status**: closed, no data loss

## Context

Windows LAPS required patching the only domain controller, which had received no update since March 2022. The September 2026 cumulative update was launched from `sconfig`.

## What happened

| Time | Event |
|---|---|
| 12:17 | Installation started (`sconfig` → install all quality updates) |
| ~12:58 | VM no longer responding: frozen clock, display not refreshing, mouse inactive |
| 13:06 | Host check: download finished (no network traffic), steady low CPU, no disk activity |
| 13:39 | Still frozen after 40 minutes: VM reset from the hypervisor |
| 13:47 | DC back: update installed (KB5122881), `NTDS`, `DNS` and `Netlogon` running |

Two aggravating factors were found during the incident:

- The PowerShell console was in **selection mode** (title "Select Administrator: …"): a click inside a console pauses the running script as soon as it writes output.
- The most recent VM snapshot was named `avant-iam`: it predated **all** of phase 2. Restoring it would have lost every account, group, delegation and GPO created since.

## Impact

With a single DC, nobody could authenticate to the domain during the freeze and the reboots. No data was lost.

## Findings

| # | Finding | Remediation |
|---|---|---|
| 1 | A heavy change on the only domain controller was started without a recent restore point | Snapshot or verified backup **before** every change on a Tier 0 server |
| 2 | The DC was left unpatched for four and a half years | Monthly patching process |
| 3 | A single DC: any reboot interrupts authentication for the whole domain | A second DC (baseline finding A-NotEnoughDC); in production, DCs are patched one at a time |
| 4 | No change record | Every change on a critical server goes through a change ticket (ITIL): risk, rollback plan, maintenance window |
| 5 | The DC still has its random installation name (`WIN-A5T5IRJE99D`) | Naming convention; renaming a DC is a planned operation, not done in a hurry |

## Lessons

- Before forcing a reset, check from the host whether the VM is still working (CPU, disk): a frozen screen does not mean a frozen system.
- A restore point is only useful if it is recent: check *what* the snapshot contains before relying on it.
- Documentation stored outside the system (the Git repository) means even a full rollback would only cost time.
