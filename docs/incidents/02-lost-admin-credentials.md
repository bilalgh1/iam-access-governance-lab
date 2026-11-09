# Incident 02 — Lost administrator credentials and break-glass account use

**Type**: real · **Status**: closed

## Context

During phase 2, administration was reorganised:

| Account | Use |
|---|---|
| `bilal.ghlouci` | Daily work, no administrative rights |
| `adm0-bilal` | Tier 0: Active Directory administration only |
| `Administrator` (built-in) | Break-glass account: 25+ character password written down offline, never used in normal operation |

## What happened

Four days after these changes, the password of `adm0-bilal` had been forgotten, along with the local administrator password of the workstation: the lab had accumulated too many accounts without a password vault.

Repeated login attempts locked `adm0-bilal` out, as intended by the domain policy (5 failures, 15-minute lockout).

## Recovery

The **break-glass account** was used, as designed:

1. Logon to the DC with `COMPANY\Administrator`, using the password stored offline.
2. From an elevated session:

```powershell
Unlock-ADAccount -Identity "adm0-bilal"
Set-ADAccountPassword -Identity "adm0-bilal" -Reset -NewPassword (Read-Host -AsSecureString "New password")
```

3. Immediate logoff of the break-glass session, then logon with `adm0-bilal` to verify.

## Side effects

- The PingCastle rule **P-AdminLogin** (built-in administrator used in the last 35 days) is reset: its 35-day clock restarts from this justified use.
- The lost local administrator password of the workstation is not recovered: it will be replaced by a unique, rotated password once Windows LAPS is deployed.

## Findings

| # | Finding | Remediation |
|---|---|---|
| 1 | No password vault: credentials of privileged accounts were only memorised | Password manager (KeePassXC) for every lab credential — the vault component of a PAM, at lab scale |
| 2 | The break-glass account was never tested before being needed | Periodic test of break-glass accounts, documented |
| 3 | Unknown local administrator password on a workstation | Windows LAPS: unique random password per machine, stored in AD, readable by authorised groups only |
| 4 | Account lockout protected the admin account against password guessing, including by its owner | Expected behaviour; unlock procedure documented |

## Lessons

- A break-glass account is only useful if its secret is stored **outside** the system it protects, and if it is tested.
- Every use of a break-glass account must be justified and traced; the session is closed as soon as the recovery is done.
- Losing the local administrator password of a workstation is the exact problem LAPS solves at scale.
