# 03 — Privileged accounts, tiering and delegation

Remediation of the privileged-account findings of the [baseline audit](02-baseline-audit.md), and delegation of day-to-day tasks without granting administrative rights.

## 1. Separate accounts per tier

Before: every administrative task, including SSH sessions from the DC and file share configuration, was performed with the built-in `Administrator` account.

| Account | Tier | Scope | Location |
|---|---|---|---|
| `bilal.ghlouci` | — | Daily work (mail, documents, web). **No administrative right** | OU Utilisateurs/IT |
| `adm2-bilal` | 2 | Local administrator of workstations only, through `GG_ROLE_AdminsPostes` | OU Admins |
| `adm0-bilal` | 0 | Active Directory administration only. Never used on a workstation | OU Admins |
| `Administrator` | — | **Break-glass**: 25+ character password stored offline, used only in emergencies | Built-in |

Hardening of the Tier 0 account:

```powershell
Add-ADGroupMember -Identity "Domain Admins"   -Members "adm0-bilal"
Add-ADGroupMember -Identity "Protected Users" -Members "adm0-bilal"   # no NTLM, no cached credentials, no delegation
Set-ADUser -Identity "adm0-bilal"    -AccountNotDelegated $true      # "sensitive and cannot be delegated"
Set-ADUser -Identity "Administrator" -AccountNotDelegated $true
```

Zero standing privilege on the most powerful groups:

```powershell
Remove-ADGroupMember -Identity "Schema Admins"     -Members "Administrator" -Confirm:$false
Remove-ADGroupMember -Identity "Enterprise Admins" -Members "Administrator" -Confirm:$false
```

Both groups are now empty; membership is granted temporarily, only for the duration of an operation that requires it.

Why separate Tier 0 and Tier 2: an administrator who opens a session on a machine leaves reusable credentials in its memory. If a Domain Admin logs on to a compromised workstation, the whole domain is compromised. The Tier 0 account therefore never logs on below Tier 0.

## 2. Machine account quota

By default, any authenticated user can join up to 10 computers to the domain, creating identities they control, with no process or traceability.

```powershell
Set-ADDomain -Identity "company.local" -Replace @{"ms-DS-MachineAccountQuota" = "0"}
```

## 3. Local administrators of workstations, through a group

GPO **`C_Admins_Locaux_Postes`**, linked to OU `Postes`:
Computer Configuration → Preferences → Control Panel Settings → Local Users and Groups → `Administrators (built-in)` (SID `S-1-5-32-544`), action **Update**, member **`COMPANY\GG_ROLE_AdminsPostes`**.

Result on the workstation:

```
net localgroup Administrateurs
  admin
  Administrateur
  COMPANY\Domain Admins
  COMPANY\GG_ROLE_AdminsPostes
```

A new Tier 2 technician becomes local administrator of every workstation, present and future, with a single group membership change.

## 4. Service desk delegation

The service desk resets passwords and unlocks accounts of **users only**, without being administrators.

```powershell
New-ADGroup -Name "GG_ROLE_ServiceDesk" -GroupScope Global -GroupCategory Security -Path "OU=Groupes,OU=COMPANY,DC=company,DC=local"
Add-ADGroupMember -Identity "GG_ROLE_ServiceDesk" -Members "david.moreau"

dsacls "OU=Utilisateurs,OU=COMPANY,DC=company,DC=local" /I:S /G `
  "COMPANY\GG_ROLE_ServiceDesk:CA;Reset Password;user" `
  "COMPANY\GG_ROLE_ServiceDesk:RPWP;pwdLastSet;user" `
  "COMPANY\GG_ROLE_ServiceDesk:RPWP;lockoutTime;user"
```

- Delegated to a **group**, never to a person.
- Scope: OU `Utilisateurs` only. Admin accounts live in OU `Admins`, and members of protected groups are additionally covered by **AdminSDHolder**.
- The technician works from **their workstation** with the AD PowerShell module (RSAT), installed through an over-the-shoulder elevation with the Tier 2 account. Never from the DC.

### Tests (as `david.moreau`, standard user, from PC-USER1)

| Test | Expected | Result |
|---|---|---|
| Reset `bob.durand` with a 3-character password | Rejected by the **password policy** (not by permissions) | ✅ policy error |
| Reset `bob.durand` with a compliant password + force change at next logon | Allowed | ✅ |
| Reset `adm0-bilal` | Denied: outside the delegated scope, protected account | ✅ Access denied |
| Add himself to `Domain Admins` | Denied: no group management delegated | ✅ Insufficient access rights |

## Effect on the audit score

| Rule | Points | Status |
|---|---|---|
| P-Delegated | 20 | ✅ Fixed |
| P-SchemaAdmin | 10 | ✅ Fixed |
| S-ADRegistration | 10 | ✅ Fixed |
| P-AdminLogin | 20 | ⏳ Clears after 35 days without using the built-in `Administrator` (clock reset by the justified break-glass use, see [incident 02](incidents/02-lost-admin-credentials.md)) |

## Pitfalls met (and what they teach)

| Symptom | Cause | Lesson |
|---|---|---|
| `New-ADUser` fails on password policy, then "account already exists" | The object is created **before** the password is set: a failed creation leaves a disabled, half-created account (already added to a group) | Provisioning must verify and roll back (phase 4) |
| "Access denied" as Domain Admin | UAC: non-elevated sessions get a filtered token, admin groups are "deny only" | Even admins do not work with full rights by default |
| `Administrator` still in Schema Admins after removal | The access token is built at logon and never recalculated | Removing a right from an open session is not immediate: close sessions on urgent removals |
| GPO not applied although linked, enabled, versioned | The preference item had been saved **after** the last refresh (GPP timestamps are UTC) | Check the actual content (`Groups.xml`) and its timestamp before blaming the client |
| `findstr Administrators` finds nothing | Localised OS: the group is `Administrateurs` | Rely on SIDs (`S-1-5-32-544`), not names |
| Built-in group description cleared | The "Update" action applies every field, including empty ones | Test preferences on one machine before deploying |
| Member stored with `sid=""` | Name typed instead of picked | Pick objects with the browse button so the SID is stored |
