# 05 — Local administrator passwords with Windows LAPS

Fixes the baseline finding **A-LAPS-Not-Installed** (15 points) and finding 3 of [incident 02](incidents/02-lost-admin-credentials.md) (lost local administrator password).

## Problem

Every workstation has a local administrator account (`admin`). Without LAPS, its password is set by hand: forgotten (incident 02), or worse, **identical on every machine**. An attacker who extracts it from one workstation can then log on to all the others with it (lateral movement, *pass-the-hash*).

Windows LAPS gives each workstation a **unique, random password, rotated automatically**, stored in Active Directory and readable only by an authorised group.

## Prerequisite: patching the domain controller

Windows LAPS is built into Windows since the April 2023 updates. The DC had received **no update since March 2022** (`Get-HotFix`): the LAPS cmdlets did not exist.

An unpatched domain controller is a finding in itself, more serious than LAPS: every vulnerability fixed since 2022 was exploitable. The September 2026 cumulative update (KB5122881) was installed — see [incident 03](incidents/03-dc-update-freeze.md) for how it went.

## 1. Schema extension, with just-in-time elevation

LAPS adds attributes to computer objects, which requires **Schema Admins**. That group was emptied in [phase 2](03-privileged-accounts-and-delegation.md). The right is granted only for the duration of the operation:

```powershell
Add-ADGroupMember -Identity "Schema Admins" -Members "adm0-bilal"
# log off / log on: the access token is built at logon
Update-LapsADSchema -Verbose
Remove-ADGroupMember -Identity "Schema Admins" -Members "adm0-bilal" -Confirm:$false
```

Trace of the elevation:

| Time | Event | Meaning |
|---|---|---|
| 14:09:54 | 4756 | `adm0-bilal` added to Schema Admins |
| 14:11:47 | 4757 | `adm0-bilal` removed from Schema Admins |

The highest privilege in the forest was held for **less than two minutes**, with named, timestamped evidence.

> Schema Admins and Enterprise Admins are **universal** groups: membership changes produce 4756/4757, not 4728/4729 (global groups) or 4732/4733 (domain local groups). A detection rule watching only 4728 misses every elevation to the most powerful groups.

## 2. Permissions on the workstations OU

```powershell
$postes = "OU=Postes,OU=Ordinateurs,OU=COMPANY,DC=company,DC=local"
Set-LapsADComputerSelfPermission -Identity $postes                                         # each computer writes its own password
Set-LapsADReadPasswordPermission -Identity $postes -AllowedPrincipals "COMPANY\GG_ROLE_AdminsPostes"
Find-LapsADExtendedRights -Identity $postes | Format-List                                  # who else can read?
```

`Find-LapsADExtendedRights` lists accounts holding *All Extended Rights*, which can read LAPS passwords without ever being granted that right explicitly. Result: only `SYSTEM`, `Domain Admins` and `GG_ROLE_AdminsPostes`.

## 3. Policy

GPO **`C_LAPS_Postes`**, linked to OU `Postes` (Computer Configuration → Policies → Administrative Templates → System → LAPS):

| Setting | Value |
|---|---|
| Password backup directory | Active Directory |
| Password settings | Upper + lower case + digits + special characters, 20 characters, 30 days |
| Administrator account to manage | `admin` |
| Password encryption | Enabled |
| Authorized password decryptors | `COMPANY\GG_ROLE_AdminsPostes` |
| Post-authentication actions | Reset the password and restart, 24 hours after the account is used |

Verified from the GPO content, not only its link:

```powershell
Get-GPRegistryValue -Name "C_LAPS_Postes" -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS"
```

## 4. Tests

| # | Test | Expected | Result |
|---|---|---|---|
| 1 | `gpupdate` + `Invoke-LapsPolicyProcessing` on PC-USER1 | Events 10020 (local password changed) and 10018 (stored in AD) | ✅ |
| 2 | Read the password as `adm0-bilal` (Domain Admin, Tier 0) | The attribute is readable but **not decryptable** | ✅ `DecryptionStatus: Unauthorized` |
| 3 | Read the password as a member of `GG_ROLE_AdminsPostes` (Tier 2) | Decrypted | ✅ `DecryptionStatus: Success` |
| 4 | Password displayed in clear text during test 3 → `Reset-LapsPassword` | New password, old one invalid | ✅ rotated, `PasswordUpdateTime` updated |

Reading a password requires **two independent conditions**: the read permission on the object, and being an authorised decryptor.

| | Read the attribute | Decrypt |
|---|---|---|
| `adm0-bilal` (Tier 0) | ✅ | ❌ |
| `GG_ROLE_AdminsPostes` (Tier 2) | ✅ | ✅ |

A Domain Admin could still add himself to `GG_ROLE_AdminsPostes`. No technical control fully resists Tier 0, but that change produces a 4728 event: the control does not make abuse impossible, it makes it **traceable**.

## Accepted residual risk

Event **10108**: the schema lacks `msLAPSCurrentPasswordVersion`, a newer attribute that detects a workstation restored from an old image or snapshot (local password out of sync with the one stored in AD). The Server 2022 version of `Update-LapsADSchema` does not add it; adding it would require running the schema update with a Tier 0 account **from a workstation**, which the tiering model forbids.

| Decision | Compensating measure |
|---|---|
| Not added; accepted until an administration server running a newer Windows version is available | After restoring a workstation snapshot or image, run `Reset-LapsPassword` |

## Lessons

- Rotation is the answer to an exposed secret: with LAPS, a leaked password is replaced in one command, with timestamped proof.
- Encryption separates *reading* from *decrypting*: Domain Admins no longer see workstation passwords by default.
- Security rules are not broken for a secondary feature: the gap is documented and compensated instead.
