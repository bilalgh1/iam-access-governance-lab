# 06 — Domain controller hardening and audit after remediation

Last remediation items of the [baseline audit](02-baseline-audit.md), then a new PingCastle run to measure the result.

Two dedicated GPOs carry the hardening, so that **default GPOs stay untouched** and every future domain controller or computer inherits the settings automatically:

| GPO | Linked to | Content |
|---|---|---|
| `C_Durcissement_DC` | OU Domain Controllers (link order **1**) | Print spooler disabled, NTLMv1 refused, LDAP signing required |
| `C_Durcissement_Global` | Domain root | Hardened UNC paths for SYSVOL and NETLOGON |

## 1. Print spooler on the DC (A-DC-Spooler, A-DC-Coerce)

The print spooler lets **any domain user** force the DC to authenticate to a machine of their choice ("PrinterBug", an authentication coercion). The attacker relays that authentication of the DC's computer account, or captures it through unconstrained delegation, up to full domain compromise. A DC never prints.

`C_Durcissement_DC` → System Services → **Print Spooler: Disabled**, then `Stop-Service Spooler` (the policy changes the startup type; it does not stop a running service).

```
"Spooler",4,""          # GptTmpl.inf: 4 = Disabled
Status: Stopped  StartType: Disabled
```

A-DC-Coerce also disappeared after this change and the cumulative update of the DC ([incident 03](incidents/03-dc-update-freeze.md)).

## 2. NTLMv1 (S-OldNtlm)

An NTLMv1 response captured on the network can be cracked in hours and gives the account's hash.

`C_Durcissement_DC` → Security Options → **Network security: LAN Manager authentication level** = *Send NTLMv2 response only. Refuse LM & NTLM* → `LmCompatibilityLevel = 5`.

## 3. LDAP signing (A-DCLdapSign)

Without signing, an attacker on the network can relay or tamper with LDAP requests to the DC, for example to add an account to a group.

`C_Durcissement_DC` → Security Options → **Domain controller: LDAP server signing requirements** = *Require signing*.

The setting was in the GPO, the GPO was linked and applied, yet the DC still showed `LDAPServerIntegrity = 1`:

| Order | GPO linked to Domain Controllers | LDAP signing |
|---|---|---|
| 1 | Default Domain Controllers Policy | None (1) — **wins** |
| 3 | C_Durcissement_DC | Require (2) |

When GPOs linked to the same OU conflict, the one with the **lowest link order** wins. `NTLMv1` was applied because the default policy does not define it.

```powershell
Set-GPLink -Name "C_Durcissement_DC" -Target "OU=Domain Controllers,DC=company,DC=local" -Order 1
# LDAPServerIntegrity = 2
```

Test from PC-USER1 after each change: secure channel (`nltest /sc_verify:company.local` → `NERR_Success`) and LDAP queries (`Get-ADUser`) still work.

## 4. AD subnets (S-DC-SubnetMissing)

No subnet was declared, so Active Directory could not map machines to a site.

```powershell
New-ADReplicationSubnet -Name "10.10.20.0/24" -Site "Default-First-Site-Name"   # servers (DC)
New-ADReplicationSubnet -Name "10.10.10.0/24" -Site "Default-First-Site-Name"   # workstations
```

The two subnets match the network segmentation of the firewall.

## 5. Hardened UNC paths (A-HardenedPaths)

The rule reported "No GPO found": the protection was not lowered, it was simply **not defined explicitly**. Windows applies it by default, but the STIG baseline requires it to be explicit so that no future GPO can silently weaken it. It protects against a man-in-the-middle serving fake GPOs or logon scripts (MS15-011).

```powershell
$key = "HKLM\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
Set-GPRegistryValue -Name "C_Durcissement_Global" -Key $key -ValueName "\\*\SYSVOL"   -Type String -Value "RequireMutualAuthentication=1, RequireIntegrity=1"
Set-GPRegistryValue -Name "C_Durcissement_Global" -Key $key -ValueName "\\*\NETLOGON" -Type String -Value "RequireMutualAuthentication=1, RequireIntegrity=1"
```

Verified on PC-USER1: both values present in the registry, SYSVOL still reachable.

## 6. Audit policy completed (A-AuditDC)

The rule was still present after [doc 04](04-audit-and-traceability.md). Its details list the subcategories expected by the adsecurity.org reference policy and missing from `C_Audit_DC`:

| Added subcategory (Success) | Detects |
|---|---|
| Directory Service Access | 4662: DCSync (had silently dropped to No Auditing, see doc 04) |
| Process Creation + command line | 4688: every program run on the DC, with its arguments |
| DPAPI Activity | 4692: export of the DPAPI backup key |
| Sensitive Privilege Use | Use of privileges such as SeDebugPrivilege (reading LSASS memory) |
| Security System Extension | 4697: new services or security packages (persistence) |
| Authentication Policy Change | Trust and Kerberos policy changes |
| Logoff | 4634: end of sessions |

Proof — the same command before and after enabling the command line:

| Time | Event 4688 for `whoami.exe` | Process Command Line |
|---|---|---|
| 13:37:16 | `adm0-bilal`, elevated token, from `powershell.exe` | *(empty)* |
| 13:46:58 | `adm0-bilal`, elevated token, from `powershell.exe` | `"C:\Windows\system32\whoami.exe" /priv` |

## 7. Active Directory backup (A-BackupMetadata)

PingCastle reported the last AD backup at the **installation date of the DC**, although a Windows Server Backup of 26/10 existed and included the system state. The most likely cause: `wbadmin start backup` performs a **VSS copy backup** by default. Files are copied, but Active Directory is not told that a backup took place; only a full VSS backup or a system state backup updates its backup date.

```powershell
wbadmin start systemstatebackup -backupTarget:E: -quiet
wbadmin get versions        # new version 11/12/2026
```

Rule cleared after the backup. A VM snapshot is not a DC backup either: Active Directory does not know about it, and restoring a DC snapshot in a multi-DC domain can break replication.

The backup contains `NTDS.dit`, i.e. the hashes of every password in the domain: the backup disk is a **Tier 0 asset**. In production, a copy is also kept offline or immutable, since ransomware targets backups first.

## Result

| Category | Baseline | After remediation |
|---|---|---|
| Anomalies | 75 | **5** |
| Privileged Accounts | 50 | **20** |
| Stale Objects | 41 | **0** |
| Trusts | 0 | 0 |
| **Domain risk level** | **75 / 100** | **20 / 100** |

Target of the remediation plan (about 15) reached once P-AdminLogin clears.

| Remaining rule | Points | Status |
|---|---|---|
| P-AdminLogin | 20 | Clears automatically 35 days after the last use of the built-in `Administrator`, i.e. the justified break-glass use of [incident 02](incidents/02-lost-admin-credentials.md) |
| A-NotEnoughDC | 5 | Accepted lab limitation: a single DC. In production, at least two DCs |

Rules cleared without dedicated action: **S-AesNotEnabled** and **S-PwdNeverExpires** (11 points) no longer appear; their exact cause was not isolated.

Informative rules (0 points) left for later: LLMNR not disabled, no NetCease, Pre-Windows 2000 group containing Authenticated Users, PowerShell auditing.

## Lessons

- Check the **effective** state on the machine (`auditpol`, registry, `Get-Service`), not only the GPO: a correct, linked, applied GPO can still be overridden by another one.
- Keep default GPOs untouched and put hardening in dedicated, explicitly ordered GPOs.
- A backup is only a backup if the system it protects knows about it and it is repeated: one backup 47 days old is not a backup policy.
- Measuring before and after turns a list of changes into a result a manager can read.
