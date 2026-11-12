# 02 — Baseline audit of Active Directory

Before changing anything, the current state of the `company.local` domain was measured with **PingCastle** (Netwrix, open source edition, downloaded from the official GitHub releases).

The audit was run from a domain workstation with a **standard user account** (`alice.martin`, accountant, no administrative rights). It worked: any authenticated user can read almost the whole directory, so an attacker who steals any account can produce the same report.

```powershell
.\PingCastle.exe --healthcheck --server company.local
```

## Score

PingCastle scores risk from 0 to 100 (lower is better). The global score is the **worst** of the four categories.

| Category | Score | Rules matched |
|---|---|---|
| **Anomalies** | **75** | 16 |
| Privileged Accounts | 50 | 4 |
| Stale Objects | 41 | 12 |
| Trusts | 0 | 0 |
| **Domain risk level** | **75 / 100** | |

Consequence for prioritisation: fixing Stale Objects alone would not lower the global score while Anomalies stays at 75.

## Findings

Rules scoring points, extracted from the XML report:

```powershell
[xml]$report = Get-Content .\ad_hc_company.local.xml
$report.HealthcheckData.RiskRules.HealthcheckRiskRule |
    Sort-Object {[int]$_.Points} -Descending |
    Format-Table Points, Category, RiskId, Rationale -Wrap
```

| Points | Rule | Finding | Family |
|---|---|---|---|
| 20 | P-AdminLogin | Built-in `Administrator` account used today | Identity & access |
| 20 | P-Delegated | 1 admin account without "sensitive and cannot be delegated" | Identity & access |
| 15 | A-LAPS-Not-Installed | No LAPS: local admin passwords not managed | Identity & access |
| 15 | S-OldNtlm | LAN Manager level allows NTLMv1 / LM | DC hardening |
| 15 | A-BackupMetadata | Last AD backup reported 39 days ago | To investigate |
| 10 | S-ADRegistration | Any user can join up to 10 computers to the domain | Identity & access |
| 10 | A-DC-Spooler | Print spooler reachable on the DC | DC hardening |
| 10 | A-DC-Coerce | DC RPC interfaces likely vulnerable to coercion (2) | Accepted lab limitation |
| 10 | A-AuditDC | DC audit policy does not collect key events | Identity & access (traceability) |
| 10 | P-SchemaAdmin | Schema Admins group not empty (1 account) | Identity & access |
| 10 | S-AesNotEnabled | 1 service account without AES support | Identity & access |
| 5 | A-DCLdapSign | LDAP signing not enforced | DC hardening |
| 5 | A-HardenedPaths | Hardened UNC paths lowered | DC hardening |
| 5 | A-NotEnoughDC | Single DC, no redundancy | Accepted lab limitation |
| 5 | S-DC-SubnetMissing | DC address not in a declared AD subnet | DC hardening |
| 1 | S-PwdNeverExpires | 1 account with a never-expiring password | Identity & access |

Informative rules (0 points) also flagged: LLMNR not disabled, no NetCease, no service account password policy, Pre-Windows 2000 group containing Authenticated Users, PowerShell auditing incomplete, an OU without accidental deletion protection.

### Key observation

**The three heaviest privileged-account findings (50 points) come from day-to-day administration habits**: using the built-in `Administrator` account for everything, no protection against credential delegation, and a permanent member in Schema Admins. They are fixed by separate admin accounts, protected privileged accounts and zero standing privilege.

### Open question

`A-BackupMetadata` reports the last AD backup 39 days ago, although a system state backup with Windows Server Backup was performed 9 days before this audit. **Resolved**: the earlier backup was most likely a VSS copy backup, which Active Directory does not record — see [06](06-dc-hardening-and-final-audit.md#7-active-directory-backup-a-backupmetadata).

## Prioritised remediation plan

| Priority | Actions | Points | Phase |
|---|---|---|---|
| 1 | Named admin account, built-in `Administrator` kept for emergencies only, privileged accounts marked sensitive, Schema Admins emptied | 50 | AD |
| 2 | Machine account quota set to 0, DC audit policy | 20 | AD |
| 3 | Windows LAPS | 15 | AD |
| 4 | Service account: AES, long password | 10 | AD |
| 5 | DC hardening: spooler, NTLMv1, LDAP signing, subnet | 35 | Quick wins |
| — | AD backup metadata discrepancy | 15 | Investigation |
| — | Single DC, RPC coercion | 15 | Accepted and documented lab limitations |

**Target: global score from 75 to about 15**, starting with privileged accounts.

## After remediation

Global score **75 → 20**, details in [06 — DC hardening and audit after remediation](06-dc-hardening-and-final-audit.md#result).
