# 04 — Audit and traceability on domain controllers

The fourth question of IAM — *what did you do?* — had no reliable answer: during [incident 01](incidents/01-missing-user-account.md), an account vanished without any trace. For an access manager, traceability is mandatory: without it, nobody can prove who granted an access, or when.

Fixes the baseline finding **A-AuditDC** (10 points).

## Before

Effective policy on the DC (`auditpol`), i.e. Windows defaults:

| Subcategory | Setting |
|---|---|
| Directory Service Changes | **No Auditing** |
| User / Security Group / Computer Account Management | Success only (failed attempts not logged) |

## 1. Advanced audit policy

GPO **`C_Audit_DC`**, linked to OU **Domain Controllers** (applies to every current and future DC).
Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration:

| Category | Subcategory | Success | Failure | Key events |
|---|---|---|---|---|
| Account Logon | Credential Validation | ✅ | ✅ | NTLM authentication |
| Account Logon | Kerberos Authentication Service | ✅ | ✅ | 4768, 4771 (password spraying) |
| Account Logon | Kerberos Service Ticket Operations | ✅ | ✅ | 4769 (Kerberoasting) |
| Account Logon | Other Account Logon Events | ✅ | ✅ | |
| Account Management | User Account Management | ✅ | ✅ | 4720, 4722, 4724, 4726, 4738, 4740 |
| Account Management | Security Group Management | ✅ | ✅ | 4728, 4729, 4732, 4733 |
| Account Management | Computer Account Management | ✅ | ✅ | 4741, 4743 |
| DS Access | **Directory Service Changes** | ✅ | | **5136, 5137, 5141** |
| Logon/Logoff | Logon | ✅ | ✅ | 4624, 4625 |
| Logon/Logoff | Special Logon | ✅ | | 4672 |
| Policy Change | Audit Policy Change | ✅ | | Someone disabling auditing |

Plus Security Options → **Audit: Force audit policy subcategory settings to override audit policy category settings** = Enabled.

Checks:

```powershell
$gpo = Get-GPO -Name "C_Audit_DC"
Get-Content "\\company.local\SYSVOL\company.local\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\Audit\audit.csv"
auditpol /get /category:"DS Access"
auditpol /get /category:"Account Management"
```

## 2. SACL on the directory

The audit policy only allows the DC to log directory changes. **Which** objects and operations are logged is defined by the **SACL** of each object. The default SACL inherited from the domain root only audits writes to two specific attributes (GPO links), so a change to a user produced no event.

Audit rule added on OU **COMPANY**, inherited by every user, group and computer it contains:

```powershell
$ou     = "AD:\OU=COMPANY,DC=company,DC=local"
$acl    = Get-Acl -Path $ou -Audit
$all    = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")   # Everyone
$rights = [System.DirectoryServices.ActiveDirectoryRights]"CreateChild, DeleteChild, Delete, WriteProperty, WriteDacl, WriteOwner"
$rule   = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($all, $rights,
            [System.Security.AccessControl.AuditFlags]::Success,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
$acl.AddAuditRule($rule)
Set-Acl -Path $ou -AclObject $acl
```

Covered: creations (5137), deletions (5141), attribute changes (5136), permission and owner changes.

## 3. Proof

```powershell
Set-ADUser -Identity "bob.durand" -Description "Test audit 2 $(Get-Date -Format 'HH:mm:ss')"
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136,5137,5141} -MaxEvents 3
```

| Question | Answer in event 5136 |
|---|---|
| Who? | `COMPANY\adm0-bilal` (named account, no longer the generic `Administrator`) |
| When? | 10/11/2026 12:08:51 |
| Which object? | `CN=Bob Durand,OU=Compta,OU=Utilisateurs,OU=COMPANY,…` |
| Which attribute? | `description` |
| Before / after? | *Value Deleted*: "Test audit 12:06" — *Value Added*: "Test audit 2 12:08:45", linked by the same Correlation ID |

## Lessons

- Directory auditing needs **two keys**: the audit policy (*may* the DC log?) and the SACL (*what* to log). Either one alone produces nothing.
- An advanced audit policy GPO **replaces** the default policy: every subcategory it does not mention becomes "No Auditing". *Directory Service Access* (event 4662, used to detect DCSync) silently went from Success to No Auditing and has to be configured explicitly.
- A GPO can be linked and applied while containing nothing useful: always check its actual content (`audit.csv`) and the effective result (`auditpol`).
- No result a few seconds after an action does not prove that no event exists.

## Remaining improvement

Logs are still stored only on the DC. In production, they are forwarded in real time to a SIEM managed by another team, where administrators cannot alter them.
