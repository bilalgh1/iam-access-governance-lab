# 10 — Access review campaign and final audit

Every access right in the directory is reviewed: why it exists, who must certify it, and what does not fit. Then a last PingCastle run measures the domain after the whole project.

## Method

[`scripts/Export-AccessReview.ps1`](../scripts/Export-AccessReview.ps1), run by the access manager (`adm1-bilal`). **Read-only**: it changes nothing in the directory.

For each account in OU `Utilisateurs` and OU `Desactives`, and each group it belongs to, it states the **source** of the access and the **reviewer**:

| Source | Justification | Reviewer |
|---|---|---|
| ROLE | Default access matrix, for the person's HR role | Application owner (`GG_APP_*`), otherwise the person's manager |
| GRANT | Approved ticket with an expiry date ([doc 08](08-access-requests-glpi.md)) | Application owner |
| PRIVILEGED | Administrative delegation, built-in admin groups | CISO |
| UNEXPECTED | Nothing justifies it | To explain or remove |

It also reports findings: orphan accounts, HR / directory mismatches, inactive or never-used accounts, SoD conflicts, grants expiring soon, privileged memberships, administrative accounts without a recorded owner, standing membership in Enterprise or Schema Admins.

Outputs: one CSV of rights to certify (with empty *Decision* and *Comment* columns for reviewers) and one CSV of findings.

## Results

| Rights reviewed | ROLE | GRANT | PRIVILEGED | **UNEXPECTED** |
|---|---|---|---|---|
| 32 | 24 | 1 | 7 | **0** |

No unjustified access, no SoD conflict, no orphan account, no leaver still enabled. Every right can be traced to a role, a ticket or a delegation — which the directory could not show before the [JML process](07-joiner-mover-leaver.md).

### Findings

| Severity | Finding | Accounts | Analysis | Action |
|---|---|---|---|---|
| Medium | `ADMIN_WITHOUT_OWNER` | `adm0-bilal`, `adm1-bilal`, `adm2-bilal` | Administrative accounts not linked to their owner: when he leaves, the JML process disables his business account but **his admin accounts stay enabled**, and nobody knows they were his | Linked to employee ID `E1010` (Tier 0 change); the JML leaver process now reports the person's enabled admin accounts, to be disabled the same day by a Tier 0 administrator |
| Low | `NEVER_USED` | `bob.durand` | Bob signed in to the CRM and PayFlow the day before. `lastLogonTimestamp` only records **Active Directory** logons: cloud sign-ins are invisible to it | Inactivity reviews must combine AD logons with the Entra ID sign-in log, or cloud-only users would be disabled while they work |
| Low | `NEVER_USED` | `bilal.ghlouci` | The administrator worked only with his admin accounts; his daily account stayed unused | Expected in the lab; in production the daily account is the one used for mail and web |
| Low | `NEVER_USED` | `claire.petit` | No logon since creation | Confirmed with the manager before any action |
| Info | `PRIVILEGED_ACCESS` | `david.moreau` | Service desk delegation held by a business account | Certified by the CISO (below) |

### Side effect caught by testing

Linking the admin accounts to `E1010` gave **four** accounts the same employee ID. The JML process resolved a person's manager by employee ID across the whole domain: at its next run, David (manager `E1010`) would have received an ambiguous result and an error. Found by running the modified data against a mocked directory before deployment; the manager lookup is now restricted to business accounts. Dry run on the real directory afterwards: **NO_CHANGE** for every person.

## Certification

| Right | Reviewer | Decision | Reason |
|---|---|---|---|
| `bob.durand` → `GG_APP_CRM_Lecture` (ticket 1) | CRM owner | ✅ Keep until 2027-02-15 | Approved business need; removed automatically at expiry |
| `david.moreau` → `GG_ROLE_ServiceDesk` | CISO | ⚠️ Keep **and regularise** | Justified (service desk technician), but granted in phase 2 with no ticket and no approval: regularisation ticket **2** opened in GLPI |
| `adm0-bilal` → Domain Admins | CISO | ✅ Keep | Named Tier 0 account, member of Protected Users |
| `Administrator` → Domain Admins, Administrators | CISO | ✅ Keep | Break-glass account, secret stored offline, every use flagged by PingCastle (P-AdminLogin) |
| Domain Admins, Enterprise Admins → Administrators | CISO | ✅ Keep | Default nesting; Enterprise Admins has no member |
| `Administrator` → Group Policy Creator Owners | CISO | ❌ **Revoke** | Default membership, redundant with Domain Admins: redundant rights blur every review. Removed, group now empty |

## Final audit

| Category | Baseline ([doc 02](02-baseline-audit.md)) | After hardening ([doc 06](06-dc-hardening-and-final-audit.md)) | **Final** |
|---|---|---|---|
| Anomalies | 75 | 5 | **5** |
| Privileged Accounts | 50 | 20 | **20** |
| Stale Objects | 41 | 0 | **0** |
| Trusts | 0 | 0 | **0** |
| **Domain risk level** | **75 / 100** | **20 / 100** | **20 / 100** |

| Remaining rule | Points | Status |
|---|---|---|
| P-AdminLogin | 20 | Clears on its own 35 days after the last, justified use of the break-glass account ([incident 02](incidents/02-lost-admin-credentials.md)): the score then drops to **5** |
| A-NotEnoughDC | 5 | Accepted lab limitation: a single domain controller |

### A rule that came back

Between two runs, **A-BackupMetadata** (15 points) reappeared: the system state backup of [doc 06](06-dc-hardening-and-final-audit.md#7-active-directory-backup-a-backupmetadata) was nine days old. One backup is not a backup policy.

| Step | Detail |
|---|---|
| Fix | Daily system state backup scheduled at 21:00 (`wbadmin enable backup -systemState`) |
| Catch | The scheduled job was created as a **VSS copy backup** — the very cause found earlier for backups Active Directory does not record. It would have run every night while the alert returned a week later |
| Correction | `Set-WBVssBackupOption -VssFullBackup` on the policy; immediate backup run |
| Verification | New PingCastle run: rule cleared |

## Lessons

- A review is only fast when every right carries its justification: here, 32 rights and 0 unexplained.
- Administrative accounts must be linked to their owner, or leavers keep their most powerful accounts.
- Inactivity based on Active Directory alone misses cloud users.
- A data fix can break automation: test changes against the processes that read the data.
- Controls drift back (a backup ages, a schedule uses the wrong option): audits are repeated, not done once.
