# 07 — Joiner-mover-leaver process

Identity lifecycle driven by HR, implementing the [governance framework](01-governance-framework.md): HR is accountable for every joiner, mover and leaver; IT never creates or removes an identity without an HR event; the default access matrix and the segregation-of-duties matrix are applied automatically.

## Architecture

```
HR export (CSV)        →   Invoke-Jml.ps1                     →   Active Directory
authoritative source       compares HR and AD, applies the          accounts, OUs,
key: employee ID           role matrix, checks SoD, logs,            business role groups
                           rolls back failed creations
```

| File | Content |
|---|---|
| [`data/hr-export.csv`](../data/hr-export.csv) | Fictitious HR export: employee ID, name, role, manager, start and end dates |
| [`config/roles.csv`](../config/roles.csv) | Default access matrix of [doc 01](01-governance-framework.md#default-access-matrix-birthright) as groups: 10 roles |
| [`config/sod-rules.csv`](../config/sod-rules.csv) | Forbidden combinations (SoD rules 1 and 2 of doc 01) |
| [`scripts/New-JmlStructure.ps1`](../scripts/New-JmlStructure.ps1) | One-time setup by Tier 0: OUs, groups, least-privilege delegation. Idempotent |
| [`scripts/Invoke-Jml.ps1`](../scripts/Invoke-Jml.ps1) | The JML engine. **Dry run by default**, changes only with `-Apply`, CSV report for every run |

### Design choices

| Choice | Reason |
|---|---|
| Matching key: **employee ID** stored in `employeeID` | Unique and stable. A name changes (marriage) and has homonyms; a login derives from the name; a SID changes when an account is recreated ([incident 01](incidents/01-missing-user-account.md)) |
| Application rights as **groups** (`GG_APP_GESCOM_*`, `GG_APP_PayFlow_*`, `GG_APP_CRM_*`) | One place to grant and review access; the same groups will drive SSO in phase 4 |
| Leaver: **disabled on the end date**, deleted after 30 days | Access is cut the same day; deletion is irreversible, so the account is kept (disabled, no groups) in case of HR error or for investigations |
| Mover: old role groups removed **before** new ones are added | No window in which the person holds both sets of rights |
| Business role groups fully driven by the matrix | A business group added outside the process is drift, corrected at the next run |
| `GG_ROLE_*` and privileged groups **out of scope** | Privileged access is approved by the CISO (RACI), never granted by automation; for a leaver they are reported as a manual action |
| Name-based matching only for the **one-time** link of pre-existing accounts, flagged for validation | Approximate matching would eventually link an identity to the wrong person |
| Random initial password, never displayed nor logged | First logon goes through the service desk: identity check, reset, change at next logon |

## Least privilege for the process itself

The script runs as **`adm1-bilal`**, a Tier 1 identity administrator, member of **`GG_ROLE_IAM`**: not as a Domain Admin.

| Delegated to `GG_ROLE_IAM` | Scope |
|---|---|
| Create and delete **user** objects | OU `Utilisateurs` (and sub-OUs), OU `Desactives` |
| Read/write user attributes, reset passwords | Same OUs, user objects only |
| Write the `member` attribute | The 16 business role groups of `roles.csv` only |

Scripts and data live in a hidden share **`IAM$`** on the server. Permissions:

| | Share | NTFS |
|---|---|---|
| `GG_ROLE_IAM` | Change | **Read** on scripts, config and HR data · **Modify** on `reports` only |
| Domain Admins | Full | Full |

The operator can run the process and write reports, but **cannot modify the HR export nor the script**: whoever executes changes cannot write their own request (SoD rule 4).

## First run: connecting HR to an existing directory

Dry run first. It revealed an error that would have created a **duplicate identity**:

```
E1010   bilal.ghlouci2   JOINER   ...
        bilal.ghlouci    ORPHAN   Active account with no HR record
```

Cause: the existing `bilal.ghlouci` account had no given name nor surname (left over from the failed creation of phase 2), so the one-time name matching did not find it. The script was **not** changed to match more loosely: the access manager linked the account manually (`Set-ADUser -EmployeeID E1010`), a change traced by the directory audit (event 5136).

Second dry run clean, then `-Apply`:

| Action | Count | Detail |
|---|---|---|
| JOINER | 6 | Accounts created in the right OU, with role groups and manager |
| RECONCILE + UPDATE | 6 | Existing accounts linked to their employee ID, job title set, missing role groups added |
| PENDING | 1 | Future joiner (start date in December): nothing created before the start date |

An immediate second dry run returned **NO_CHANGE for every person**: the directory had converged on the HR source. A later dry run showing changes while the HR export is unchanged means someone modified the directory outside the process.

## Lifecycle tests

Test day: the HR export was modified on the server (by Tier 0, simulating the HR system), plus one change made directly in the directory.

| # | Scenario | Expected | Result |
|---|---|---|---|
| 1 | **Mover**: Lucas, sales representative → accountant | Remove sales groups, then add accounting groups, move to OU Compta, new manager | ✅ `MOVER` — 3 groups removed, 3 added, moved, manager = Sophie Bernard |
| 2 | **Leaver**: Emma, end date today | Disabled first, password reset, groups removed, moved to `Desactives`, removed groups recorded | ✅ `LEAVER` — `Enabled: False`, `MemberOf: {}`, description `Disabled by JML on 2026-11-16. Groups removed: GG_APP_PayFlow_Saisie, GG_RH` |
| 3 | **Failed joiner**: role misconfigured to grant `Domain Admins` | Delegation refuses the privileged group; the partially created account is deleted | ✅ `ERROR: insufficient access rights \| rolled back: partially created account deleted` — no account left |
| 4 | **Out-of-process grant**: Bob (supplier creation) added directly to *payment approval* | Drift removed at the next run | ✅ `UPDATE remove: GG_APP_GESCOM_ValidationPaiements` |

Test 3 shows two independent safeguards: the delegation blocked a privilege escalation even though the configuration asked for it, and the rollback left no half-created account ([incident 01](incidents/01-missing-user-account.md), finding 4).

Test 4, traced in the DC security log:

| Time | Event | By | Meaning |
|---|---|---|---|
| 14:00:40 | 4728 | `adm0-bilal` | Bob added to payment approval: SoD rule 1 broken (supplier creation + payment approval) |
| 14:08:17 | 4729 | `adm1-bilal` | Removed by the JML run |

The forbidden combination existed for less than eight minutes, and both the change and its correction have a named author.

## Residual risks

| Risk | Mitigation in production |
|---|---|
| "Write all properties" on users also allows writing sensitive attributes (e.g. `servicePrincipalName`, enabling targeted Kerberoasting) | Restrict the delegation to the attributes the process writes |
| The process runs interactively from a workstation | Scheduled task on a Tier 1 management server, under a group managed service account (gMSA): no password to store |
| Initial password handling relies on the service desk | Temporary access pass or self-service onboarding with identity verification |
| Reports contain personal data (names, roles) | Retention period and restricted access on the `reports` folder |
| No approval workflow for ad hoc requests | Ticketing with approval by the application owner (next step: GLPI) |

## Lessons

- Always dry run: the first simulation caught a duplicate identity before it existed.
- Fix the data, not the matching rule: when automatic matching fails, a person decides and the decision is traced.
- A process that restores the expected state makes out-of-process grants short-lived; the audit log tells who made them.
- The account running the automation is itself an identity to govern: least privilege, no Tier 0.
