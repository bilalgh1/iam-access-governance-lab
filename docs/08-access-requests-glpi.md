# 08 — Ad hoc access requests with GLPI

Anything outside the default access matrix goes through a request. This implements the "ad hoc access request" row of the [RACI](01-governance-framework.md#raci): the employee requests, the **application owner approves (A)**, the **access manager executes (R)**, and nobody approves their own request (SoD rule 4).

## Workflow

```
Employee          Access manager            Application owner        JML process
(GLPI ticket) →   qualifies, requests   →   approves in GLPI    →    grants\access-grants.csv
                  approval                                            → group added, expires automatically
```

| Step | Who | Where | Evidence |
|---|---|---|---|
| Request with business need and duration | Requester | GLPI ticket, category *Access request* | Ticket, timestamp |
| Qualification, approval request to the owner | Access manager | GLPI *Approvals* tab | Approval request |
| Decision | Application owner | GLPI | Approval with comment and timestamp |
| Grant recorded with ticket, approver, expiry | Access manager | `grants/access-grants.csv` | File line |
| Group added, checked, logged | JML process ([doc 07](07-joiner-mover-leaver.md)) | Active Directory | Run report, event 4728 |
| Removal at expiry | JML process | Active Directory | Run report citing the ticket, event 4729 |

## Automated controls on every grant

Application owners are declared in [`config/app-owners.csv`](../config/app-owners.csv) (GESCOM: finance manager, PayFlow: HR manager, CRM: sales manager). A grant line is **rejected** if:

| Control | Rule |
|---|---|
| Scope | Only application groups (`GG_APP_*`): a request cannot grant a department group or an administrative group |
| Approver | Must be the owner of that application |
| Self-approval | Approver and beneficiary must differ |
| Duration | 90 days maximum: every ad hoc access is temporary |
| Segregation of duties | The grant must not create a forbidden combination with the person's other rights |
| Traceability | A ticket reference is mandatory |

Valid grants are added on top of the role; expired grants are removed at the next run, like any other drift.

## Test

| # | Scenario | Result |
|---|---|---|
| 1 | Bob (accountant) requests read access to the CRM for 3 months — ticket 1, approved by Nora (CRM owner) | ✅ `UPDATE add: GG_APP_CRM_Lecture (ticket 1, until 2027-02-15)` |
| 2 | The access manager grants himself payroll approval, declaring himself as approver — ticket 99 | ✅ `INVALID_GRANT REJECTED: approver E1010 is not the owner of PayFlow (E1005); self-approval` |

Also tested before deployment against a mocked directory: wrong owner, duration above 90 days, non-application group, SoD conflict (supplier creation + payment approval → `GRANT_SOD_CONFLICT`), and automatic removal of an expired grant.

GLPI evidence for ticket 1: request by Bob, approval request by the access manager, *Accepted — granted for 3 months* by Nora, each with its author and timestamp.

## GLPI deployment

| Item | Choice |
|---|---|
| Host | `SRV-UBUNTU1` (10.10.20.10), servers network |
| Deployment | Docker Compose: GLPI + MySQL 8.4 ([`glpi/docker-compose.yml`](../glpi/docker-compose.yml)), port 8080 (Nginx already uses 80) |
| Database secret | Random password generated **on the server** in `.env` (`chmod 600`), never displayed nor committed |
| Default accounts | `glpi` password changed; `tech`, `normal`, `post-only` (public default passwords) **disabled**, not deleted |
| Accounts | `bob.durand` and `nora.haddad` (Self-Service), `bilal.ghlouci` (Technician) |

### Pitfalls met

| Symptom | Cause | Lesson |
|---|---|---|
| SSH from the DC refused (`publickey`) | Password authentication disabled on the server (sysadmin hardening); `adm0-bilal` had no key | One key per account: a new key was created and deployed, password authentication re-enabled for two minutes only, then closed and checked (`sshd -T`) |
| Commands pasted after `apt` never ran | `apt` read the pasted lines as answers to its own prompts | Never paste a long sequence behind an interactive command |
| GLPI reachable on 8080 although `ufw` only allows 80 | Docker writes its own firewall rules, evaluated before `ufw` | `ufw` does not protect published container ports; the network firewall (OPNsense) does |
| Script blocked: "not digitally signed" | Run from a network share, so treated as remote under the execution policy | In production: code-signing certificate and `AllSigned` |
| Ticket created without category | Category not visible in the simplified (Self-Service) interface | Make request categories visible to requesters, or reviews cannot find the requests |

## Residual risks

| Risk | Mitigation in production |
|---|---|
| The grant line is typed by the access manager: the approval it references is not verified by the script | Read approvals from the GLPI API instead of a file; meanwhile, every line is cross-checked against GLPI during the access review (phase 5) |
| GLPI accounts are local: a leaver keeps GLPI access | Link GLPI to Active Directory. LDAP signing is now required on the DC ([doc 06](06-dc-hardening-and-final-audit.md)), so this needs LDAPS, hence a certificate authority |
| GLPI served over HTTP: credentials in clear on the network | TLS reverse proxy (Nginx is already on the server) |
| Unsigned script | Code signing + `AllSigned` execution policy |

## Lessons

- An ad hoc access is a decision by the owner of the application, recorded with an end date: without an expiry, "temporary" access becomes permanent.
- Controls that do not depend on people's good will (owner check, no self-approval, SoD) are applied by the process itself.
- Default credentials are the first thing to remove from any new tool.
