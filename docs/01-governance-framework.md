# 01 — Access governance framework

Scoping phase: who decides, who does what, which access each job gets by default, and which combinations of rights are forbidden. Every later phase (Active Directory, joiner-mover-leaver process, Entra ID, access review) implements these documents.

## Context: Company

Fictitious SME, 30 employees, single site.

| Department | Headcount | Jobs |
|---|---|---|
| Management | 2 | CEO, executive assistant |
| Finance (Compta) | 6 | Accountant, finance manager |
| HR (RH) | 4 | HR officer, HR manager |
| Sales (Commercial) | 8 | Sales representative, sales manager |
| Marketing | 4 | Marketing officer |
| IT | 4 | Service desk technician, system administrator, access manager |

### Applications in scope

| Application | Technology | Sensitive functions |
|---|---|---|
| File shares | Active Directory (domain local groups) | One folder per department |
| Mail and Microsoft 365 | Microsoft Entra ID | Shared mailboxes (`compta@`, `rh@`) |
| **GESCOM** (ERP) | IBM i (AS400) | Sales (orders, customers), Purchasing (**supplier creation**), Accounting (entries, **payment approval**) |
| **PayFlow** (payroll) | SaaS, SAML SSO | Read, payroll input, **payroll approval** |
| **CRM** | SaaS, OpenID Connect SSO | Customer accounts, **discount approval** |
| GLPI | IT service management | Requester (everyone), technician (IT) |

## RACI

**R** performs · **A** decides and is accountable (**exactly one A per row**) · **C** consulted before · **I** informed after.

| Process | Employee | Manager | HR | Application owner | Access manager | Service desk | CISO |
|---|---|---|---|---|---|---|---|
| Joiner | I | C | **A** | | R | R | |
| Mover | I | C | **A** | | R | I | |
| Leaver | | I | **A** | | R | R | I |
| Ad hoc access request | R | C | | **A** | R | | |
| Privileged group membership | | C | | | R | | **A** |
| Periodic access review | | R | | **A** | R | | I |

Design choices:
- **HR is accountable for joiners, movers and leavers**: the HR system is the authoritative source. IT never creates or removes an identity without an HR event.
- **The application owner approves access to their application**: they know what the rights allow. The manager confirms the business need.
- **The CISO approves privileged access**: the access manager executes but never approves privileged rights, including for themselves.

## Default access matrix (birthright)

Rights granted automatically at arrival, based on the job. Anything else goes through an ad hoc request.

`—` none · `R` read · `M` modify

| Job | Own department share | GESCOM (IBM i) | PayFlow | CRM | Shared mailbox |
|---|---|---|---|---|---|
| Accountant | M | Accounting entries, supplier creation | — | — | `compta@` |
| Finance manager | M | Accounting entries, **payment approval** | — | — | `compta@` |
| HR officer | M | — | Payroll input | — | `rh@` |
| HR manager | M | — | **Payroll approval** | — | `rh@` |
| Sales representative | M | Sales: order entry | — | M | — |
| Sales manager | M | Sales | — | M + **discount approval** | — |
| Service desk technician | — | — (no access to business data) | — | — | — |
| CEO | M (Management share only) | R (reporting) | — | R | — |

Design choices:
- **Need to know does not depend on seniority.** The CEO gets no default access to other departments' data or mailboxes. The CEO's account is a prime target (CEO fraud); broad default rights would make it the key to the whole company.
- **IT administers tools, not business data.** Technical interventions on an application use a dedicated admin account, through a tracked request.

## Segregation of duties (SoD) matrix

| # | Right A | Right B | Risk | Control |
|---|---|---|---|---|
| 1 | Supplier creation (GESCOM) | Payment approval (GESCOM) | Create a fake supplier and pay it | Forbidden: two different people |
| 2 | Payroll input (PayFlow) | Payroll approval (PayFlow) | Raise a salary or pay a ghost employee | Forbidden |
| 3 | Order entry (GESCOM) | Discount approval (CRM) | Grant abusive discounts to an accomplice customer | Discounts above a threshold approved by the sales manager |
| 4 | Submitting an access request | Approving the same request | Granting oneself rights | Forbidden in the ticketing tool |
| 5 | Administering a system | Administering its audit logs | Erasing traces of one's own actions | Logs forwarded to a central system the administrator cannot modify |

Every assignment of a default right or an ad hoc request is checked against this matrix **before** it is granted (prevention), and again during access reviews (detection).

## Review of the first draft

The first draft of these documents contained five errors, found during peer review. They are kept here because they are typical:

| Error | Principle | Fix |
|---|---|---|
| Two "A" on the ad hoc request row | Single accountability | Application owner A, manager C |
| Access manager both A and R on privileged access | Segregation of duties, no self-approval | CISO A |
| Finance manager with supplier creation **and** payment approval | Contradicted SoD rule no. 1 | Supplier creation moved to the accountant |
| Service desk technician with modify rights in the ERP | Least privilege: IT administers tools, not data | No data access |
| CEO with full access to every share and mailbox | Need to know | Own scope, read-only reporting, ad hoc requests |

Lesson: the most serious errors were **contradictions between documents**. A reliable control cross-checks the access matrix against the SoD matrix instead of reading each line in isolation.
