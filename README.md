# IAM Access Governance Lab

Building access governance from scratch for a fictitious SME: access policy, role-based access matrix, segregation of duties, ITIL-based access request process, automated joiner-mover-leaver lifecycle, Active Directory delegation, hybrid identity with Microsoft Entra ID, SSO (SAML / OpenID Connect) and periodic access reviews.

> 🚧 **Work in progress** — phases are published as they are completed.

---

## Scenario

**Company** is a 30-employee SME (Management, Finance, HR, Sales, Marketing, IT). Access rights have always been granted case by case, with no process, no approval trail and no review.

As **access manager**, my mission is to:
1. define who decides and who does what;
2. structure and delegate access in Active Directory;
3. run every access change through a tracked ITIL process;
4. automate joiners, movers and leavers from the HR source;
5. extend identities to the cloud with SSO;
6. prove the result with an access review and a before/after audit.

## Environment

Built on top of my previous labs ([network-admin-lab](https://github.com/bilalgh1/network-admin-lab), [sysadmin-lab](https://github.com/bilalgh1/sysadmin-lab)):

| Component | Role |
|---|---|
| Windows Server — Active Directory `company.local` | On-premises directory, groups, delegation |
| Windows 11 Enterprise workstation | Domain member, user tests |
| GLPI | ITIL service desk: access request catalog and approvals |
| Microsoft Entra ID (free tier) | Hybrid identity, SSO |
| OPNsense | Network segmentation and firewall |

## Roadmap

| # | Phase | Status |
|---|---|---|
| 1 | [Governance framework: RACI, default access matrix, segregation of duties](docs/01-governance-framework.md) | ✅ |
| 2 | Active Directory: [PingCastle baseline audit](docs/02-baseline-audit.md) ✅, [privileged accounts, tiering and delegation](docs/03-privileged-accounts-and-delegation.md) ✅, [audit and traceability](docs/04-audit-and-traceability.md) ✅, [Windows LAPS](docs/05-laps.md) ✅, DC hardening, incidents [01](docs/incidents/01-missing-user-account.md), [02](docs/incidents/02-lost-admin-credentials.md) and [03](docs/incidents/03-dc-update-freeze.md) | 🔄 |
| 3 | Access request and joiner-mover-leaver process (PowerShell + GLPI tickets) | ⏳ |
| 4 | Microsoft Entra ID: hybrid sync, SAML and OpenID Connect SSO | ⏳ |
| 5 | Access review campaign, final audit, executive summary | ⏳ |

Planned next step after phase 5: migrating the lifecycle automation to an IGA tool (midPoint).

## Skills demonstrated

- Access governance: RACI, birthright access matrix, segregation of duties, access reviews
- Active Directory: group design (AGDLP), delegation of control, privileged accounts
- ITIL request fulfilment and change management
- Identity lifecycle automation (joiner, mover, leaver)
- Hybrid identity and federation: Microsoft Entra ID, SAML, OpenID Connect
