# 09 — Microsoft Entra ID: hybrid identity and single sign-on

Extends the on-premises identity to the cloud: the accounts and groups managed by the [JML process](07-joiner-mover-leaver.md) are synchronised to Microsoft Entra ID, and drive access to two SaaS-style applications through SSO — **OpenID Connect** for the CRM and **SAML 2.0** for payroll, as defined in the [governance framework](01-governance-framework.md#applications-in-scope).

```
Active Directory (company.local)  ──Cloud Sync──►  Microsoft Entra ID  ──SSO──►  "CRM"      OIDC
 accounts, employee ID,                              same identities,              "PayFlow"  SAML
 GG_APP_* groups (JML)                               same groups
```

One control point: a change made by the JML process in Active Directory (joiner, mover, leaver, temporary grant) reaches the cloud applications without any manual step.

## Tenant and licensing

| Item | Choice |
|---|---|
| Tenant | Microsoft Entra ID **Free**, created with a free Azure account (no paid resource used) |
| Why not P1/P2 | The P2 trial could not be activated on this tenant (trials moved to the Microsoft 365 admin center) |
| What Free changes | Applications are assigned **user by user**: assigning a group to an application requires P1. Groups still reach applications **inside the token** |

## Administration accounts

| Account | Role | Use |
|---|---|---|
| Personal Microsoft account that created the tenant | Global Administrator | Seen by Entra as an external account; tenant-level settings only |
| `adm-cloud-bilal@…onmicrosoft.com` | **Hybrid Identity Administrator** only | Cloud-only, dedicated, MFA. Registered the sync agent |

The sync agent cannot be registered with an external account, and least privilege rules out using the Global Administrator for it.

## Synchronisation with Cloud Sync

### Agent

| Item | Value |
|---|---|
| Location | Domain controller — supported by Microsoft, which recommends treating the agent server as a **Tier 0 asset** anyway |
| Service account | Group managed service account **`pGMSA_a662343c$`**: password generated and rotated by Active Directory, known by nobody |
| Prerequisite | KDS root key (`Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))` — lab shortcut valid with a single DC; production waits 10 hours for replication) |
| Installation | Internet Explorer Enhanced Security Configuration blocked the Microsoft sign-in page: disabled for administrators **during the installation only**, then re-enabled |

Rights of the agent's account at the domain root (`dsacls`): *Replicating Directory Changes* and *Replicating Directory Changes All* (password hash sync), *Reset Password*, write access to user and group objects, write access to `msDS-KeyCredentialLink`. Whoever controls the agent server controls the domain — hence Tier 0. Its replication requests produce event **4662** on the DC: expected from this account, a DCSync indicator from any other ([doc 04](04-audit-and-traceability.md)).

### Scope

| OU | Synchronised | Reason |
|---|---|---|
| `Utilisateurs`, `Groupes` | ✅ | Employees and the business role groups |
| `Desactives` | ✅ | A leaver appears in the cloud as a **blocked** account; out of scope, it would be deleted from the cloud without trace |
| `Admins` | ❌ | Tier 0 accounts never go to the cloud: a tenant compromise must not reach them |

Options: password hash synchronisation enabled; accidental deletion prevention lowered from the default 500 objects to **5** (a default of 500 protects nothing in a 30-person company), with e-mail notification.

### Validation on one object first

`Provision on demand` for Bob before enabling the configuration: import, scoping, matching, creation — all green. The equivalent of the JML dry run.

### Observations

| Observation | Explanation |
|---|---|
| `bob.durand@company.local` becomes **`bob.durand@…onmicrosoft.com`** | `.local` is not a routable domain and cannot be verified in Entra ID. In production: add a routable UPN suffix in AD (e.g. `@company.fr`), verified in the tenant, so that each employee has **one** identifier everywhere |
| `employeeID` synchronised | The HR key identifies the person in AD **and** in the cloud |
| Test text in `description` synchronised | Every synchronised attribute is exposed to the cloud: clean directory data before connecting it |

### Incident: passwords not synchronised

| Step | Finding |
|---|---|
| Symptom | Bob's account and groups present in Entra ID, but "incorrect account or password" at sign-in |
| Check 1 | Password hash sync **enabled** in the configuration |
| Check 2 | `dsacls … \| findstr provAgent` returned nothing, suggesting missing replication rights |
| Correction of the check | The real account name is `pGMSA_a662343c$` (the wizard displays a friendly name): the rights were **present**. Always verify the exact account name before concluding that a right is missing |
| Decisive evidence | Bob's *last password change* in Entra ID: 18/11 14:38 (creation), not the reset made later in AD |
| Root cause | A password is only sent **when it changes**; that change had been missed and nothing retries it |
| Resolution | New reset in AD by the access manager (`adm1-bilal`): *last password change* updated within seconds, sign-in accepted |

## OpenID Connect: the "CRM"

| Setting | Value |
|---|---|
| Registration | Single tenant, redirect URI `https://jwt.ms` (Microsoft tool that displays a token: it stands in for the application) |
| Flow | ID token through the implicit flow — **demonstration only**; a real application uses the authorization code flow with PKCE |
| Group claim | Security groups, emitted as **`sAMAccountName`** (readable names of the synchronised groups) |
| Assignment required | **Yes**, Bob assigned |
| API permissions | `User.Read` only, **admin consent** granted |

Users cannot consent on their own to an application that requires assignment. This blocks *illicit consent grant* attacks (a fake "PDF reader" app asking users to accept access to their mail): every application is approved once by an administrator, with the minimum permissions.

### ID token received for Bob

| Claim | Value | Purpose |
|---|---|---|
| `iss` | the tenant | Who issued the token |
| `aud` | the CRM application ID | Who the token is for: a token issued for another application is rejected |
| `exp` − `iat` | ≈ 65 minutes | Validity |
| `nonce` | `12345` | Prevents replay |
| `preferred_username`, `name` | Bob Durand | **Authentication**: who signed in |
| `groups` | `GG_Compta`, `GG_APP_GESCOM_Ecritures`, `GG_APP_GESCOM_CreationFournisseurs`, **`GG_APP_CRM_Lecture`**, `DL_Partage-Compta_RW` | **Authorisation**: what the application lets him do |

End-to-end chain for `GG_APP_CRM_Lecture`: GLPI ticket 1 → approved by the CRM owner → recorded with an expiry → added in AD by the JML process → synchronised → present in the token. On the expiry date, the JML process removes it and it disappears from the next tokens.

`DL_Partage-Compta_RW` shows that Entra ID resolves **indirect** membership (AGDLP model: `GG_Compta` is a member of the domain local group).

## SAML 2.0: "PayFlow"

Gallery application *Microsoft Entra SAML Toolkit* (Microsoft test service provider), renamed `PayFlow (SAML demo)`.

| Setting | Value |
|---|---|
| Trust | Entra ID's **signing certificate** uploaded to the application: it accepts only assertions signed by this tenant and never sees a password |
| Entity ID / Reply URL (ACS) / Sign-on URL | Values provided by the application; the reply URL is the only address Entra ID sends the assertion to |
| NameID | Format **email address**, source `user.userprincipalname` (the application matches users on it) |
| Group claim | Security groups, `sAMAccountName` |
| Flow tested | **SP-initiated**: the user starts on the application, which redirects to Entra ID |

## Evidence: Bob's sign-in log

| Time | Application | Result | Code | Meaning |
|---|---|---|---|---|
| 11:02 | CRM | Interrupted | 50072 | Password accepted, MFA registration required (security defaults) |
| 11:07 | CRM | Failure | 90094 | Admin consent required |
| 11:12 | CRM | **Success** | 0 | OIDC SSO, token with groups |
| 11:14 | CRM | Failure | 50105 | Assignment removed: access **revoked** |
| 15:54 | PayFlow | **Success** | 0 | SAML SSO |

## Leaver propagation

Emma, disabled by the JML process on 16/11: in Entra ID, **Account enabled: No**, OU `Desactives`, employee ID `E1006`, manager unchanged. A single change in AD blocks her access to every SSO application.

## What a P1 licence would add

| Capability | Effect |
|---|---|
| Group-based application assignment | `GG_APP_CRM_*` assigned to the CRM: the JML process alone grants and revokes application access |
| Conditional Access | Replace security defaults with explicit policies (MFA by risk, location, device), excluding two cloud-only break-glass accounts |
| 30-day sign-in log retention | Free keeps 7 days: logs must be exported to a SIEM for investigations |

## Residual risks

| Risk | Mitigation |
|---|---|
| Agent on the DC with replication rights | Tier 0 handling; in production, a dedicated Tier 0 server and two agents for availability |
| Different identifiers on-premises and in the cloud (`.local`) | Routable UPN suffix |
| No cloud-only break-glass account | Two emergency accounts, long secrets stored offline, monitored sign-ins |
| Application access granted user by user | P1 group-based assignment |

## Lessons

- Validate on one object before enabling a synchronisation, as with the JML dry run.
- Authentication and authorisation are separate: Bob authenticated successfully and was still refused when no longer assigned (50105).
- Sign-in error codes are the access manager's first diagnostic tool.
- Synchronising identities also synchronises their mistakes: data quality comes first.
