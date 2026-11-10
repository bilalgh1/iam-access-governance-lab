# Incident 01 — A user account disappeared without a trace

**Type**: real, discovered during phase 2 · **Status**: closed, root cause undetermined

## Detection

While setting up the service desk delegation, adding `david.moreau` (IT) to the new `GG_ROLE_ServiceDesk` group failed:

```
Add-ADGroupMember : Cannot find an object with identity: 'david.moreau'
```

The account had been created ten days earlier by the user provisioning script, and its presence had been verified at the time.

An identity disappearing without any decision is an incident: before recreating it, the account was investigated. Recreating it blindly would give it a **new SID**, losing any right tied to the old one, and the cause would never be understood.

## Investigation

| # | Hypothesis | Check | Result |
|---|---|---|---|
| 1 | Renamed or moved | Search the whole domain by surname | Not found |
| 2 | Deleted (recoverable) | Search the AD Recycle Bin by `sAMAccountName`, then list the whole `Deleted Objects` container | Not found; the container is empty |
| 3 | Deletion logged | Security log: events 4720 (created) and 4726 (deleted) | Creation logged on 25/10 by `Administrator`; **no deletion event** |
| 4 | Log overwritten | Size and oldest entry of the Security log | 128 MB, reaches back to the DC installation: nothing overwritten |
| 5 | Renamed (the SID never changes) | SID extracted from the 4720 event, object searched by SID including deleted objects | **No object with this SID**, under any form |
| 6 | Any other change | Every Security event mentioning the account name or SID | Only the creation sequence (4720, 4738, 4724, 4722, 4728), all within the same second |

```powershell
$evt = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720} | Where-Object { $_.Message -match 'david.moreau' }
$sid = (([xml]$evt.ToXml()).Event.EventData.Data | Where-Object Name -eq 'TargetSid').'#text'
Get-ADObject -Filter "objectSid -eq '$sid'" -IncludeDeletedObjects
Get-WinEvent -LogName Security | Where-Object { $_.Message -match 'david.moreau' -or $_.Message -match [regex]::Escape($sid) }
```

## Conclusion

The account no longer exists in the directory database in any form, and nothing in the current logs explains its removal. **The root cause cannot be determined with the available evidence.** Rather than guessing, the incident is closed with that conclusion and the gaps it revealed.

## Findings

| # | Finding | Link to the baseline audit | Remediation |
|---|---|---|---|
| 1 | Directory changes are not fully audited: only account management events are recorded, not changes to directory objects (5136, 5137, 5141) | A-AuditDC | ✅ Done: advanced audit policy and directory SACL, see [04](../04-audit-and-traceability.md) |
| 2 | Every administrative action was performed with the generic built-in `Administrator` account: even with an event, *who* acted could not be established | P-AdminLogin | ✅ Done: named admin accounts, see [03](../03-privileged-accounts-and-delegation.md) |
| 3 | Security logs are only stored on the DC, where they can be altered or lost | — | Forward logs in real time to a central SIEM managed separately |
| 4 | A failed account creation (password policy) left a half-created, disabled account in a group | — | Provisioning must verify the result and roll back on failure (phase 3) |

## Recovery

The account was recreated with a new SID and re-added to its groups through the normal process.

## Lessons

- Before recreating a missing identity, investigate: the SID is the only attribute that never changes, and the best search key.
- An investigation can only go as far as the logs allow. Traceability must be designed **before** an incident.
- Stating "root cause undetermined" with documented evidence is better than an unproven explanation.
