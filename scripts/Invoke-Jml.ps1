#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Joiner-mover-leaver provisioning from the HR export to Active Directory.
.DESCRIPTION
    Compares the HR export (authoritative source) with Active Directory and applies
    the default access matrix (config\roles.csv):
      JOINER         creates the account and adds the role groups; rolls back on failure
      MOVER/UPDATE   updates job, department, OU and manager; removes the old role
                     groups BEFORE adding the new ones
      LEAVER         disables the account on the end date, resets its password,
                     removes its groups and moves it to OU Desactives
      PURGE          deletes disabled accounts after the retention period
      RECONCILE      links an existing account to its HR record (one-time, by name)
      ORPHAN         reports active accounts without an HR record (never deleted)
    Ad hoc access (grants\access-grants.csv): application access approved through a
    ticket is added on top of the role, checked (approver = application owner, no
    self-approval, maximum duration, SoD) and removed automatically when it expires.
    The segregation-of-duties matrix (config\sod-rules.csv) is checked before any
    change: a conflicting change is blocked and escalated.

    DRY RUN BY DEFAULT: nothing is changed in Active Directory without -Apply.
    Every run writes a CSV report in the reports folder.

    Runs as a member of GG_ROLE_IAM (see New-JmlStructure.ps1), never as Tier 0.
.EXAMPLE
    .\Invoke-Jml.ps1            # dry run: report of planned changes only
.EXAMPLE
    .\Invoke-Jml.ps1 -Apply     # apply the changes
#>
[CmdletBinding()]
param(
    [string]$HrFile       = "$PSScriptRoot\..\data\hr-export.csv",
    [string]$ConfigPath   = "$PSScriptRoot\..\config",
    [string]$ReportFolder = "$PSScriptRoot\..\reports",
    [string]$GrantsFile   = "$PSScriptRoot\..\grants\access-grants.csv",
    [int]$RetentionDays   = 30,
    [int]$MaxGrantDays    = 90,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$today      = (Get-Date).Date
$inv        = [Globalization.CultureInfo]::InvariantCulture
$domain     = Get-ADDomain
$root       = "OU=COMPANY,$($domain.DistinguishedName)"
$usersOU    = "OU=Utilisateurs,$root"
$disabledOU = "OU=Desactives,$root"
$mode       = if ($Apply) { 'APPLY' } else { 'DRY-RUN' }
$report     = New-Object System.Collections.Generic.List[object]

#region Helpers

function Add-Report($EmployeeID, $Account, $Action, $Detail, $Result) {
    $report.Add([pscustomobject]@{
        Timestamp  = Get-Date -Format 's'
        Mode       = $mode
        EmployeeID = $EmployeeID
        Account    = $Account
        Action     = $Action
        Detail     = $Detail
        Result     = $Result
    })
}

# Runs a change only with -Apply; returns the result for the report.
function Invoke-Change([scriptblock]$Change) {
    if (-not $Apply) { return 'PLANNED' }
    try   { & $Change | Out-Null; 'DONE' }
    catch { "ERROR: $($_.Exception.Message)" }
}

function ConvertTo-Ascii([string]$Text) {
    $decomposed = $Text.Normalize([Text.NormalizationForm]::FormD)
    -join ($decomposed.ToCharArray() | Where-Object {
        [Globalization.CharUnicodeInfo]::GetUnicodeCategory($_) -ne 'NonSpacingMark'
    })
}

function New-SamAccountName([string]$First, [string]$Last) {
    $base = ((ConvertTo-Ascii $First) + '.' + (ConvertTo-Ascii $Last)).ToLower() -replace '[^a-z0-9.\-]', ''
    if ($base.Length -gt 18) { $base = $base.Substring(0, 18) }   # sAMAccountName: 20 characters max
    $sam = $base
    $i = 2
    while (Get-ADUser -Filter "SamAccountName -eq '$sam'") { $sam = "$base$i"; $i++ }
    $sam
}

# Random password, never displayed nor logged. First logon goes through the
# service desk (identity check, then reset with change at next logon).
function New-RandomPassword {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%*-_=+'
    $bytes = New-Object byte[] 24
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $plain = 'Aa1!' + (-join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] }))
    ConvertTo-SecureString -String $plain -AsPlainText -Force
}

function Get-ManagerDN([string]$ManagerID) {
    if (-not $ManagerID) { return $null }
    # Business accounts only: administrative accounts carry their owner's employee ID too
    $m = @(Get-ADUser -Filter "EmployeeID -eq '$ManagerID'" -SearchBase $usersOU)
    if ($m.Count -eq 1) { $m[0].DistinguishedName } else { $null }
}

function Get-UserGroups($User) {
    @($User.MemberOf | ForEach-Object {
        if ($groupName.ContainsKey($_)) { $groupName[$_] } else { ($_ -split ',')[0] -replace '^CN=' }
    })
}

function Test-Sod([string[]]$Groups) {
    foreach ($r in $sodRules) {
        if ($Groups -contains $r.GroupA -and $Groups -contains $r.GroupB) {
            "$($r.Rule): $($r.GroupA) + $($r.GroupB) ($($r.Risk))"
        }
    }
}

#endregion

#region Lifecycle actions

function Invoke-Joiner($P, $Role) {
    $sod = @(Test-Sod $Role.Groups)
    if ($sod) {
        Add-Report $P.ID '' 'SOD_VIOLATION' ($sod -join ' | ') 'BLOCKED: role definition conflicts with the SoD matrix'
        return
    }
    $sam    = New-SamAccountName $P.First $P.Last
    $detail = "role $($P.Role); groups: $($Role.Groups -join ', '); OU $($Role.OU)"
    if (-not $Apply) { Add-Report $P.ID $sam 'JOINER' $detail 'PLANNED'; return }

    try {
        $params = @{
            Name                  = "$($P.First) $($P.Last)"
            GivenName             = $P.First
            Surname               = $P.Last
            DisplayName           = "$($P.First) $($P.Last)"
            SamAccountName        = $sam
            UserPrincipalName     = "$sam@$($domain.DNSRoot)"
            EmployeeID            = $P.ID
            Title                 = $Role.Title
            Department            = $Role.Department
            Path                  = $Role.OU
            AccountPassword       = New-RandomPassword
            ChangePasswordAtLogon = $true
            Enabled               = $false      # enabled only once fully provisioned
        }
        $mgr = Get-ManagerDN $P.ManagerID
        if ($mgr) { $params.Manager = $mgr }

        New-ADUser @params
        foreach ($g in $Role.Groups) { Add-ADGroupMember -Identity $g -Members $sam }
        Enable-ADAccount -Identity $sam
        Add-Report $P.ID $sam 'JOINER' $detail 'DONE'
    }
    catch {
        # Rollback: New-ADUser creates the object BEFORE setting the password, so a
        # failure can leave a half-created account (incident 01, finding 4).
        $msg  = $_.Exception.Message
        $half = Get-ADUser -Filter "SamAccountName -eq '$sam'" -Properties EmployeeID
        if ($half -and $half.EmployeeID -eq $P.ID) {
            Remove-ADUser -Identity $half -Confirm:$false
            $msg += ' | rolled back: partially created account deleted'
        }
        Add-Report $P.ID $sam 'JOINER' $detail "ERROR: $msg"
    }
}

function Invoke-Update($P, $Role, $User) {
    $sam     = $User.SamAccountName
    $current = Get-UserGroups $User
    $adhoc   = @($current | Where-Object { $managedGroups -notcontains $_ })
    $target  = @($Role.Groups)

    # Ad hoc grants on top of the role: each one is SoD-checked on its own
    $grantInfo = @{}
    $myGrants  = if ($grants.ContainsKey($P.ID)) { $grants[$P.ID] } else { @() }
    foreach ($gr in $myGrants) {
        if ($target -contains $gr.Group) { continue }
        $conflict = @(Test-Sod ($target + $adhoc + $gr.Group))
        if ($conflict) {
            Add-Report $P.ID $sam 'GRANT_SOD_CONFLICT' "ticket $($gr.Ticket), $($gr.Group): $($conflict -join ' | ')" 'REJECTED'
            continue
        }
        $target += $gr.Group
        $grantInfo[$gr.Group] = "ticket $($gr.Ticket), until $($gr.ExpiresOn)"
    }
    $expiredInfo = if ($expired.ContainsKey($P.ID)) { $expired[$P.ID] } else { @{} }

    # SoD check on the resulting rights: new role groups + ad hoc rights kept
    $sod = @(Test-Sod ($target + $adhoc))
    if ($sod) {
        Add-Report $P.ID $sam 'SOD_VIOLATION' ($sod -join ' | ') 'BLOCKED: no change applied, escalate to the application owner'
        return
    }

    $toRemove   = @($current | Where-Object { $managedGroups -contains $_ -and $target -notcontains $_ })
    $toAdd      = @($target  | Where-Object { $current -notcontains $_ })
    $ouChange   = $User.DistinguishedName -notlike "*,$($Role.OU)"
    $attrChange = ($User.Title -ne $Role.Title) -or ($User.Department -ne $Role.Department)
    $managerDN  = Get-ManagerDN $P.ManagerID
    $mgrChange  = $managerDN -and ($User.Manager -ne $managerDN)

    if (-not ($toRemove -or $toAdd -or $ouChange -or $attrChange -or $mgrChange)) {
        Add-Report $P.ID $sam 'NO_CHANGE' "role $($P.Role)" 'OK'
        return
    }

    $action = if ($User.Title -and $User.Title -ne $Role.Title) { 'MOVER' } else { 'UPDATE' }
    $detail = @()
    if ($User.Title -ne $Role.Title) { $detail += "title '$($User.Title)' -> '$($Role.Title)'" }
    if ($toRemove)  { $detail += 'remove: ' + (($toRemove | ForEach-Object { if ($expiredInfo.ContainsKey($_)) { "$_ ($($expiredInfo[$_]))" } else { $_ } }) -join ', ') }
    if ($toAdd)     { $detail += 'add: ' + (($toAdd | ForEach-Object { if ($grantInfo.ContainsKey($_)) { "$_ ($($grantInfo[$_]))" } else { $_ } }) -join ', ') }
    if ($ouChange)  { $detail += "move to $($Role.OU)" }
    if ($mgrChange) { $detail += 'manager updated' }

    $result = Invoke-Change {
        Set-ADUser -Identity $User -Title $Role.Title -Department $Role.Department
        if ($managerDN) { Set-ADUser -Identity $User -Manager $managerDN }
        # old rights removed BEFORE new ones are added: no window with both
        foreach ($g in $toRemove) { Remove-ADGroupMember -Identity $g -Members $User -Confirm:$false }
        foreach ($g in $toAdd)    { Add-ADGroupMember -Identity $g -Members $User }
        if ($ouChange) { Move-ADObject -Identity $User.DistinguishedName -TargetPath $Role.OU }
    }
    Add-Report $P.ID $sam $action ($detail -join '; ') $result
}

function Invoke-Leaver($P, $User) {
    $sam     = $User.SamAccountName
    $groups  = Get-UserGroups $User
    $managed = @($groups | Where-Object { $managedGroups -contains $_ })
    $other   = @($groups | Where-Object { $managedGroups -notcontains $_ })
    $detail  = "end date $($P.End.ToString('yyyy-MM-dd')); groups removed: $($managed -join ', ')"

    $result = Invoke-Change {
        Disable-ADAccount -Identity $User                               # 1. cut access first
        Set-ADAccountPassword -Identity $User -Reset -NewPassword (New-RandomPassword)
        foreach ($g in $managed) { Remove-ADGroupMember -Identity $g -Members $User -Confirm:$false }
        Set-ADUser -Identity $User -Description ('Disabled by JML on {0}. Groups removed: {1}' -f $today.ToString('yyyy-MM-dd'), ($managed -join ', '))
        Move-ADObject -Identity $User.DistinguishedName -TargetPath $disabledOU
    }
    Add-Report $P.ID $sam 'LEAVER' $detail $result

    if ($other) {
        Add-Report $P.ID $sam 'MANUAL_ACTION' "Groups outside the JML scope, to be removed by an administrator: $($other -join ', ')" 'PENDING'
    }

    # Administrative accounts linked to the same person (OU Admins, same employee ID):
    # outside the delegation of the JML process, they are disabled by a Tier 0 administrator
    $admins = @(Get-ADUser -Filter "EmployeeID -eq '$($P.ID)'" -SearchBase "OU=Admins,$root" | Where-Object Enabled)
    if ($admins) {
        Add-Report $P.ID $sam 'MANUAL_ACTION' "Administrative accounts of this person, to be disabled today by a Tier 0 administrator: $(($admins.SamAccountName) -join ', ')" 'PENDING'
    }
}

#endregion

#region Load configuration and HR data

$roles = @{}
foreach ($r in Import-Csv -Path "$ConfigPath\roles.csv" -Encoding UTF8) {
    $roles[$r.Role] = [pscustomobject]@{
        Title      = $r.Title
        Department = $r.Department
        OU         = "OU=$($r.OU),$usersOU"
        Groups     = @($r.Groups -split ';' | Where-Object { $_ })
    }
}
$sodRules      = @(Import-Csv -Path "$ConfigPath\sod-rules.csv" -Encoding UTF8)
$managedGroups = @($roles.Values | ForEach-Object { $_.Groups } | Sort-Object -Unique)
$groupName     = @{}
foreach ($g in $managedGroups) { $groupName[(Get-ADGroup -Identity $g).DistinguishedName] = $g }

$people = @()
$seen   = @{}
foreach ($row in Import-Csv -Path $HrFile -Encoding UTF8) {
    $id    = "$($row.EmployeeID)".Trim()
    $errs  = @()
    $start = [datetime]::MinValue
    $end   = [datetime]::MinValue
    if (-not $id)                       { $errs += 'missing EmployeeID' }
    elseif ($seen.ContainsKey($id))     { $errs += 'duplicate EmployeeID' }
    if (-not $roles.ContainsKey($row.Role)) { $errs += "unknown role '$($row.Role)'" }
    if (-not [datetime]::TryParseExact($row.StartDate, 'yyyy-MM-dd', $inv, 'None', [ref]$start)) { $errs += 'invalid StartDate' }
    if ($row.EndDate -and -not [datetime]::TryParseExact($row.EndDate, 'yyyy-MM-dd', $inv, 'None', [ref]$end)) { $errs += 'invalid EndDate' }
    if ($errs) { Add-Report $id '' 'INVALID_HR_RECORD' ($errs -join '; ') 'SKIPPED'; continue }

    $seen[$id] = $true
    $people += [pscustomobject]@{
        ID        = $id
        First     = $row.FirstName.Trim()
        Last      = $row.LastName.Trim()
        Role      = $row.Role
        ManagerID = "$($row.ManagerID)".Trim()
        Start     = $start
        End       = if ($row.EndDate) { $end } else { $null }
    }
}

# Ad hoc grants: application access approved by the application owner through a ticket
$owners  = @(Import-Csv -Path "$ConfigPath\app-owners.csv" -Encoding UTF8)
$grants  = @{}
$expired = @{}
if (Test-Path $GrantsFile) {
    foreach ($g in Import-Csv -Path $GrantsFile -Encoding UTF8) {
        $errs    = @()
        $granted = [datetime]::MinValue
        $expires = [datetime]::MinValue
        $owner   = $owners | Where-Object { $g.Group -like "$($_.GroupPrefix)*" } | Select-Object -First 1
        if (-not $g.Ticket) { $errs += 'missing ticket reference' }
        if (-not $owner) {
            $errs += 'not an application group: only application access can be granted on request'
        } elseif ($managedGroups -notcontains $g.Group) {
            $errs += 'unknown application group'
        } elseif ($g.ApproverID -ne $owner.OwnerEmployeeID) {
            $errs += "approver $($g.ApproverID) is not the owner of $($owner.Application) ($($owner.OwnerEmployeeID))"
        }
        if ($g.ApproverID -eq $g.EmployeeID) { $errs += 'self-approval' }
        if (-not [datetime]::TryParseExact($g.GrantedOn, 'yyyy-MM-dd', $inv, 'None', [ref]$granted)) { $errs += 'invalid GrantedOn' }
        if (-not [datetime]::TryParseExact($g.ExpiresOn, 'yyyy-MM-dd', $inv, 'None', [ref]$expires)) { $errs += 'invalid ExpiresOn' }
        elseif ($expires -gt $granted.AddDays($MaxGrantDays)) { $errs += "duration above $MaxGrantDays days" }

        if ($errs) {
            Add-Report $g.EmployeeID '' 'INVALID_GRANT' "ticket $($g.Ticket), $($g.Group): $($errs -join '; ')" 'REJECTED'
            continue
        }
        if ($expires -lt $today) {
            if (-not $expired.ContainsKey($g.EmployeeID)) { $expired[$g.EmployeeID] = @{} }
            $expired[$g.EmployeeID][$g.Group] = "ticket $($g.Ticket) expired on $($g.ExpiresOn)"
            continue
        }
        if ($granted -gt $today) { continue }
        if (-not $grants.ContainsKey($g.EmployeeID)) { $grants[$g.EmployeeID] = @() }
        $grants[$g.EmployeeID] += $g
    }
}

$props   = 'EmployeeID', 'Title', 'Department', 'Manager', 'MemberOf', 'Description', 'adminCount'
$adUsers = @(Get-ADUser -Filter * -SearchBase $usersOU    -Properties $props) +
           @(Get-ADUser -Filter * -SearchBase $disabledOU -Properties $props)
$byId    = @{}
foreach ($u in $adUsers) { if ($u.EmployeeID) { $byId[$u.EmployeeID] = $u } }
$matched = @{}

#endregion

#region Reconciliation: HR -> AD

foreach ($p in $people) {
    $role = $roles[$p.Role]
    $user = $byId[$p.ID]

    # One-time link of accounts created before the HR source was connected.
    # Matching by name is only acceptable here, and is flagged for validation.
    if (-not $user) {
        $cand = @($adUsers | Where-Object { -not $_.EmployeeID -and $_.GivenName -eq $p.First -and $_.Surname -eq $p.Last })
        if ($cand.Count -eq 1) {
            $user = $cand[0]
            $id   = $p.ID
            $r    = Invoke-Change { Set-ADUser -Identity $user -EmployeeID $id }
            Add-Report $p.ID $user.SamAccountName 'RECONCILE' 'Existing account linked to its HR record by name: to be validated by the access manager' $r
        }
        elseif ($cand.Count -gt 1) {
            Add-Report $p.ID '' 'RECONCILE' "$($cand.Count) accounts match '$($p.First) $($p.Last)': manual decision required" 'SKIPPED'
            continue
        }
    }
    if ($user) { $matched[$user.DistinguishedName] = $true }
    $sam = if ($user) { $user.SamAccountName } else { '' }

    if ($p.Start -gt $today) {
        Add-Report $p.ID $sam 'PENDING' "Starts on $($p.Start.ToString('yyyy-MM-dd'))" 'SKIPPED'
        continue
    }
    if ($user -and $user.adminCount -eq 1) {
        Add-Report $p.ID $sam 'PROTECTED' 'Member (or former member) of a privileged group: handled manually' 'SKIPPED'
        continue
    }

    $isLeaver = $p.End -and $p.End -le $today
    if ($isLeaver) {
        if ($user -and $user.Enabled) { Invoke-Leaver $p $user }
        continue
    }
    if (-not $user) { Invoke-Joiner $p $role; continue }
    if (-not $user.Enabled) {
        Add-Report $p.ID $sam 'REHIRE' 'Active in HR but account disabled: manual review, never re-enabled automatically' 'SKIPPED'
        continue
    }
    Invoke-Update $p $role $user
}

#endregion

#region AD -> HR: orphans and purge

$activeIds = @{}
foreach ($p in $people) { if (-not ($p.End -and $p.End -le $today)) { $activeIds[$p.ID] = $true } }

foreach ($u in $adUsers) {
    $inDisabledOU = $u.DistinguishedName -like "*,$disabledOU"

    if ($inDisabledOU -and -not $u.Enabled -and -not $activeIds.ContainsKey("$($u.EmployeeID)") -and
        $u.Description -match 'Disabled by JML on (\d{4}-\d{2}-\d{2})') {
        $disabledOn = [datetime]::ParseExact($Matches[1], 'yyyy-MM-dd', $inv)
        if ($disabledOn.AddDays($RetentionDays) -le $today) {
            $target = $u
            $r = Invoke-Change { Remove-ADUser -Identity $target -Confirm:$false }
            Add-Report $u.EmployeeID $u.SamAccountName 'PURGE' "Disabled on $($Matches[1]), retention of $RetentionDays days exceeded" $r
        }
        continue
    }

    if (-not $matched.ContainsKey($u.DistinguishedName) -and -not $inDisabledOU -and $u.Enabled) {
        Add-Report $u.EmployeeID $u.SamAccountName 'ORPHAN' 'Active account with no HR record: owner to be identified, never deleted automatically' 'REVIEW'
    }
}

#endregion

#region Report

New-Item -ItemType Directory -Path $ReportFolder -Force | Out-Null
$file = Join-Path $ReportFolder ('jml-{0}-{1}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $mode.ToLower())
$report | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8

$report | Format-Table EmployeeID, Account, Action, Result, Detail -AutoSize -Wrap
Write-Host "Mode: $mode - $($report.Count) line(s) - report: $file"
if (-not $Apply) { Write-Host 'Dry run: nothing was changed. Run again with -Apply to apply.' -ForegroundColor Yellow }

#endregion
