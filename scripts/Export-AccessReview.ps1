#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Access review campaign: exports every access right with its justification,
    and the findings to investigate. Read-only: changes nothing in Active Directory.
.DESCRIPTION
    For every account in OU Utilisateurs and OU Desactives, and every group it belongs to,
    the export states WHY the access exists and WHO must certify it:
      ROLE        granted by the default access matrix (roles.csv) for the HR role
      GRANT       ad hoc access approved through a ticket (access-grants.csv), with its expiry
      PRIVILEGED  administrative delegation (GG_ROLE_*, built-in admin groups): certified by the CISO
      UNEXPECTED  no justification found: to be explained or removed
    Reviewers:
      application groups (GG_APP_*)   the application owner (app-owners.csv)
      department and other groups     the person's manager
      privileged groups               the CISO
    Findings: orphan accounts, HR / directory mismatches, inactive accounts, SoD conflicts,
    unexpected access, grants expiring soon, privileged memberships, admin accounts
    without a recorded owner.
.EXAMPLE
    .\Export-AccessReview.ps1
#>
[CmdletBinding()]
param(
    [string]$HrFile       = "$PSScriptRoot\..\data\hr-export.csv",
    [string]$ConfigPath   = "$PSScriptRoot\..\config",
    [string]$GrantsFile   = "$PSScriptRoot\..\grants\access-grants.csv",
    [string]$ReportFolder = "$PSScriptRoot\..\reports",
    [int]$InactiveDays    = 90,
    [int]$ExpiringDays    = 30
)

$ErrorActionPreference = 'Stop'
$today    = (Get-Date).Date
$inv      = [Globalization.CultureInfo]::InvariantCulture
$domain   = Get-ADDomain
$root     = "OU=COMPANY,$($domain.DistinguishedName)"
$stamp    = Get-Date -Format 'yyyyMMdd'
$rights   = New-Object System.Collections.Generic.List[object]
$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding($Severity, $Type, $Account, $Detail, $Owner) {
    $findings.Add([pscustomobject]@{ Severity = $Severity; Type = $Type; Account = $Account; Detail = $Detail; Reviewer = $Owner })
}
function ConvertFrom-IsoDate([string]$Text) {
    $d = [datetime]::MinValue
    if ($Text -and [datetime]::TryParseExact($Text, 'yyyy-MM-dd', $inv, 'None', [ref]$d)) { $d } else { $null }
}
function Get-CN([string]$DN) { ($DN -split ',')[0] -replace '^CN=' }

#region Reference data

$roles = @{}
foreach ($r in Import-Csv "$ConfigPath\roles.csv" -Encoding UTF8) {
    $roles[$r.Role] = @($r.Groups -split ';' | Where-Object { $_ })
}
$owners   = @(Import-Csv "$ConfigPath\app-owners.csv" -Encoding UTF8)
$sodRules = @(Import-Csv "$ConfigPath\sod-rules.csv" -Encoding UTF8)

$hr = @{}
foreach ($p in Import-Csv $HrFile -Encoding UTF8) {
    $end = ConvertFrom-IsoDate $p.EndDate
    $hr[$p.EmployeeID] = [pscustomobject]@{
        Role   = $p.Role
        Status = if ($end -and $end -le $today) { 'LEFT' } elseif ((ConvertFrom-IsoDate $p.StartDate) -gt $today) { 'FUTURE' } else { 'ACTIVE' }
    }
}

$grants = @{}
if (Test-Path $GrantsFile) {
    foreach ($g in Import-Csv $GrantsFile -Encoding UTF8) {
        $exp = ConvertFrom-IsoDate $g.ExpiresOn
        if ($exp -and $exp -ge $today) { $grants["$($g.EmployeeID)|$($g.Group)"] = $g }
    }
}

$privilegedNames = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
                     'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators',
                     'Group Policy Creator Owners')

#endregion

#region Rights of business accounts

$props = 'EmployeeID', 'Title', 'MemberOf', 'Manager', 'LastLogonTimestamp', 'whenCreated'
$users = @(Get-ADUser -Filter * -SearchBase "OU=Utilisateurs,$root" -Properties $props) +
         @(Get-ADUser -Filter * -SearchBase "OU=Desactives,$root"   -Properties $props)

foreach ($u in $users) {
    $person   = if ($u.EmployeeID -and $hr.ContainsKey($u.EmployeeID)) { $hr[$u.EmployeeID] } else { $null }
    $expected = if ($person -and $roles.ContainsKey($person.Role)) { $roles[$person.Role] } else { @() }
    $manager  = if ($u.Manager) { Get-CN $u.Manager } else { '(no manager)' }
    $groups   = @($u.MemberOf | ForEach-Object { Get-CN $_ })

    # Lifecycle checks
    if (-not $person) {
        if ($u.Enabled) { Add-Finding 'High' 'ORPHAN' $u.SamAccountName 'Enabled account with no HR record' 'Access manager' }
    } elseif ($person.Status -eq 'LEFT' -and $u.Enabled) {
        Add-Finding 'High' 'LEAVER_STILL_ENABLED' $u.SamAccountName 'Left the company according to HR, account still enabled' 'Access manager'
    } elseif ($person.Status -eq 'ACTIVE' -and -not $u.Enabled) {
        Add-Finding 'Medium' 'ACTIVE_BUT_DISABLED' $u.SamAccountName 'Active in HR, account disabled' 'Access manager'
    }

    $lastLogon = if ($u.LastLogonTimestamp) { [datetime]::FromFileTime($u.LastLogonTimestamp) } else { $null }
    if ($u.Enabled) {
        if (-not $lastLogon -and $u.whenCreated -lt $today.AddDays(-7)) {
            Add-Finding 'Low' 'NEVER_USED' $u.SamAccountName "Enabled since $($u.whenCreated.ToString('yyyy-MM-dd')), never logged on" $manager
        } elseif ($lastLogon -and $lastLogon -lt $today.AddDays(-$InactiveDays)) {
            Add-Finding 'Medium' 'INACTIVE' $u.SamAccountName "Last logon $($lastLogon.ToString('yyyy-MM-dd'))" $manager
        }
    }

    # One line per right, with its justification and reviewer
    foreach ($g in $groups) {
        $owner = $owners | Where-Object { $g -like "$($_.GroupPrefix)*" } | Select-Object -First 1
        $key   = "$($u.EmployeeID)|$g"
        if ($privilegedNames -contains $g -or $g -like 'GG_ROLE_*') {
            $source = 'PRIVILEGED'; $reviewer = 'CISO'; $detail = 'Administrative delegation'
        } elseif ($expected -contains $g) {
            $source = 'ROLE'; $detail = "Default access for role $($person.Role)"
            $reviewer = if ($owner) { "$($owner.Application) owner ($($owner.OwnerEmployeeID))" } else { $manager }
        } elseif ($grants.ContainsKey($key)) {
            $gr = $grants[$key]; $source = 'GRANT'
            $detail = "Ticket $($gr.Ticket), approved by $($gr.ApproverID), expires $($gr.ExpiresOn)"
            $reviewer = if ($owner) { "$($owner.Application) owner ($($owner.OwnerEmployeeID))" } else { $manager }
            if ((ConvertFrom-IsoDate $gr.ExpiresOn) -le $today.AddDays($ExpiringDays)) {
                Add-Finding 'Info' 'GRANT_EXPIRING' $u.SamAccountName "$g, ticket $($gr.Ticket), expires $($gr.ExpiresOn): renew through a new request or let it expire" $reviewer
            }
        } else {
            $source = 'UNEXPECTED'; $detail = 'No role, grant or delegation justifies this access'
            $reviewer = if ($owner) { "$($owner.Application) owner ($($owner.OwnerEmployeeID))" } else { $manager }
            Add-Finding 'High' 'UNEXPECTED_ACCESS' $u.SamAccountName "${g}: $detail" $reviewer
        }
        if ($source -eq 'PRIVILEGED') {
            Add-Finding 'Info' 'PRIVILEGED_ACCESS' $u.SamAccountName "$g held by a business account" 'CISO'
        }
        $rights.Add([pscustomobject]@{
            EmployeeID = $u.EmployeeID; Account = $u.SamAccountName; Enabled = $u.Enabled
            HRStatus   = if ($person) { $person.Status } else { 'NO HR RECORD' }
            Group      = $g; Source = $source; Justification = $detail; Reviewer = $reviewer
            Decision   = ''; Comment = ''
        })
    }

    foreach ($r in $sodRules) {
        if ($groups -contains $r.GroupA -and $groups -contains $r.GroupB) {
            Add-Finding 'Critical' 'SOD_CONFLICT' $u.SamAccountName "$($r.Rule): $($r.GroupA) + $($r.GroupB) ($($r.Risk))" 'Application owner + CISO'
        }
    }
}

#endregion

#region Administrative accounts and privileged groups

foreach ($a in Get-ADUser -Filter * -SearchBase "OU=Admins,$root" -Properties Manager, EmployeeID, Description, MemberOf) {
    if (-not $a.Manager -and -not $a.EmployeeID) {
        Add-Finding 'Medium' 'ADMIN_WITHOUT_OWNER' $a.SamAccountName 'Administrative account not linked to its owner (Manager or EmployeeID empty)' 'CISO'
    }
}

foreach ($name in $privilegedNames) {
    $grp = Get-ADGroup -Filter "Name -eq '$name'" -ErrorAction SilentlyContinue
    if (-not $grp) { continue }
    $members = @(Get-ADGroupMember -Identity $grp | Select-Object -ExpandProperty SamAccountName)
    if ($members.Count -gt 0 -and $name -in @('Enterprise Admins', 'Schema Admins')) {
        Add-Finding 'High' 'STANDING_PRIVILEGE' ($members -join ', ') "$name should be empty outside planned operations" 'CISO'
    }
    foreach ($m in $members) {
        $rights.Add([pscustomobject]@{
            EmployeeID = ''; Account = $m; Enabled = ''; HRStatus = 'ADMIN'
            Group = $name; Source = 'PRIVILEGED'; Justification = 'Built-in privileged group'; Reviewer = 'CISO'
            Decision = ''; Comment = ''
        })
    }
}

#endregion

#region Output

New-Item -ItemType Directory -Path $ReportFolder -Force | Out-Null
$rightsFile   = Join-Path $ReportFolder "access-review-$stamp-rights.csv"
$findingsFile = Join-Path $ReportFolder "access-review-$stamp-findings.csv"
$rights   | Export-Csv $rightsFile   -NoTypeInformation -Encoding UTF8
$sevOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
$findings | Sort-Object { $sevOrder[$_.Severity] }, Type | Export-Csv $findingsFile -NoTypeInformation -Encoding UTF8

Write-Host "`nRights by source"
$rights | Group-Object Source | Sort-Object Name | Format-Table Count, Name -AutoSize
Write-Host "Findings"
$findings | Sort-Object { $sevOrder[$_.Severity] }, Type | Format-Table Severity, Type, Account, Detail, Reviewer -AutoSize -Wrap
Write-Host "Rights to certify: $rightsFile"
Write-Host "Findings:          $findingsFile"

#endregion
