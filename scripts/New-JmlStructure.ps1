#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    One-time setup for the joiner-mover-leaver process: OUs, role groups and
    least-privilege delegation.
.DESCRIPTION
    Run once by a Tier 0 administrator. Idempotent: existing objects are kept.
    The JML script itself never runs with Tier 0 rights: it runs as a member of
    GG_ROLE_IAM, which only receives the rights granted here:
      - create, update, disable, move and delete user accounts in OU Utilisateurs
        and OU Desactives (no other object type, no other OU);
      - change the membership of the business role groups listed in roles.csv
        (never of privileged groups such as Domain Admins or GG_ROLE_*).
#>
[CmdletBinding()]
param(
    [string]$ConfigPath = "$PSScriptRoot\..\config"
)

$ErrorActionPreference = 'Stop'
$domain   = Get-ADDomain
$root     = "OU=COMPANY,$($domain.DistinguishedName)"
$usersOU  = "OU=Utilisateurs,$root"
$groupsOU = "OU=Groupes,$root"
$iam      = "$($domain.NetBIOSName)\GG_ROLE_IAM"

function New-OUIfMissing([string]$Name, [string]$Path) {
    $dn = "OU=$Name,$Path"
    if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'") {
        Write-Host "  exists  $dn"
    } else {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $true
        Write-Host "  created $dn" -ForegroundColor Green
    }
    $dn
}

function New-GroupIfMissing([string]$Name, [string]$Description) {
    if (Get-ADGroup -Filter "Name -eq '$Name'") {
        Write-Host "  exists  $Name"
    } else {
        New-ADGroup -Name $Name -GroupScope Global -GroupCategory Security -Path $groupsOU -Description $Description
        Write-Host "  created $Name" -ForegroundColor Green
    }
}

function Grant-Ace([string]$Target, [string[]]$Arguments) {
    $out = & dsacls.exe $Target @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "dsacls failed on $Target : $out" }
    Write-Host "  granted $($Arguments -join ' ') on $Target"
}

$roles = Import-Csv -Path "$ConfigPath\roles.csv" -Encoding UTF8

Write-Host "Organisational units"
$roles.OU | Sort-Object -Unique | ForEach-Object { New-OUIfMissing $_ $usersOU | Out-Null }
$disabledOU = New-OUIfMissing 'Desactives' $root

Write-Host "Role groups"
$groups = $roles | ForEach-Object { $_.Groups -split ';' } | Where-Object { $_ } | Sort-Object -Unique
foreach ($g in $groups) {
    New-GroupIfMissing $g 'Business role group: membership managed by the JML process only'
}
New-GroupIfMissing 'GG_ROLE_IAM' 'Delegated: runs the JML process (user accounts and business group membership only)'

Write-Host "Delegation to GG_ROLE_IAM"
foreach ($ou in @($usersOU, $disabledOU)) {
    # create and delete user objects in the OU and its sub-OUs
    Grant-Ace $ou @('/I:T', '/G', "${iam}:CCDC;user")
    # read/write user attributes and reset passwords, on user objects only
    Grant-Ace $ou @('/I:S', '/G', "${iam}:RPWP;;user", "${iam}:CA;Reset Password;user")
}
foreach ($g in $groups) {
    # change the member attribute of business role groups only
    Grant-Ace (Get-ADGroup -Identity $g).DistinguishedName @('/G', "${iam}:RPWP;member")
}

Write-Host "Done." -ForegroundColor Green
