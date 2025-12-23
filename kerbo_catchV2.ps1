<#
.SYNOPSIS
KerboCatch v2: Unified Security log triage (CSV or Live) using a normalized event object stream and a detection filter.

.DESCRIPTION
KerboCatch v2 is an interactive Security log triage script with two modes:

MODE 1: Import-CSV
- Prompts for a CSV path and validates it exists.
- Imports the CSV and expects a JSON "Payload" field containing EventData.
- Normalizes each row into a single [PSCustomObject] schema (EventID, User, TargetUser, ServiceName, Domain, Encryption, etc.).
- Pipes each normalized object into Invoke-DetectionLogic for streaming detections.

MODE 2: Live System Triage
- Prompts for StartDate and EndDate in the format: 'YYYY-MM-DD HH:MM:SS'
- Queries the local Security event log with Get-WinEvent using a FilterHashtable.
- Normalizes each event’s XML into the same [PSCustomObject] schema used in CSV mode.
- Pipes each normalized object into Invoke-DetectionLogic for streaming detections.

DETECTION PIPELINE DESIGN
This script is intentionally split into two stages:
1) Normalization stage: build a consistent [PSCustomObject] for every event (same fields in both modes).
2) Detection stage: Invoke-DetectionLogic (a filter) acts like a specialized Where-Object that evaluates each object and prints findings.

DETECTIONS (Invoke-DetectionLogic)
1) Kerberoasting (4769)
   - TicketEncryptionType = 0x17 (heuristic for weak encryption)
   - Excludes machine accounts (*$), SYSTEM, and krbtgt
2) DCSync Attempt (4662)
   - AccessMask = 0x100 and excludes machine accounts (*$)
3) Golden Ticket Heuristic (4624 / 4672 / 4769)
   - Flags lowercase letters in Domain (regex [a-z]) as a heuristic indicator
4) AS-REP Roasting (4768)
   - PreAuthType = 0 (or 0x0) and TicketEncryptionType = 0x17
5) Sensitive Group Modification (4728 / 4732 / 4756)
   - Flags modifications involving: Domain Admins, Enterprise Admins, Administrators

OUTPUT
- Prints detections to the console as they are identified (streaming).
- Each detection banner includes key context like Row/RecordId, TimeCreated, Actor/User, TargetUser, ServiceName, SrcIP when available.

.PARAMETER Events
Not used as a direct parameter in v2. This script is pipeline-driven: normalized objects are piped to Invoke-DetectionLogic.

.PARAMETER csv_Path
Collected interactively when selecting option 1 (Import-CSV).

.PARAMETER StartDate
Collected interactively when selecting option 2 (Live System Triage).
Format: 'YYYY-MM-DD HH:MM:SS'

.PARAMETER EndDate
Collected interactively when selecting option 2 (Live System Triage).
Format: 'YYYY-MM-DD HH:MM:SS'

.EXAMPLE
PS> .\kerbo_catchV2.ps1
Select option 1, provide a CSV path, stream detections to the console.

.EXAMPLE
PS> .\kerbo_catchV2.ps1
Select option 2, provide StartDate/EndDate, triage local Security logs and stream detections.

.NOTES
CSV MODE EXPECTATIONS (typical columns)
- EventID
- TimeCreated
- RemoteHost (optional)
- Payload (JSON string containing EventData)
- RecordNumber (optional, used as Row when present)

LIVE MODE REQUIREMENTS
- Requires permission to read the local Security event log (often Admin).
- Time window must be valid; StartDate/EndDate are parsed with Get-Date.

LIMITATIONS / WARNINGS
- Some checks are heuristic (especially the Golden Ticket lowercase-domain indicator).
- Field mappings can vary by environment and event schema; validate key fields in your log source if results look off.

.LINK
https://attack.mitre.org/techniques/T1558/
https://attack.mitre.org/techniques/T1003/006/
#>


Write-Host "Select a Security Log Option to Triage: " -ForegroundColor Cyan
Write-Host "1. Import-CSV" -ForegroundColor Cyan
Write-Host "2. Live System Triage" -ForegroundColor Cyan

$userDecision = Read-Host "Select Options 1-2" 


switch ($userDecision) {
    1 {
        $csv_Path = (Read-Host "Path to CSV").Trim('"')
        if (-Not (Test-Path -Path $csv_Path)) { Write-Host "Invalid Path" -ForegroundColor Red; exit }
        $Mode = 'CSV'
    }
    2 {
        $StartDate = (Read-Host "Start Date (YYYY-MM-DD HH:MM:SS)")
        $EndDate = (Read-Host "End Date (YYYY-MM-DD HH:MM:SS)")
        $Mode = 'Live'
    }
    Default { Write-Host "Invalid Choice." ; exit }
}


filter Invoke-DetectionLogic {
    $Events = $_

    if ((($Events.EventID -eq 4769) -or ($Events.EventIdL -eq 4769)) -and $Events.Encryption -eq '0x17' -and 
        $Events.ServiceName -notlike '*$*' -and $Events.TargetUser -notlike '*$*' -and 
        $Events.TargetUser -notlike '*SYSTEM*' -and $Events.ServiceName -notmatch 'krbtgt') {
        
        Write-Host "CRITICAL: Kerberoasting Detected (Weak Encryption)" -ForegroundColor Red
        Write-Host "Row: $($Events.Row) | Time: $($Events.TimeCreated) | IP: $($Events.SrcIP) | User: $($Events.TargetUser) | Target Service: $($Events.ServiceName)"
        Write-Host "--------------------------------"

        [PSCustomObject]@{
            TimeCreated     = $Events.TimeCreated
            Detection       = "Kerberoasting"
            Severity        = "CRITICAL"
            Row             = $Events.Row
            IP              = $Events.SrcIP
            Actor           = $Events.User
            User            = $Events.TargetUser
            TargetService   = $Events.ServiceName
            Domain          = $Events.Domain
            Group           = ""
            Member          = ""
            RepRights       = ""
        }
    }

    $DCSyncGuidMap = @{
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes"
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All"
        "89e95b76-444d-4c62-991a-0facbeda640c" = "DS-Replication-Get-Changes-In-Filtered-Set"
    }

    if ((($Events.EventID -eq 4662) -or ($Events.EventIdL -eq 4662)) -and 
        $Events.AccessMask -eq '0x100' -and $Events.User -notlike '*$*') {

        $matched = foreach ($guid in $DCSyncGuidMap.Keys) {
            if ($Events.DCSyncGUID -like "*$guid*") {
                [PSCustomObject]@{
                    Guid    = $guid
                    Meaning = $DCSyncGuidMap[$guid]
                }
            }
        }

        if ($matched) {
            $repRights = (($matched | ForEach-Object { "$($_.Meaning) ($($_.Guid))" }) -join ", ")

            if ($matched.Count -ge 2) {
                Write-Host "CRITICAL: DCSync Attempt Detected" -ForegroundColor Red
                Write-Host "Row: $($Events.Row) | Time: $($Events.TimeCreated) | Actor: $($Events.User)"
                Write-Host ("Matched: " + $repRights)
                Write-Host "--------------------------------"

                [PSCustomObject]@{
                    TimeCreated     = $Events.TimeCreated
                    Detection       = "DC Sync"
                    Severity        = "CRITICAL"
                    Row             = $Events.Row
                    IP              = $Events.SrcIP
                    Actor           = $Events.User
                    User            = $Events.TargetUser
                    TargetService   = $Events.ServiceName
                    Domain          = $Events.Domain
                    Group           = ""
                    Member          = ""
                    RepRights       = $repRights
                }
            }
            else {
                Write-Host "WARN: Replication Right Observed" -ForegroundColor Yellow
                Write-Host "Row: $($Events.Row) | Time: $($Events.TimeCreated) | Actor: $($Events.User)"
                Write-Host ("Matched: " + $repRights)
                Write-Host "--------------------------------"

                [PSCustomObject]@{
                    TimeCreated     = $Events.TimeCreated
                    Detection       = "DC Sync"
                    Severity        = "WARN"
                    Row             = $Events.Row
                    IP              = $Events.SrcIP
                    Actor           = $Events.User
                    User            = $Events.TargetUser
                    TargetService   = $Events.ServiceName
                    Domain          = $Events.Domain
                    Group           = ""
                    Member          = ""
                    RepRights       = $repRights
                }
            }
        }
    }

    if ((($Events.EventID -in 4624,4672,4769) -or ($Events.EventIdL -in 4624,4672,4769)) -and 
        $Events.Domain -cmatch '[a-z]' -and $Events.TargetUser -notlike '*$*' -and
        $Events.TargetUser -notmatch 'DWM-|UMFD-') {

        Write-Host "WARNING: Golden Ticket Heuristic (Lowercase Domain)" -ForegroundColor Yellow
        Write-Host "Row: $($Events.Row) | Time: $($Events.TimeCreated) | Domain: $($Events.Domain) | User: $($Events.TargetUser)"
        Write-Host "--------------------------------"

        [PSCustomObject]@{
            TimeCreated     = $Events.TimeCreated
            Detection       = "Golden Ticket Heuristic"
            Severity        = "WARNING"
            Row             = $Events.Row
            IP              = $Events.SrcIP
            Actor           = $Events.User
            User            = $Events.TargetUser
            TargetService   = $Events.ServiceName
            Domain          = $Events.Domain
            Group           = ""
            Member          = ""
            RepRights       = ""
        }
    }

    if ((($Events.EventID -eq 4768) -or ($Events.EventIdL -eq 4768)) -and ($Events.PreAuthType -in '0','0x0') -and $Events.Encryption -eq '0x17') {
        Write-Host "CRITICAL: AS-REP Roasting Detected" -ForegroundColor Red
        Write-Host "Row: $($Events.Row) | Time: $($Events.TimeCreated) | User: $($Events.TargetUser)"
        Write-Host "--------------------------------"

        [PSCustomObject]@{
            TimeCreated     = $Events.TimeCreated
            Detection       = "AS-REP Roasting"
            Severity        = "CRITICAL"
            Row             = $Events.Row
            IP              = $Events.SrcIP
            Actor           = $Events.User
            User            = $Events.TargetUser
            TargetService   = $Events.ServiceName
            Domain          = $Events.Domain
            Group           = ""
            Member          = ""
            RepRights       = ""
        }
    }

    if ((($Events.EventID -in 4728,4732,4756) -or ($Events.EventIdL -in 4728,4732,4756)) -and 
        $Events.Group -match "Domain Admins|Enterprise Admins|Administrators") {

        Write-Host "CRITICAL: Sensitive Group Modification" -ForegroundColor Magenta
        Write-Host "Row: $($Events.Row) | Time: $($Events.TimeCreated) | Actor: $($Events.User) | Group: $($Events.Group) | Member: $($Events.Member)"
        Write-Host "--------------------------------"

        [PSCustomObject]@{
            TimeCreated     = $Events.TimeCreated
            Detection       = "Sensitive Group Modification"
            Severity        = "CRITICAL"
            Row             = $Events.Row
            IP              = $Events.SrcIP
            Actor           = $Events.User
            User            = $Events.TargetUser
            TargetService   = $Events.ServiceName
            Domain          = $Events.Domain
            Group           = $Events.Group
            Member          = $Events.Member
            RepRights       = ""
        }
    }
}




if ($Mode -eq 'CSV') {
    $detections = Import-Csv -Path $csv_Path | ForEach-Object {
        $json = $_.Payload | ConvertFrom-Json
        $data = $json.EventData.Data

        [PSCustomObject]@{
            Row = $_.RecordNumber
            EventID     = $_.EventID
            EventIdL = $_.EventId
            TimeCreated = $_.TimeCreated
            SrcIP       = ($_.RemoteHost -replace '^::ffff:', '' -replace ':\d+$', '')
            User        = ($data | Where-Object { $_.'@Name' -eq "SubjectUserName" }).'#text' # Actor
            TargetUser  = ($data | Where-Object { $_.'@Name' -eq "TargetUserName" }).'#text'
            ServiceName = ($data | Where-Object { $_.'@Name' -eq "ServiceName" }).'#text'
            Domain      = ($data | Where-Object { $_.'@Name' -eq "TargetDomainName" }).'#text'
            Encryption  = ($data | Where-Object { $_.'@Name' -eq "TicketEncryptionType" }).'#text'
            AccessMask  = ($data | Where-Object { $_.'@Name' -eq "AccessMask" }).'#text'
            PreAuthType = ($data | Where-Object { $_.'@Name' -eq "PreAuthType" }).'#text'
            Group       = ($data | Where-Object { $_.'@Name' -eq "TargetUserName" }).'#text'
            Member = ($data | Where-Object { $_.'@Name' -eq "MemberName" }).'#text' 
            DCSyncGUID = ($data | Where-Object { $_.'@Name' -eq "Properties"}).'#text'
        } | Invoke-DetectionLogic 
    
    } 
}

if ($Mode -eq 'Live') {

   $detections = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        StartTime = (Get-Date $StartDate)
        EndTime   = (Get-Date $EndDate)
        ID        = 4769, 4662, 4624, 4672, 4768, 4728, 4732, 4756
    } -ErrorAction SilentlyContinue | ForEach-Object {
        
        $xml  = [xml]$_.ToXml()
        $data = $xml.Event.EventData.Data
        

        [PSCustomObject]@{
            Row = $_.RecordId
            EventID     = $_.Id
            TimeCreated = $_.TimeCreated
            SrcIP       = ($data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
            User        = ($data | Where-Object { $_.Name -match 'SubjectUserName' }).'#text'
            TargetUser  = ($data | Where-Object { $_.Name -match 'TargetUserName' }).'#text'
            ServiceName = ($data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
            Domain      = ($data | Where-Object { $_.Name -match 'TargetDomainName|SubjectDomainName' }).'#text'
            Encryption  = ($data | Where-Object { $_.Name -eq 'TicketEncryptionType' }).'#text'
            AccessMask  = ($data | Where-Object { $_.Name -eq 'AccessMask' }).'#text'
            PreAuthType = ($data | Where-Object { $_.Name -eq 'PreAuthType' }).'#text'
            DCSyncGUID = ($data | Where-Object { $_.Name -eq 'Properties' }).'#text'
            Group       = ($_.Message -split "`n")[0] 
        } | Invoke-DetectionLogic
    }
}

$detections | Export-Csv ".\detections.csv" -NoTypeInformation
