<#
.SYNOPSIS
Interactive AD Security log triage script (CSV import or Live system) to spot common credential/theft & persistence artifacts.

.DESCRIPTION
This script provides a menu-driven workflow to triage Windows Security logs in two modes:

MODE 1: Import-CSV
- Prompts for a CSV path, validates it exists and ends in .csv, then imports it.
- Expects each row to include a JSON "Payload" field (EventData.Data) and standard columns (EventID, TimeCreated, RemoteHost, Computer, etc.).
- Parses the JSON payload into a normalized object per event and prints detections to the console.

MODE 2: Live System Triage
- Prompts for a StartDate and EndDate in the format: 'YYYY-MM-DD HH:MM:SS'
- Queries the local Security event log using Get-WinEvent for relevant Event IDs:
  4769, 4662, 4624, 4672, 4768, 4728, 4732, 4756
- Parses each event XML and builds a plain-text report string ($body) that is printed at the end if findings exist.

DETECTIONS (both modes)
1) Kerberoasting (Event ID 4769)
   - CSV mode: Status must be 0x0, excludes machine accounts (*$) and SYSTEM, excludes krbtgt.
   - Live mode: Flags 4769 with TicketEncryptionType = 0x17 and excludes machine accounts (*$).
   - Notes: The 0x17 check is treated as "weak encryption" in this script’s heuristic.

2) DCSync Attempt (Event ID 4662)
   - Flags AccessMask = 0x100 and excludes machine accounts (*$).
   - Prints the suspected actor (SubjectUserName / TargetUserName depending on mode).

3) Golden Ticket Artifact Heuristic (Event IDs 4624 / 4672 / 4769)
   - Flags events where the domain field contains lowercase letters (regex [a-z]).
   - WARNING: This is a heuristic and can generate false positives/negatives. Confirm with additional evidence.

4) AS-REP Roasting (Event ID 4768)
   - Flags PreAuthType = 0 (or 0x0 in Live mode) and TicketEncryptionType = 0x17.

5) Sensitive Group Modification (Event IDs 4728 / 4732 / 4756)
   - CSV mode: Flags additions to critical groups:
     Domain Admins, Enterprise Admins, Administrators, Schema Admins
   - Live mode: Flags if the event message contains:
     Domain Admins, Enterprise Admins, Administrators

OUTPUT BEHAVIOR
- CSV mode: Uses Write-Host to print banners and key fields (time, event id, user/service, src IP when available).
- Live mode: Appends findings to a report string and prints it once at the end if non-empty.

.PARAMETER csv_Path
CSV path collected interactively when selecting option 1.
Note: In the current script, CSV path validation runs after the menu as well; if you choose Live mode, ensure the CSV validation block is not executed (or guard it with $artifactType -eq 'CSV').

.PARAMETER StartDate
Start of the time window for Live triage. Enter as: 'YYYY-MM-DD HH:MM:SS'

.PARAMETER EndDate
End of the time window for Live triage. Enter as: 'YYYY-MM-DD HH:MM:SS'

.INPUTS
None. All inputs are gathered via Read-Host.

.OUTPUTS
None (no pipeline output). Findings are printed to the console.

.EXAMPLE
PS C:\> .\Invoke-SecurityLogTriage.ps1
Select a Security Log Option to Triage:
1. Import-CSV
2. Live System Triage
Select Options 1-2: 1
Path to CSV: C:\IR\SecurityExport.csv

Parses the CSV and prints detections as they are found.

.EXAMPLE
PS C:\> .\Invoke-SecurityLogTriage.ps1
Select a Security Log Option to Triage:
1. Import-CSV
2. Live System Triage
Select Options 1-2: 2
Between Which Dates? (Format '2021-07-28 00:00:00'): 2021-07-28 00:00:00
Between Which Dates? (Format '2021-07-28 00:00:00'): 2021-07-28 23:59:59

Queries the local Security log for the specified time range and prints a summary report if findings exist.

.NOTES
CSV MODE EXPECTED COLUMNS (typical)
- EventID
- TimeCreated
- Payload (JSON string with EventData.Data entries)
- PayloadData1 (often contains domain\user context)
- RemoteHost
- Computer

LIVE MODE REQUIREMENTS
- Must be run with permissions that allow reading the Security event log (often requires Admin).

LIMITATIONS / WARNINGS
- Several checks are heuristic (especially Golden Ticket detection by lowercase domain).
- Encryption type values and meanings depend on your environment and audit data quality.
- This script prints to console only; it does not write structured output objects.


.LINK
https://attack.mitre.org/techniques/T1558/
https://attack.mitre.org/techniques/T1003/006/
#>

Write-Host "Select a Security Log Option to Triage: " -ForegroundColor Cyan
Write-Host "1. Import-CSV" -ForegroundColor Cyan
Write-Host "2. Live System Triage" -ForegroundColor Cyan

$userDecision = Read-Host "Select Options 1-2" 

switch ($userDecision) {
    1 {$csv_Path = (Read-Host "Path to CSV").Trim('"') ; $artifactType = 'CSV'
    if (-Not (Test-Path -Path $csv_Path)) {
    Write-Host "File not found. Please provide a valid path." -ForegroundColor Red
    exit
    } elseif ($csv_Path -notlike "*.csv") {
        Write-Host "Invalid file type. Please provide a CSV file." -ForegroundColor Red
        exit
        }
    }
    2 {$StartDate = (Read-Host "Between Which Dates? (Format '2021-07-28 00:00:00')") ; $EndDate = (Read-Host "Between Which Dates? (Format '2021-07-28 00:00:00')") ; $artifactType = 'Live'}
    Default {Write-Host "Invalid Choice. Exiting." ; exit}
}



$csv = Import-Csv -Path $csv_Path

if ($artifactType -eq "CSV") { $Parsed_Events = Import-Csv -Path $csv_Path | ForEach-Object {
    $json = $_.Payload | ConvertFrom-Json
    $data = $json.EventData.Data

    # Parse JSON fields into a Custom Object
    $obj = [PSCustomObject]@{
        EventID           = $_.EventID
        TimeCreated       = $_.TimeCreated
        DomainAndUser     = $_.PayloadData1
        AccessMask        = ($data | Where-Object { $_.'@Name' -eq "AccessMask" }).'#text'
        SrcIP             = $_.RemoteHost
        Status            = ($data | Where-Object { $_.'@Name' -eq "Status" }).'#text'
        ServiceName       = ($data | Where-Object { $_.'@Name' -eq "ServiceName" }).'#text'
        TargetUser        = ($data | Where-Object { $_.'@Name' -eq "TargetUserName" }).'#text'
        PreAuthType       = ($data | Where-Object { $_.'@Name' -eq "PreAuthType" }).'#text'
        Encryption        = ($data | Where-Object { $_.'@Name' -eq "TicketEncryptionType" }).'#text'
        TargetDomainName  = ($data | Where-Object { $_.'@Name' -eq "TargetDomainName" }).'#text'
        DCSubjectUserName = ($data | Where-Object { $_.'@Name' -eq "SubjectUserName" }).'#text'
        ComputerName      = $_.Computer
    }

    # Kerberoasting Detection
    foreach ($events in $obj) {
        if ($events.Status -eq "0x0" -and $events.ServiceName -notlike "*$*" -and $events.TargetUser -notlike "*$*" -and $events.TargetUser -notlike "*SYSTEM*" -and $events.ServiceName -notmatch "krbtgt" -and $events.EventID -eq "4769") {
            
            if ($events.Encryption -eq "0x17") {
                $raw = $events.SrcIP
                $ip = $raw -replace '^::ffff:', '' -replace ':\d+$', ''
                
                Write-Host "Kerberoasting Detected-Weak Encryption" -ForegroundColor Red
                Write-Host ""
                Write-Host ("Time Created: {0}" -f $events.TimeCreated)
                Write-Host ("EventId: {0}" -f $events.EventId)
                Write-Host ("Source IP: {0}" -f $ip)
                Write-Host ("Target User: {0}" -f $events.TargetUser)
                Write-Host -NoNewline "Encryption:"
                Write-Host $events.Encryption -ForegroundColor Red
                Write-Host -NoNewline "Service Name: "
                Write-Host $events.ServiceName -ForegroundColor Red
                Write-Host "================================"
            }
            else {
                $raw = $events.SrcIP
                $ip = $raw -replace '^::ffff:', '' -replace ':\d+$', ''
                
                Write-Host "Kerberoasting Detected!!!" -ForegroundColor Red
                Write-Host ""
                Write-Host ("Time Created: {0}" -f $events.TimeCreated)
                Write-Host ("EventId: {0}" -f $events.EventId)
                Write-Host ("Source IP: {0}" -f $ip)
                Write-Host ("Target User: {0}" -f $events.TargetUser)
                Write-Host ("Encryption: {0}" -f $events.Encryption)
                Write-Host -NoNewline "Service Name: "
                Write-Host $events.ServiceName -ForegroundColor Red
                Write-Host "================================"
            }
        }
    }

    # DC Sync / Golden Ticket Detection
    foreach ($events in $obj) {
        
        # DCSync Check
        if ($events.EventID -eq "4662" -and $events.AccessMask -eq "0x100" -and $events.DCSubjectUserName -notlike "*$*") {
            Write-Host "[!] DCSync Attempt Detected (Event 4662)" -ForegroundColor Red
            Write-Host ("Time Created: {0}" -f $events.TimeCreated)
            Write-Host ("Computer Name: {0}" -f $events.ComputerName)
            Write-Host "User: $($events.DCSubjectUserName)"
            Write-Host "Event Description: Operation Performed on an Object with Replication Rights"
            Write-Host "================================"
        }

        # Golden Ticket Artifact Check
        if ($events.TargetDomainName -cmatch '[a-z]' -and ($events.EventID -match '4624|4672|4769')) {
            $raw = $events.SrcIP
            $ip = $raw -replace '^::ffff:', '' -replace ':\d+$', ''
            
            Write-Host "Golden Ticket Detected!!!" -ForegroundColor Yellow
            Write-Host ""
            Write-Host ("Time Created: {0}" -f $events.TimeCreated)
            Write-Host ("EventId: {0}" -f $events.EventId)
            Write-Host ("Source IP: {0}" -f $ip)
            Write-Host ("Target User: {0}" -f $events.TargetUser)
            Write-Host ("Target Domain: {0}" -f $events.TargetDomainName)
            Write-Host ("Encryption Type: {0}" -f $events.Encryption)
            Write-Host "================================"
        }
    }

    # AS-Rep Roasting Detection
    foreach ($events in $obj) {
        if ($events.EventID -eq "4768" -and $events.PreAuthType -eq "0" -and $events.Encryption -eq "0x17") {
                $raw = $events.SrcIP
                $ip = $raw -replace '^::ffff:', '' -replace ':\d+$', ''
                
                Write-Host "AS-Rep Roasting Detected-Weak Encryption" -ForegroundColor Red
                Write-Host ""
                Write-Host ("Time Created: {0}" -f $events.TimeCreated)
                Write-Host ("EventId: {0}" -f $events.EventId)
                Write-Host ("Source IP: {0}" -f $ip)
                Write-Host ("Target User: {0}" -f $events.TargetUser)
                Write-Host -NoNewline "Encryption:"
                Write-Host $events.Encryption -ForegroundColor Red
                Write-Host -NoNewline "PreAuthentication Type: "
                Write-Host "No Pre-Authentication Needed" -ForegroundColor Red
                Write-Host -NoNewline "Service Name: "
                Write-Host $events.ServiceName -ForegroundColor Red
                Write-Host "================================"



        }
    }

    # Sensitive Group Modification (Persistence)
    # Event 4728: Member Added to Global Security Group
    # Event 4732: Member Added to Domain Local Security Group
    # Event 4756: Member Added to Universal Security Group
    foreach ($events in $obj) {
    if ($events.EventID -match '4728|4732|4756') {
        
 
        $CriticalGroups = "Domain Admins|Enterprise Admins|Administrators|Schema Admins"

        if ($events.TargetUser -match $CriticalGroups) {
            Write-Host "[!!!] CRITICAL: Member Added to Admin Group" -ForegroundColor Magenta
            Write-Host ""
            Write-Host ("Time Created:  {0}" -f $events.TimeCreated)
            Write-Host ("EventId:       {0}" -f $events.EventId)
            Write-Host ("Who did it:    {0}" -f $events.DCSubjectUserName)
            Write-Host ("Group Name:    {0}" -f $events.TargetUser) 
            Write-Host "Action:        IMMEDIATE ESCALATION REQUIRED" -ForegroundColor Magenta
            Write-Host "================================"
            }
        }

    }
}
}
if ($artifactType -eq "Live") {
    
    # 1. Grab Raw Events (Fast)
    $SecurityLogs = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        StartTime = (Get-Date $StartDate)
        EndTime   = (Get-Date $EndDate)
        ID        = 4769, 4662, 4624, 4672, 4768, 4728, 4732, 4756 # Grab everything we need at once
    }

    $body = ""

    foreach ($Events in $SecurityLogs) {
        
      
        $xml = [xml]$Events.ToXml()
        $data = $xml.Event.EventData.Data

       
        $EventID     = $Events.Id
        $Message     = $Events.Message
        $TargetUser  = ($data | Where-Object { $_.Name -match 'TargetUserName|SubjectUserName' }).'#text'
        $ServiceName = ($data | Where-Object { $_.Name -eq 'ServiceName' }).'#text'
        $Domain      = ($data | Where-Object { $_.Name -match 'TargetDomainName|SubjectDomainName' }).'#text'
        $Status      = ($data | Where-Object { $_.Name -eq 'Status' }).'#text'
        $Encryption  = ($data | Where-Object { $_.Name -eq 'TicketEncryptionType' }).'#text'
        $AccessMask  = ($data | Where-Object { $_.Name -eq 'AccessMask' }).'#text'
        $PreAuth     = ($data | Where-Object { $_.Name -eq 'PreAuthType' }).'#text'


     
        if ($EventID -eq 4769 -and $Encryption -eq '0x17' -and $ServiceName -notlike '*$*' -and $TargetUser -notlike '*$*') {
            $body += "CRITICAL: Kerberoasting Detected (Weak Encryption)`n"
            $body += "Event ID: $EventID `nUser: $TargetUser `nService: $ServiceName `n`n====================`n`n"
        }

     
        if ($EventID -eq 4662 -and $AccessMask -eq '0x100' -and $TargetUser -notlike '*$*') {
            $body += "CRITICAL: DCSync Attempt Detected`n"
            $body += "Event ID: $EventID `nActor: $TargetUser `nMask: $AccessMask `n`n====================`n`n"
        }

   
        if ($EventID -match '4624|4672|4769' -and $Domain -cmatch '[a-z]') {
            $body += "CRITICAL: Golden Ticket Artifact (Lowercase Domain)`n"
            $body += "Event ID: $EventID `nDomain: $Domain `nUser: $TargetUser `n`n====================`n`n"
        }

      
        if ($EventID -eq 4768 -and ($PreAuth -eq '0' -or $PreAuth -eq '0x0') -and $Encryption -eq '0x17') {
            $body += "CRITICAL: AS-REP Roasting Detected`n"
            $body += "Event ID: $EventID `nUser: $TargetUser `n`n====================`n`n"
        }

        
        if ($EventID -match '4728|4732|4756' -and $Message -match "Domain Admins|Enterprise Admins|Administrators") {
             $body += "CRITICAL: Sensitive Group Modification`n"
             $body += "Event ID: $EventID `nMessage Summary: $($Message.Split("`n")[0]) `n`n====================`n`n"
        }
    }
    
  
    if ($body.Length -gt 0) {
        $body
    }

}
