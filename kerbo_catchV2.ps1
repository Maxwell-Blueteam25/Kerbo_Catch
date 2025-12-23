<#
.SYNOPSIS
Unified Security Log Triage (Streaming + Normalized)
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

    # 1. Kerberoasting (4769 + Weak Encrypt + Not Machine)
    if ($Events.EventID -eq 4769 -and $Events.Encryption -eq '0x17' -and 
        $Events.ServiceName -notlike '*$*' -and $Events.TargetUser -notlike '*$*' -and 
        $Events.TargetUser -notlike '*SYSTEM*' -and $Events.ServiceName -notmatch 'krbtgt') {
        
        Write-Host "CRITICAL: Kerberoasting Detected (Weak Encryption)" -ForegroundColor Red
        Write-Host "Row: $($Events.Row) | Time: $($Events.TimeCreated) | IP: $($Events.SrcIP) | User: $($Events.TargetUser)"
        Write-Host "--------------------------------"
    }

    # 2. DCSync (4662 + AccessMask 0x100)
    if ($Events.EventID -eq 4662 -and $Events.AccessMask -eq '0x100' -and $Events.User -notlike '*$*') {
        Write-Host "CRITICAL: DCSync Attempt Detected" -ForegroundColor Red
        Write-Host "Row: $($Events.Row) | Time: $($Events.TimeCreated) | Actor: $($Events.User)"
        Write-Host "--------------------------------"
    }

    # 3. Golden Ticket (Lowercase Domain Heuristic)
    if ($Events.EventID -match '4624|4672|4769' -and $Events.Domain -cmatch '[a-z]' -and $Events.TargetUser -notlike '*$*') {
        Write-Host "WARNING: Golden Ticket Heuristic (Lowercase Domain)" -ForegroundColor Yellow
        Write-Host "Row: $($Events.Row) | Time: $($Events.TimeCreated) | Domain: $($Events.Domain) | User: $($Events.TargetUser)"
        Write-Host "--------------------------------"
    }

    # 4. AS-REP Roasting
    if ($Events.EventID -eq 4768 -and ($Events.PreAuthType -in '0','0x0') -and $Events.Encryption -eq '0x17') {
        Write-Host "CRITICAL: AS-REP Roasting Detected" -ForegroundColor Red
        Write-Host "Row: $($Events.Row) | Time: $($Events.TimeCreated) | User: $($Events.TargetUser)"
        Write-Host "--------------------------------"
    }

    # 5. Sensitive Group Mod
    if ($Events.EventID -match '4728|4732|4756' -and $Events.Group -match "Domain Admins|Enterprise Admins|Administrators") {
        Write-Host "CRITICAL: Sensitive Group Modification" -ForegroundColor Magenta
        Write-Host "Row: $($Events.Row) | Time: $($Events.TimeCreated) | Actor: $($Events.User) | Group: $($Events.Group)"
        Write-Host "--------------------------------"
    }
}



if ($Mode -eq 'CSV') {
    Import-Csv -Path $csv_Path | ForEach-Object {
        $json = $_.Payload | ConvertFrom-Json
        $data = $json.EventData.Data

        [PSCustomObject]@{
            Row = $_.RecordNumber
            EventID     = $_.EventID
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
        } | Invoke-DetectionLogic
    }
}

if ($Mode -eq 'Live') {

    Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        StartTime = (Get-Date $StartDate)
        EndTime   = (Get-Date $EndDate)
        ID        = 4769, 4662, 4624, 4672, 4768, 4728, 4732, 4756
    } -ErrorAction SilentlyContinue | ForEach-Object {
        
        $xml  = [xml]$_.ToXml()
        $data = $xml.Events.EventData.Data
        

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
            Group       = ($_.Message -split "`n")[0] 
        } | Invoke-DetectionLogic
    }
}