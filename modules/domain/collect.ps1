param([string]$OutputPath)

$ErrorActionPreference = 'Continue'
if (!(Test-Path $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }

function Export-SafeJson { param($Path,$Data) $Data | ConvertTo-Json -Depth 5 | Out-File $Path -Encoding UTF8 }

function Test-ADAvailability {
    try {
        Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $null = $domain.Name
        return $true, $domain.Name
    } catch {
        return $false, $null
    }
}

$adAvailable, $currentDomain = Test-ADAvailability

# ---------- Доверительные отношения ----------
$trustRelationships = @()
if ($adAvailable) {
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $trustRelationships = $domain.GetAllTrustRelationships() | ForEach-Object {
            @{
                source      = $_.SourceName
                target      = $_.TargetName
                type        = $_.TrustType.ToString()
                direction   = $_.TrustDirection.ToString()
                isTransitive = $_.IsTransitive
            }
        }
    } catch {
        Write-Warning "Не удалось получить доверительные отношения: $($_.Exception.Message)"
    }
}

# ---------- Kerberos tickets (метаданные) ----------
$kerbTickets = try {
    $raw = klist tickets 2>$null | Out-String
    @{ raw_output = $raw; parsed_count = ($raw -split '^\s*Client:').Count - 1 }
} catch {
    @{ error = "klist unavailable" }
}

# ---------- Logon sessions ----------
$logonSessions = Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue | 
    ForEach-Object {
        $user = Get-CimInstance Win32_Account -Filter "SID='$($_.SID)'" -ErrorAction SilentlyContinue
        $accountName = if ($user) { "$($user.Domain)\$($user.Name)" } else { "" }
        @{
            logon_id   = $_.LogonId
            start_time = $_.StartTime
            logon_type = $_.LogonType
            account    = $accountName
        }
    }

# ---------- Итоговый JSON ----------
$result = @{
    metadata = @{
        hostname   = $env:COMPUTERNAME
        timestamp  = (Get-Date -Format 'o')
        module     = 'domain'
        ad_available = $adAvailable
    }
    current_domain = $currentDomain
    domain_trusts   = $trustRelationships
    kerberos_tickets = $kerbTickets
    active_logons   = $logonSessions
    collection_note = if ($adAvailable) { "AD modules executed" } else { "AD modules skipped: not domain-joined or insufficient permissions" }
}

Export-SafeJson -Path "$OutputPath\domain.json" -Data $result
Write-Host "[domain] Collected $($trustRelationships.Count) trusts, $($logonSessions.Count) logon sessions" -ForegroundColor Green