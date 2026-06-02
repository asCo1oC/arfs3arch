param([string]$OutputPath)

$ErrorActionPreference = 'Continue'

# Если OutputPath не задан – используем временную папку (только для ручных тестов)
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $env:TEMP "network_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Write-Warning "OutputPath not specified, using $OutputPath"
}
if (!(Test-Path $OutputPath)) { 
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null 
}

function Export-SafeJson { param($Path,$Data) $Data | ConvertTo-Json -Depth 5 | Out-File $Path -Encoding UTF8 }

# ------------------------------
# 1. ARP cache
# ------------------------------
$arpEntries = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
    Where-Object State -ne 'Permanent' | 
    Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias

# ------------------------------
# 2. DNS cache
# ------------------------------
$dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | 
    Select-Object Name, Type, Data, Entry, TimeToLive

# ------------------------------
# 3. Routing table
# ------------------------------
$routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -notlike '255.255.255.255/*' -and $_.RouteMetric -lt 5000 } |
    Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric

# ------------------------------
# 4. IP configuration
# ------------------------------
$ipConfig = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object IPAddress, InterfaceAlias, PrefixLength, AddressState

# ------------------------------
# 5. TCP connections
# ------------------------------
$tcpConnections = @()
try {
    $tcpConnections = Get-NetTCPConnection -ErrorAction Stop |
        Where-Object { $_.State -in @('Established','Listen') } |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
} catch {
    Write-Warning "Failed to get TCP connections: $($_.Exception.Message)"
}

# ------------------------------
# 6. UDP endpoints
# ------------------------------
$udpEndpoints = @()
try {
    $udpEndpoints = Get-NetUDPEndpoint -ErrorAction Stop |
        Select-Object LocalAddress, LocalPort, OwningProcess
} catch {
    Write-Warning "Failed to get UDP endpoints: $($_.Exception.Message)"
}

# ------------------------------
# 7. Adapter statistics
# ------------------------------
$netStats = @()
try {
    $netStats = Get-NetAdapterStatistics -ErrorAction Stop |
        Select-Object Name, ReceivedBytes, SentBytes, ReceivedPackets, SentPackets
} catch {
    Write-Warning "Failed to get adapter statistics: $($_.Exception.Message)"
}

# ------------------------------
# 8. PID -> ProcessName mapping (без использования встроенной переменной $pid)
# ------------------------------
$allPids = @()
$allPids += $tcpConnections.OwningProcess | Where-Object { $_ -gt 0 -and $_ -ne 4 }
$allPids += $udpEndpoints.OwningProcess | Where-Object { $_ -gt 0 -and $_ -ne 4 }
$allPids = $allPids | Select-Object -Unique

$processMap = @{}
foreach ($procId in $allPids) {
    try {
        $proc = Get-Process -Id $procId -ErrorAction Stop
        if ($proc) {
            $name = $proc.ProcessName -replace '[^\w\-\.]', ''
            $processMap[$procId] = $name
        }
    } catch {
        # игнорируем процессы, которые не найдены или недоступны
    }
}

# Добавляем ProcessName к TCP объектам
$tcpConnections = $tcpConnections | ForEach-Object {
    $procName = if ($processMap.ContainsKey($_.OwningProcess)) { $processMap[$_.OwningProcess] } else { $null }
    $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue $procName -PassThru
}

# Добавляем ProcessName к UDP объектам
$udpEndpoints = $udpEndpoints | ForEach-Object {
    $procName = if ($processMap.ContainsKey($_.OwningProcess)) { $processMap[$_.OwningProcess] } else { $null }
    $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue $procName -PassThru
}

# ------------------------------
# 9. Итоговый JSON
# ------------------------------
$result = @{
    metadata = @{
        hostname   = $env:COMPUTERNAME
        timestamp  = (Get-Date -Format 'o')
        module     = 'network'
        note       = 'Passive network state collection, no active scanning'
    }
    arp_cache      = @($arpEntries)
    dns_cache      = @($dnsCache)
    routing_table  = @($routes)
    ip_config      = @($ipConfig)
    tcp_connections= @($tcpConnections)
    udp_endpoints  = @($udpEndpoints)
    adapter_stats  = @($netStats)
}

Export-SafeJson -Path "$OutputPath\network.json" -Data $result
Write-Host "[network] Collected $($arpEntries.Count) ARP, $($tcpConnections.Count) TCP, $($udpEndpoints.Count) UDP endpoints" -ForegroundColor Green
