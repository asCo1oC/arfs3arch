param([string]$OutputPath)
$ErrorActionPreference = "SilentlyContinue"

# 1. Services
$services = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\*" -ErrorAction SilentlyContinue |
            Where-Object { $_.ImagePath -ne $null } |
            Select-Object PSChildName, ImagePath, DisplayName, Start, Type, ErrorControl

# 2. UserAssist (raw)
$uaPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BC1E25671}\Count"
)
$userAssist = @()
foreach ($p in $uaPaths) {
    if (Test-Path $p) {
        $item = Get-Item $p
        foreach ($prop in $item.Property) {
            $raw = (Get-ItemProperty $p $prop).$prop
            $userAssist += @{ path=$p; name=$prop; base64=[Convert]::ToBase64String($raw); length=$raw.Length }
        }
    }
}

# 3. Event ID 7045
$events = Get-WinEvent -FilterHashtable @{LogName='System'; ID=7045} -MaxEvents 50 -ErrorAction SilentlyContinue
$serviceEvents = foreach ($e in $events) {
    $xml = [xml]$e.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        time = $e.TimeCreated.ToString("o")
        service = ($data | ?{$_.Name -eq 'ServiceName'}).'#text'
        image = ($data | ?{$_.Name -eq 'ImagePath'}).'#text'
    }
}

$result = [PSCustomObject]@{
    metadata = @{ hostname=$env:COMPUTERNAME; username=$env:USERNAME; timestamp=(Get-Date).ToString("o"); module="logs" }
    services = $services
    user_assist = $userAssist
    service_events = $serviceEvents
}
$jsonStr = $result | ConvertTo-Json -Depth 10 -Compress
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $OutputPath "logs.json"), $jsonStr, $utf8)
