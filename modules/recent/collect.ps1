# modules/recent/collect.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"

# JLECmd.exe лежит строго рядом с этим скриптом в папке модуля
$JLECmd = Join-Path $PSScriptRoot "JLECmd.exe"
$RecentPath = "$env:APPDATA\Microsoft\Windows\Recent"

# 1. Проверка наличия инструмента
if (-not (Test-Path $JLECmd)) {
    throw "JLECmd.exe not found at: $JLECmd"
}

# 2. Проверка наличия директории Recent
if (-not (Test-Path $RecentPath)) {
    throw "Recent folder not found: $RecentPath"
}

# 3. Временная папка для CSV
$TempCsv = Join-Path $OutputPath "_temp_csv"
New-Item -Path $TempCsv -ItemType Directory -Force | Out-Null

try {
    Write-Host "[recent] Starting JLECmd analysis..." -ForegroundColor Gray
    
    # Запуск JLECmd
    $process = Start-Process -FilePath $JLECmd `
        -ArgumentList @("-d", $RecentPath, "--csv", $TempCsv, "-q") `
        -Wait -PassThru -NoNewWindow

    if ($process.ExitCode -ne 0) {
        throw "JLECmd exited with code $($process.ExitCode)"
    }

    # 4. Обработка результатов (AutomaticDestinations)
    $autoCsv = Get-ChildItem $TempCsv "*AutomaticDestinations*.csv" -ErrorAction SilentlyContinue
    $autoEntries = if ($autoCsv) { 
        $autoCsv | ForEach-Object { Import-Csv $_.FullName -Encoding UTF8 } 
    } else { @() }

    # 5. Обработка результатов (CustomDestinations)
    $custCsv = Get-ChildItem $TempCsv "*CustomDestinations*.csv" -ErrorAction SilentlyContinue
    $custEntries = if ($custCsv) { 
        $custCsv | ForEach-Object { Import-Csv $_.FullName -Encoding UTF8 } 
    } else { @() }

    # 6. Формирование JSON отчёта
    $result = [PSCustomObject]@{
        metadata = @{ 
            hostname=$env:COMPUTERNAME; 
            username=$env:USERNAME; 
            timestamp=(Get-Date).ToString("o"); 
            module="recent" 
        }
        automatic_destinations = $autoEntries
        custom_destinations = $custEntries
    }

    # 7. Сохранение результата
    $jsonStr = $result | ConvertTo-Json -Depth 10 -Compress
    $utf8 = New-Object System.Text.UTF8Encoding($false) # Без BOM
    [System.IO.File]::WriteAllText((Join-Path $OutputPath "recent.json"), $jsonStr, $utf8)
    
    Write-Host "[recent] Success. Found $($autoEntries.Count) Auto + $($custEntries.Count) Custom entries." -ForegroundColor Green

} finally {
    # Очистка временных файлов
    if (Test-Path $TempCsv) {
        Remove-Item -Path $TempCsv -Recurse -Force -ErrorAction SilentlyContinue
    }
}