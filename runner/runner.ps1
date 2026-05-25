<#
.SYNOPSIS
MVP Runner for Windows Artifact Collection
#>
param(
    [Parameter(Position=0)][ValidateSet("collect","run")][string]$Command = "collect",
    [Parameter(Position=1)][string]$Target = "all",
    [string]$OutputRoot = ""
)

$ErrorActionPreference = "Stop"

# ==========================================
# 1. Helper Functions (MUST be defined at script scope)
# ==========================================
function Save-JsonNoBom {
    param([object]$Data, [string]$Path)
    $json = $Data | ConvertTo-Json -Depth 10
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $utf8)
}

function Write-Log { 
    param([string]$Message) 
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor DarkGray 
}

# ==========================================
# 2. Init Paths & Output
# ==========================================
if (-not $OutputRoot) { 
    $OutputRoot = Join-Path $PSScriptRoot "..\output" 
}
$OutputRoot = $OutputRoot.TrimEnd('\')
if (-not (Test-Path $OutputRoot)) {
    New-Item -ItemType Directory -Force -Path $OutputRoot -ErrorAction SilentlyContinue | Out-Null
}

$CollectionId = "col_$(Get-Date -Format 'yyyyMMdd_HHmmss')_$(Get-Random -Minimum 1000 -Maximum 9999)"
$CollectionDir = Join-Path $OutputRoot $CollectionId
New-Item -Path $CollectionDir -ItemType Directory -Force | Out-Null

$ModuleStatus = @{}
$ModulesPath = Join-Path $PSScriptRoot "..\modules"
$Manifests = Get-ChildItem -Path $ModulesPath -Filter "manifest.json" -Recurse -ErrorAction SilentlyContinue

# ==========================================
# 3. Module Execution Pipeline
# ==========================================
foreach ($manifestFile in $Manifests) {
    try {
        $manifest = Get-Content $manifestFile.FullName -Raw | ConvertFrom-Json
        $moduleName = $manifest.name
        if (-not $moduleName) { continue }
        
        $requiresAdmin = $manifest.requires_admin -eq $true

        # Filter by target
        if ($Command -eq "run" -and $Target -ne "all" -and $moduleName -ne $Target) { continue }

        # Check Admin rights
        if ($requiresAdmin -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Log "[SKIP] $moduleName requires Administrator" -ForegroundColor Yellow
            $ModuleStatus[$moduleName] = "skipped_admin"
            continue
        }

        $moduleDir = $manifestFile.DirectoryName
        $moduleOutput = Join-Path $CollectionDir $moduleName
        New-Item -Path $moduleOutput -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

        Write-Log "[RUN] $moduleName"
        & "$moduleDir\collect.ps1" -OutputPath $moduleOutput -ErrorAction Stop
        $ModuleStatus[$moduleName] = "success"
        Write-Log "[OK] $moduleName" -ForegroundColor Green
    } catch {
        Write-Log "[ERROR] $moduleName : $_" -ForegroundColor Red
        $ModuleStatus[$moduleName] = "failed"
    }
}

# ==========================================
# 4. Metadata & Packaging
# ==========================================
$metadata = [PSCustomObject]@{
    hostname      = $env:COMPUTERNAME
    username      = $env:USERNAME
    collection_id = $CollectionId
    timestamp     = (Get-Date).ToString("o")
    runner_version= "1.0.0"
    modules       = $ModuleStatus
}
Save-JsonNoBom -Data $metadata -Path (Join-Path $CollectionDir "metadata.json")

$zipPath = "$CollectionDir.zip"
Write-Log "[ARCHIVE] Packing to $zipPath"
Compress-Archive -Path $CollectionDir -DestinationPath $zipPath -Force

# Cleanup temp collection dir (keep zip)
Remove-Item -Path $CollectionDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n✅ Collection complete. Archive: $zipPath" -ForegroundColor Green