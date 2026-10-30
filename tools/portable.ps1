[CmdletBinding()]
param(
    [string]$OutputPath = '',
    [ValidateRange(0, 9223372036854775807)][long]$MaxFileBytes = 0,
    [ValidateRange(0, 9223372036854775807)][long]$MaxTotalBytes = 0,
    [ValidateRange(0, 86400)][int]$SourceTimeoutSeconds = 120,
    [ValidateRange(0, 2147483647)][int]$MaxDomainRecords = 0,
    [ValidateSet('Current','Accessible')][string]$ProfileScope = 'Accessible',
    [string[]]$Sources = @('all'),
    [string[]]$ExcludeSources = @(),
    [switch]$Archive,
    [ValidateRange(0, 9223372036854775807)][long]$MaxArtifactBytes = 0,
    [ValidateRange(0, 9223372036854775807)][long]$MaxSharedTextFileBytes = 1048576,
    [ValidateRange(0, 32)][int]$SharedTextSearchDepth = 4,
    [switch]$TestSerialization,
    [switch]$LibraryOnly
)

# Single-file collector for upload/execution contexts such as IIS APPPOOL.
# It does not assume USERPROFILE/HOME and uses only built-in PowerShell APIs.
$ErrorActionPreference = 'Stop'
$script:PortableLDAPContext = $null

function Test-WritableDirectory([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try {
        New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop | Out-Null
        $probe = Join-Path $Path ('.write_' + [guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllText($probe, 'ok', (New-Object Text.UTF8Encoding($false)))
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        return $true
    } catch { return $false }
}
function Resolve-OutputDirectory([string]$Requested) {
    # Explicit OutputPath is the final collection directory. This makes uploads
    # predictable for service accounts without a normal user profile.
    if ($Requested) {
        if (-not (Test-WritableDirectory $Requested)) {
            throw "Specified OutputPath is not writable or could not be created: $Requested"
        }
        return [IO.Path]::GetFullPath($Requested)
    }
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($env:TEMP,$env:TMP,$env:LOCALAPPDATA,(Join-PortableOptionalPath $env:windir 'Temp'),$PSScriptRoot,(Get-Location).Path)) {
        if ($p -and -not $candidates.Contains($p)) { [void]$candidates.Add($p) }
    }
    foreach ($base in $candidates) {
        if (Test-WritableDirectory $base) {
            $dir = Join-Path $base ('portable_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '_' + $PID + '_' + [guid]::NewGuid().ToString('N').Substring(0,8))
            New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
            return $dir
        }
    }
    throw 'No writable output directory found for the current identity.'
}
function Convert-ToPlainObject($Value,[int]$Depth=0) {
    if($null -eq $Value){return $null}
    if($Depth -gt 48){throw 'Object exceeds supported serialization depth'}
    if($Value -is [enum]){return [ordered]@{name=[string]$Value;value=[long]$Value}}
    if($Value.GetType().IsPrimitive){return $Value}
    if($Value -is [string] -or $Value -is [bool] -or $Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or $Value -is [double] -or $Value -is [decimal]){return $Value}
    if($Value -is [datetime] -or $Value -is [guid]){return [string]$Value}
    if($Value -is [System.Collections.IDictionary]){$o=[ordered]@{};foreach($k in $Value.Keys){[void]($o[[string]$k]=Convert-ToPlainObject $Value[$k] ($Depth+1))};return $o}
    if($Value -is [System.Collections.IEnumerable]){$a=New-Object System.Collections.Generic.List[object];foreach($v in $Value){[void]$a.Add((Convert-ToPlainObject $v ($Depth+1)))};return ,$a.ToArray()}
    $o=[ordered]@{};foreach($p in $Value.PSObject.Properties){if($p.MemberType -match 'Property' -and $p.Name -notin @('PSComputerName','RunspaceId','PSShowComputerName')){try{[void]($o[$p.Name]=Convert-ToPlainObject $p.Value ($Depth+1))}catch{}}};if($o.Count -gt 0){return $o};return [string]$Value
}
function Convert-PortableJson($Value) {
    if ($null -eq $Value) { throw 'JSON input is null before serialization' }
    $text=Microsoft.PowerShell.Utility\ConvertTo-Json -InputObject $Value -Depth 64 -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($text) -or $text.Trim() -eq 'null') { throw 'JSON serialization returned null or empty content' }
    $null = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $text -ErrorAction Stop
    return $text
}

# Validate before publishing; an unsuccessful replacement leaves the old file intact.
function Write-PortableJson([string]$Path, $Value) {
    $text = Convert-PortableJson (Convert-ToPlainObject $Value)
    $temporary = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::WriteAllText($temporary, $text, [Text.UTF8Encoding]::new($false))
        $readBack = [IO.File]::ReadAllText($temporary, [Text.Encoding]::UTF8)
        if ($readBack -cne $text) { throw 'JSON read-back mismatch' }
        $null = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $readBack -ErrorAction Stop
        if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temporary, $Path, [System.Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($temporary, $Path) }
        return [ordered]@{path=$Path;size=([IO.FileInfo]$Path).Length}
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Get-PortableIdentity {
    $result = [ordered]@{
        schema_version='1.0'; source='identity'; status='success'
        started_at=[DateTime]::UtcNow.ToString('o'); finished_at=$null
        process_id=$PID; session_id=$null; process_is_64bit=[Environment]::Is64BitProcess
        os_is_64bit=[Environment]::Is64BitOperatingSystem
        powershell_version=$PSVersionTable.PSVersion.ToString()
        name=$null; sid=$null; authentication_type=$null; impersonation_level=$null
        environment=[ordered]@{username=$env:USERNAME;user_domain=$env:USERDOMAIN;user_profile=$env:USERPROFILE;appdata=$env:APPDATA;local_appdata=$env:LOCALAPPDATA}
        groups=@(); privileges=@(); integrity_labels=@(); commands=@(); errors=@()
    }
    $failures = New-Object System.Collections.Generic.List[object]
    $commands = New-Object System.Collections.Generic.List[object]
    $windowsIdentity = $null
    $successes = 0
    try {
        $windowsIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $result.name = $windowsIdentity.Name
        $result.sid = $windowsIdentity.User.Value
        $result.authentication_type = $windowsIdentity.AuthenticationType
        $result.impersonation_level = [string]$windowsIdentity.ImpersonationLevel
        $result.session_id = [Diagnostics.Process]::GetCurrentProcess().SessionId
        $successes++
    } catch {
        $failures.Add([ordered]@{operation='WindowsIdentity';message=$_.Exception.Message})
    } finally {
        if ($null -ne $windowsIdentity) { $windowsIdentity.Dispose() }
    }
    foreach ($spec in @(
        @{name='user';headers=@('name','sid')},
        @{name='groups';headers=@('name','type_raw','sid','attributes_raw')},
        @{name='priv';headers=@('name','description_raw','state_raw')}
    )) {
        $command = [ordered]@{name='whoami';arguments=@("/$($spec.name)",'/fo','csv','/nh');exit_code=$null;status='failed';raw=@();records=@()}
        try {
            $exe = Join-Path $env:SystemRoot 'System32\whoami.exe'
            $arguments = $command.arguments
            $raw = @(& $exe @arguments 2>&1)
            $command.exit_code = $LASTEXITCODE
            $command.raw = @($raw | ForEach-Object { [string]$_ })
            if ($command.exit_code -ne 0) { throw "whoami exited with code $($command.exit_code)" }
            if ($command.raw.Count -eq 0) { throw 'whoami returned no output' }
            $records = @($command.raw | Microsoft.PowerShell.Utility\ConvertFrom-Csv -Header $spec.headers -ErrorAction Stop)
            # Keep localized descriptions, group attributes and privilege states verbatim.
            if ($spec.name -eq 'priv') {
                foreach ($record in $records) {
                    if ($record.name -notmatch '^Se\w+Privilege$' -or [string]::IsNullOrWhiteSpace($record.state_raw)) { throw 'Unexpected privilege CSV output; see raw command output' }
                }
                $result.privileges = $records
            } elseif ($spec.name -eq 'groups') {
                foreach ($record in $records) {
                    if ($record.sid -notmatch '^S-\d-') { throw 'Unexpected group CSV output; see raw command output' }
                }
                $result.groups = $records
                $result.integrity_labels = @($records | Where-Object { $_.sid -like 'S-1-16-*' })
            } else {
                if ($records.Count -ne 1 -or $records[0].sid -notmatch '^S-\d-') { throw 'Unexpected user CSV output; see raw command output' }
            }
            $command.records = $records
            $command.status = 'success'
            $successes++
        } catch {
            $failures.Add([ordered]@{operation=('whoami /'+$spec.name);message=$_.Exception.Message})
        }
        $commands.Add($command)
    }
    $result.commands = $commands.ToArray()
    $result.errors = $failures.ToArray()
    if ($failures.Count -gt 0) {
        $result.status = 'partial'
        if ($successes -eq 0) { $result.status = 'failed' }
    }
    $result.finished_at = [DateTime]::UtcNow.ToString('o')
    return $result
}

# Embedded native logs collectors; standalone, no module imports at runtime.
function New-SourceResult {
    param([string]$Name, [object]$Location)
    return [ordered]@{
        source = $Name; location = $Location; status = 'success'
        started_at = [DateTime]::UtcNow.ToString('o'); finished_at = $null
        records = [System.Collections.Generic.List[object]]::new()
        errors = [System.Collections.Generic.List[object]]::new()
        children = @(); output_file = $null; availability = $null
    }
}


function Add-SourceError {
    param($Result, [System.Management.Automation.ErrorRecord]$ErrorRecord,
          [string]$Operation, [string]$Path)
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception.InnerException) { $exception = $exception.InnerException }
    $kind = 'failed'
    if ($ErrorRecord.CategoryInfo.Category -in @('PermissionDenied', 'SecurityError') -or
        $exception -is [UnauthorizedAccessException] -or
        $exception -is [System.Security.SecurityException]) { $kind = 'access_denied' }
    elseif ($ErrorRecord.CategoryInfo.Category -eq 'ObjectNotFound' -or
            $exception -is [System.Management.Automation.ItemNotFoundException] -or $exception -is [IO.FileNotFoundException] -or $exception -is [IO.DirectoryNotFoundException]) { $kind = 'not_found' }
    if ($exception -is [System.Management.Automation.CommandNotFoundException]) { $kind = 'unsupported' }
    if ($exception -is [TimeoutException]) { $kind='timeout' }
    if ($exception -is [PlatformNotSupportedException]) { $kind='unsupported' }
    if ($exception.Data.Contains('portable_status')) { $kind = [string]$exception.Data['portable_status'] }
    $Result.errors.Add([ordered]@{
        status = $kind; operation = $Operation; path = $Path
        category = [string]$ErrorRecord.CategoryInfo.Category
        error_id = $ErrorRecord.FullyQualifiedErrorId
        exception_type = $ErrorRecord.Exception.GetType().FullName
        message = $ErrorRecord.Exception.Message
    })
}


function Complete-SourceResult {
    param($Result)
    if ($Result.errors.Count -gt 0) {
        $Result.status = 'partial'
        if ($Result.records.Count -eq 0) {
            $kinds = @($Result.errors | ForEach-Object { $_.status } | Select-Object -Unique)
            $Result.status = 'failed'
            if ($kinds.Count -eq 1) { $Result.status = $kinds[0] }
        }
    }
    if ($Result.errors.Count -gt 0 -and @($Result.children | Where-Object { $_.status -in @('success','partial') }).Count -gt 0) { $Result.status = 'partial' }
    $Result.finished_at = [DateTime]::UtcNow.ToString('o')
    return $Result
}

# Cleanup must never replace the exception produced by a collection operation.
function Dispose-PortableResource($Resource) {
    if ($null -eq $Resource) { return }
    try {
        if ($Resource.PSObject.Methods.Name -contains 'Dispose') { $Resource.Dispose() }
    } catch {
        # Best-effort cleanup only. The source result already contains the useful error.
    }
}


function Read-RawRegistryValue {
    param($Key, [string]$Name)
    $kind = $Key.GetValueKind($Name)
    # Keep REG_EXPAND_SZ literally, including %SystemRoot% and command arguments.
    $value = $Key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $encoding = 'native'
    if ($value -is [byte[]]) { $value = [Convert]::ToBase64String($value); $encoding = 'base64' }
    return [ordered]@{ name = $Name; registry_type = [string]$kind; encoding = $encoding; value = $value }
}


function Collect-Services {
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $result = New-SourceResult 'services' $root
    $names = @('ImagePath', 'DisplayName', 'Start', 'Type', 'ErrorControl', 'ObjectName',
               'Description', 'DelayedAutoStart', 'DependOnService', 'DependOnGroup')
    try {
        Get-ChildItem -LiteralPath $root -ErrorAction Stop | ForEach-Object {
            $key = $_
            Test-PortableDeadline
            $path = $key.Name
            try {
                $available = @($key.GetValueNames())
                if ($available -contains 'ImagePath') {
                    $values = [System.Collections.Generic.List[object]]::new()
                    $parameters = [System.Collections.Generic.List[object]]::new()
                    foreach ($name in $names) {
                        if ($available -contains $name) {
                            try { $values.Add((Read-RawRegistryValue $key $name)) }
                            catch { Add-SourceError $result $_ 'ReadRegistryValue' "$path\$name" }
                        }
                    }
                    $paramKey = $null
                    try {
                        $paramKey = $key.OpenSubKey('Parameters', $false)
                        if ($null -ne $paramKey) {
                            $paramNames = @($paramKey.GetValueNames())
                            foreach ($name in @('ServiceDll', 'ServiceMain')) {
                                if ($paramNames -contains $name) {
                                    try { $parameters.Add((Read-RawRegistryValue $paramKey $name)) }
                                    catch { Add-SourceError $result $_ 'ReadRegistryValue' "$path\Parameters\$name" }
                                }
                            }
                        }
                    } catch { Add-SourceError $result $_ 'OpenRegistryKey' "$path\Parameters" }
                    finally { if ($null -ne $paramKey) { $paramKey.Dispose() } }
                    $result.records.Add([ordered]@{
                        registry_path = $path; name = $key.PSChildName
                        values = $values.ToArray(); parameters = $parameters.ToArray()
                    })
                }
            } catch { Add-SourceError $result $_ 'ReadService' $path }
            finally { $key.Dispose() }
        }
    } catch { Add-SourceError $result $_ 'EnumerateServices' $root }
    return Complete-SourceResult $result
}


function Collect-RegistryHistory {
    param([string]$Name, [string[]]$Paths)
    $result = New-SourceResult $Name $Paths
    $children = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $paths) {
        Test-PortableDeadline
        $branch = New-SourceResult 'registry_branch' $path
        $keys = [System.Collections.Generic.List[object]]::new()
        try {
            $rootKey = Get-Item -LiteralPath $path -ErrorAction Stop
            $keys.Add($rootKey)
            try {
                foreach ($childKey in @(Get-PortableRegistryDescendants $path $branch)) {
                    $keys.Add($childKey)
                }
            } catch { Add-SourceError $branch $_ 'EnumerateRegistrySubkeys' $path }

            foreach ($key in $keys) {
                Test-PortableDeadline
                $keyPath = [string]$key.Name
                try {
                    foreach ($name in @($key.GetValueNames())) {
                        try {
                            $raw = Read-RawRegistryValue $key $name
                            $entry = [ordered]@{
                                branch = $path; registry_path = $keyPath; name = $name
                                registry_type = $raw.registry_type; encoding = $raw.encoding
                                value = $raw.value
                            }
                            if ($raw.encoding -eq 'base64') {
                                $entry['length'] = [Convert]::FromBase64String($raw.value).Length
                            }
                            $branch.records.Add($entry)
                            $result.records.Add($entry)
                        } catch { Add-SourceError $branch $_ 'ReadRegistryValue' "$keyPath\$name" }
                    }
                } catch { Add-SourceError $branch $_ 'ReadRegistryKey' $keyPath }
                finally {
                    # Registry provider objects and RegistryKey handles both tolerate Dispose.
                    if ($null -ne $key -and $key.PSObject.Methods.Name -contains 'Dispose') { $key.Dispose() }
                }
            }
        } catch { Add-SourceError $branch $_ 'OpenRegistryKey' $path }
        $branch = Complete-SourceResult $branch
        foreach ($err in $branch.errors) { $result.errors.Add($err) }
        $children.Add((Get-SourceSummary $branch))
    }
    $result = Complete-SourceResult $result
    $result.children = $children.ToArray()
    return $result
}


function Collect-OfficeMru {
    $root = (Get-PortableRegistryPath 'Software\Microsoft\Office')
    $result = New-SourceResult 'office_mru' $root
    $children = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($versionKey in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
            $versionRegistryPath = [string]$versionKey.Name
            $versionPath = if ($versionKey.PSPath) { [string]$versionKey.PSPath } else { $versionRegistryPath }
            try {
                foreach ($appKey in @(Get-ChildItem -LiteralPath $versionPath -ErrorAction Stop)) {
                    $appRegistryPath = [string]$appKey.Name
                    $appPath = if ($appKey.PSPath) { [string]$appKey.PSPath } else { $appRegistryPath }
                    $appResult = New-SourceResult 'office_app' $appRegistryPath
                    $appChildren = [System.Collections.Generic.List[object]]::new()
                    foreach ($target in @(
                        @{ name = 'file_mru'; path = (Join-Path $appPath 'File MRU') },
                        @{ name = 'user_mru'; path = (Join-Path $appPath 'User MRU') }
                    )) {
                        $branch = New-SourceResult $target.name $target.path
                        $keys = [System.Collections.Generic.List[object]]::new()
                        try {
                            $key = Get-Item -LiteralPath $target.path -ErrorAction Stop
                            $keys.Add($key)
                            try {
                                foreach ($childKey in @(Get-PortableRegistryDescendants $target.path $branch)) {
                                    $keys.Add($childKey)
                                }
                            } catch { Add-SourceError $branch $_ 'EnumerateRegistrySubkeys' $target.path }
                            foreach ($valueKey in $keys) {
                                $keyPath = [string]$valueKey.Name
                                try {
                                    foreach ($name in @($valueKey.GetValueNames())) {
                                        try {
                                            $raw = Read-RawRegistryValue $valueKey $name
                                            $entry = [ordered]@{
                                                office_version = $versionKey.PSChildName
                                                application = $appKey.PSChildName
                                                branch = $target.name
                                                registry_path = $keyPath
                                                name = $name
                                                registry_type = $raw.registry_type
                                                encoding = $raw.encoding
                                                value = $raw.value
                                            }
                                            if ($raw.encoding -eq 'base64') {
                                                $entry['length'] = [Convert]::FromBase64String($raw.value).Length
                                            }
                                            $branch.records.Add($entry)
                                            $appResult.records.Add($entry)
                                            $result.records.Add($entry)
                                        } catch { Add-SourceError $branch $_ 'ReadRegistryValue' "$keyPath\$name" }
                                    }
                                } catch { Add-SourceError $branch $_ 'ReadRegistryKey' $keyPath }
                                finally {
                                    if ($null -ne $valueKey -and $valueKey.PSObject.Methods.Name -contains 'Dispose') { $valueKey.Dispose() }
                                }
                            }
                        } catch { Add-SourceError $branch $_ 'OpenRegistryKey' $target.path }
                        $branch = Complete-SourceResult $branch
                        foreach ($err in $branch.errors) { $appResult.errors.Add($err); $result.errors.Add($err) }
                        $appChildren.Add((Get-SourceSummary $branch))
                    }
                    $appResult.children = $appChildren.ToArray()
                    $appResult = Complete-SourceResult $appResult
                    $appChildrenSummary = Get-SourceSummary $appResult
                    $children.Add($appChildrenSummary)
                    if ($null -ne $appKey -and $appKey.PSObject.Methods.Name -contains 'Dispose') { $appKey.Dispose() }
                }
            } catch { Add-SourceError $result $_ 'EnumerateOfficeApplications' $versionPath }
            finally { if ($null -ne $versionKey -and $versionKey.PSObject.Methods.Name -contains 'Dispose') { $versionKey.Dispose() } }
        }
    } catch { Add-SourceError $result $_ 'EnumerateOfficeVersions' $root }
    $result = Complete-SourceResult $result
    $result.children = $children.ToArray()
    return $result
}


function Collect-RdpHistory {
    $paths = @(
        (Get-PortableRegistryPath 'Software\Microsoft\Terminal Server Client\Default'),
        (Get-PortableRegistryPath 'Software\Microsoft\Terminal Server Client\Servers')
    )
    $result = New-SourceResult 'rdp_history' $paths
    $children = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $paths) {
        Test-PortableDeadline
        $branch = New-SourceResult 'registry_branch' $path
        $keys = [System.Collections.Generic.List[object]]::new()
        try {
            $rootKey = Get-Item -LiteralPath $path -ErrorAction Stop
            $keys.Add($rootKey)
            try {
                foreach ($childKey in @(Get-PortableRegistryDescendants $path $branch)) { $keys.Add($childKey) }
            } catch { Add-SourceError $branch $_ 'EnumerateRegistrySubkeys' $path }
            foreach ($key in $keys) {
                Test-PortableDeadline
                $keyPath = [string]$key.Name
                try {
                    foreach ($name in @($key.GetValueNames())) {
                        try {
                            $raw = Read-RawRegistryValue $key $name
                            $entry = [ordered]@{
                                branch = $path; registry_path = $keyPath; name = $name
                                registry_type = $raw.registry_type; encoding = $raw.encoding; value = $raw.value
                            }
                            if ($raw.encoding -eq 'base64') { $entry['length'] = [Convert]::FromBase64String($raw.value).Length }
                            $branch.records.Add($entry); $result.records.Add($entry)
                        } catch { Add-SourceError $branch $_ 'ReadRegistryValue' "$keyPath\$name" }
                    }
                } catch { Add-SourceError $branch $_ 'ReadRegistryKey' $keyPath }
                finally { if ($null -ne $key -and $key.PSObject.Methods.Name -contains 'Dispose') { $key.Dispose() } }
            }
        } catch { Add-SourceError $branch $_ 'OpenRegistryKey' $path }
        $branch = Complete-SourceResult $branch
        foreach ($err in $branch.errors) { $result.errors.Add($err) }
        $children.Add((Get-SourceSummary $branch))
    }
    $result = Complete-SourceResult $result
    $result.children = $children.ToArray()
    return $result
}


function Collect-ScheduledTasks {
    $result = New-SourceResult 'scheduled_tasks' 'Task Scheduler'
    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
            $taskPath = [string]$task.TaskPath; $taskName = [string]$task.TaskName
            $record = [ordered]@{
                task_name = $taskName; task_path = $taskPath; state = [string]$task.State
                author = [string]$task.Author; description = [string]$task.Description
                actions = @($task.Actions | ForEach-Object { [ordered]@{ id = [string]$_.Id; execute = [string]$_.Execute; arguments = [string]$_.Arguments; working_directory = [string]$_.WorkingDirectory } })
                triggers = @($task.Triggers | ForEach-Object { [ordered]@{ type = $_.CimClass.CimClassName; enabled = $_.Enabled; start_boundary = [string]$_.StartBoundary; end_boundary = [string]$_.EndBoundary } })
                principal = [ordered]@{ user_id = [string]$task.Principal.UserId; logon_type = [string]$task.Principal.LogonType; run_level = [string]$task.Principal.RunLevel }
                xml = $null
            }
            try {
                $xml = Export-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
                $record.xml = [string]$xml
            } catch { Add-SourceError $result $_ 'ExportScheduledTask' "$taskPath$taskName" }
            $result.records.Add($record)
        }
    } catch { Add-SourceError $result $_ 'EnumerateScheduledTasks' 'Task Scheduler' }
    return Complete-SourceResult $result
}


function Collect-UserAssist {
    $paths = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BC1E25671}\Count'
    )
    $result = New-SourceResult 'userassist' $paths
    $children = [System.Collections.Generic.List[object]]::new()
    foreach ($path in $paths) {
        Test-PortableDeadline
        $branch = New-SourceResult 'registry_key' $path
        $key = $null
        try {
            $key = Get-Item -LiteralPath $path -ErrorAction Stop
            foreach ($name in $key.GetValueNames()) {
                try {
                    $raw = Read-RawRegistryValue $key $name
                    $entry = [ordered]@{
                        path = $path; name = $name; registry_type = $raw.registry_type
                        encoding = $raw.encoding; value = $raw.value
                    }
                    if ($raw.encoding -eq 'base64') {
                        $entry['length'] = [Convert]::FromBase64String($raw.value).Length
                    }
                    $branch.records.Add($entry)
                    $result.records.Add($entry)
                } catch { Add-SourceError $branch $_ 'ReadRegistryValue' "$path\$name" }
            }
        } catch { Add-SourceError $branch $_ 'OpenRegistryKey' $path }
        finally { if ($null -ne $key) { $key.Dispose() } }
        $branch = Complete-SourceResult $branch
        foreach ($err in $branch.errors) { $result.errors.Add($err) }
        $children.Add((Get-SourceSummary $branch))
    }
    $result = Complete-SourceResult $result
    # A successfully read empty branch still counts as available coverage.
    if (@($children | Where-Object { $_.status -eq 'success' }).Count -gt 0 -and $result.errors.Count -gt 0) {
        $result.status = 'partial'
    }
    $result.children = $children.ToArray()
    return $result
}


function Collect-ServiceEvents {
    $result = New-SourceResult 'service_events' ([ordered]@{ log_name = 'System'; event_id = 7045; max_events = 50 })
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; ID = 7045 } -MaxEvents 50 -ErrorAction Stop |
            ForEach-Object {
                $event = $_
                try { $result.records.Add($event.ToXml()) }
                catch { Add-SourceError $result $_ 'SerializeEventXml' 'System/7045' }
                finally { $event.Dispose() }
            }
    } catch {
        # Stable error identifier; do not match localized human-readable messages.
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            Add-SourceError $result $_ 'Get-WinEvent' 'System/7045'
        }
    }
    return Complete-SourceResult $result
}


function Get-SourceSummary {
    param($Result)
    return [ordered]@{
        source = $Result.source; location = $Result.location; status = $Result.status
        started_at = $Result.started_at; finished_at = $Result.finished_at
        record_count = $Result.records.Count; output_file = $Result.output_file
        errors = $Result.errors.ToArray(); children = @($Result.children); availability = $Result.availability
    }
}


# Native raw-file collection. No target resolution, decoding or external executables.
function Add-PortableSourceNotice($Result, [string]$Status, [string]$Operation, [string]$Path, [string]$Message) {
    $Result.errors.Add([ordered]@{status=$Status;operation=$Operation;path=$Path;category=$Status;error_id=$null;exception_type=$null;message=$Message})
}

function Test-PortablePathWithin([string]$Path, [string]$Root) {
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $parent = [IO.Path]::GetFullPath($Root).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    return $candidate.Equals($parent, [StringComparison]::OrdinalIgnoreCase) -or $candidate.StartsWith($parent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)
}

function Copy-PortableRawFile([string]$Path, [string]$DestinationDirectory, [long]$LimitBytes=0) {
    $Path=Get-PortableLocalPath $Path
    $info = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($info.PSIsContainer) { throw 'Expected a regular file' }
    if (($info.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse points are not followed' }
    Test-PortableDeadline
    $originalLength = [long]$info.Length
    if ($MaxTotalBytes -gt 0 -and $script:PortableCopiedBytes + $originalLength -gt $MaxTotalBytes) {
        $exception=[IO.InvalidDataException]::new('Total original-file byte budget exceeded')
        $exception.Data['portable_status']='skipped'; throw $exception
    }
    $originalWrite = $info.LastWriteTimeUtc
    if ($LimitBytes -gt 0 -and $originalLength -gt $LimitBytes) {
        $exception = [IO.InvalidDataException]::new('File exceeds MaxArtifactBytes; no truncated copy was created')
        $exception.Data['portable_status'] = 'skipped'
        throw $exception
    }
    $null = New-Item -ItemType Directory -Path $DestinationDirectory -Force -ErrorAction Stop
    $destination = Join-Path $DestinationDirectory ([guid]::NewGuid().ToString('N') + '_' + $info.Name)
    $temporary = $destination + '.part'
    $inputStream = $null; $outputStream = $null; $hashStream = $null; $hasher = $null
    try {
        $inputStream = [IO.File]::Open($info.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $outputStream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $buffer = New-Object byte[] 65536
        [long]$copied = 0
        while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            Test-PortableDeadline
            $copied += $read
            if ($MaxTotalBytes -gt 0 -and $script:PortableCopiedBytes + $copied -gt $MaxTotalBytes) {
                $exception=[IO.InvalidDataException]::new('Total byte budget exceeded during copy')
                $exception.Data['portable_status']='skipped'; throw $exception
            }
            if ($LimitBytes -gt 0 -and $copied -gt $LimitBytes) {
                $exception = [IO.InvalidDataException]::new('File grew beyond MaxArtifactBytes during copying')
                $exception.Data['portable_status'] = 'skipped'
                throw $exception
            }
            $outputStream.Write($buffer, 0, $read)
        }
        $outputStream.Dispose(); $outputStream = $null
        $inputStream.Dispose(); $inputStream = $null
        $hasher = [Security.Cryptography.SHA256]::Create()
        $hashStream = [IO.File]::OpenRead($temporary)
        $hash = ([BitConverter]::ToString($hasher.ComputeHash($hashStream)) -replace '-', '').ToLowerInvariant()
        $hashStream.Dispose(); $hashStream = $null
        $after = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $changed = $originalLength -ne $after.Length -or $originalWrite -ne $after.LastWriteTimeUtc -or $copied -ne $originalLength
        [IO.File]::Move($temporary, $destination)
        $script:PortableCopiedBytes += $copied
        return [ordered]@{
            path=$info.FullName; name=$info.Name; saved_path=$destination
            length=$originalLength; read_length=$copied; truncated=$false; encoding='original_bytes'
            creation_time=$info.CreationTimeUtc.ToString('o'); last_write_time=$originalWrite.ToString('o')
            sha256=$hash; hash_scope='saved_file'; source_changed=$changed
            consistency='best_effort_live_copy'; collected_at=[DateTime]::UtcNow.ToString('o')
        }
    } finally {
        if ($null -ne $inputStream) { $inputStream.Dispose() }
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        if ($null -ne $hashStream) { $hashStream.Dispose() }
        if ($null -ne $hasher) { $hasher.Dispose() }
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Collect-PortableFiles([string]$Name, [object[]]$Specs, [string]$CollectionRoot, [string]$Group, [long]$LimitBytes=0) {
    $result = New-SourceResult $Name @($Specs | ForEach-Object { $_.root })
    $children = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($spec in $Specs) {
        Test-PortableDeadline
        $branch = New-SourceResult $spec.label $spec.root
        if ([string]::IsNullOrWhiteSpace($spec.root)) {
            Add-PortableSourceNotice $branch 'not_found' 'ResolveSourcePath' '' 'Profile or system directory is unavailable'
        } else {
            try {
                $directory = Get-Item -LiteralPath (Get-PortableLocalPath $spec.root) -Force -ErrorAction Stop
                if (-not $directory.PSIsContainer) { throw 'Expected a source directory' }
                if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    Add-PortableSourceNotice $branch 'skipped' 'EnumerateFiles' $spec.root 'Reparse directory is not followed'
                } elseif (Test-PortablePathWithin $directory.FullName $CollectionRoot) {
                    Add-PortableSourceNotice $branch 'skipped' 'EnumerateFiles' $spec.root 'Collection output is excluded'
                } else {
                    Get-ChildItem -LiteralPath $directory.FullName -Filter $spec.filter -File -Force -ErrorAction Stop | ForEach-Object {
                        $file = $_
                        if (-not $seen.ContainsKey($file.FullName)) {
                            $seen[$file.FullName] = $true
                            if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or (Test-PortablePathWithin $file.FullName $CollectionRoot)) {
                                Add-PortableSourceNotice $branch 'skipped' 'CopyRawFile' $file.FullName 'Reparse file or collection output is excluded'
                            } else {
                                try {
                                    $destination = Join-Path (Join-Path (Join-Path $CollectionRoot $Group) 'files') $Name
                                    $record = Copy-PortableRawFile $file.FullName $destination $LimitBytes
                                    $record['branch'] = $spec.label
                                    $record['scope'] = if ($spec.scope) { $spec.scope } elseif ($script:PortableProfile -and -not $script:PortableProfile.current) { 'registered_profile' } else { 'current_process_profile' }
                                    $branch.records.Add($record); $result.records.Add($record)
                                    if ($record.source_changed) { Add-PortableSourceNotice $branch 'partial' 'CopyRawFile' $file.FullName 'Source changed during copying; saved bytes are not a consistent snapshot' }
                                } catch { Add-SourceError $branch $_ 'CopyRawFile' $file.FullName }
                            }
                        }
                    }
                }
            } catch { Add-SourceError $branch $_ 'EnumerateFiles' $spec.root }
        }
        $branch = Complete-SourceResult $branch
        foreach ($errorRecord in $branch.errors) { $result.errors.Add($errorRecord) }
        $children.Add((Get-SourceSummary $branch))
    }
    $result.children = $children.ToArray()
    return Complete-SourceResult $result
}

function Join-PortableOptionalPath([string]$Root, [string]$Child) {
    if (-not [string]::IsNullOrWhiteSpace($Root)) { return Join-Path $Root $Child }
    return $null
}

function Collect-PowerShellHistory([string]$CollectionRoot, [long]$LimitBytes=0) {
    $specs = @(
        @{label='appdata_psreadline';root=(Join-PortableOptionalPath (Get-PortableProfileDirectory 'appdata') 'Microsoft\Windows\PowerShell\PSReadLine');filter='*.txt'},
        @{label='windows_powershell_profile';root=(Join-PortableOptionalPath (Get-PortableProfileDirectory 'documents') 'WindowsPowerShell\PSReadLine');filter='*.txt'},
        @{label='powershell_profile';root=(Join-PortableOptionalPath (Get-PortableProfileDirectory 'documents') 'PowerShell\PSReadLine');filter='*.txt'}
    )
    return Collect-PortableFiles 'powershell_history' $specs $CollectionRoot 'logs' $LimitBytes
}

function Collect-InstallationLogs([string]$CollectionRoot, [long]$LimitBytes=0) {
    $specs = @(
        @{label='cbs';root=(Join-PortableOptionalPath $env:windir 'Logs\CBS');filter='*.log';scope='machine'},
        @{label='dism';root=(Join-PortableOptionalPath $env:windir 'Logs\DISM');filter='*.log';scope='machine'},
        @{label='panther';root=(Join-PortableOptionalPath $env:windir 'Panther');filter='*.log';scope='machine'},
        @{label='setupapi';root=(Join-PortableOptionalPath $env:windir 'inf');filter='setupapi*.log';scope='machine'},
        @{label='windows_temp';root=(Join-PortableOptionalPath $env:windir 'Temp');filter='*.log';scope='machine'},
        @{label='user_temp';root=$env:TEMP;filter='*.log';scope='current_process_environment'}
    )
    return Collect-PortableFiles 'installation_logs' $specs $CollectionRoot 'logs' $LimitBytes
}

function Collect-RecentFiles([string]$CollectionRoot, [long]$LimitBytes=0) {
    $recentRoot = Join-PortableOptionalPath (Get-PortableProfileDirectory 'appdata') 'Microsoft\Windows\Recent'
    $specs = @(
        @{label='automatic_destinations';root=(Join-PortableOptionalPath $recentRoot 'AutomaticDestinations');filter='*.automaticDestinations-ms'},
        @{label='custom_destinations';root=(Join-PortableOptionalPath $recentRoot 'CustomDestinations');filter='*.customDestinations-ms'}
    )
    return Collect-PortableFiles 'recent_files' $specs $CollectionRoot 'recent' $LimitBytes
}

function Collect-RecentRegistry {
    return Collect-RegistryHistory 'recent_registry' @(
        (Get-PortableRegistryPath 'Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'),
        (Get-PortableRegistryPath 'Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32')
    )
}

function Collect-ExplorerHistory {
    return Collect-RegistryHistory 'explorer_history' @(
        (Get-PortableRegistryPath 'Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'),
        (Get-PortableRegistryPath 'Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2'),
        (Get-PortableRegistryPath 'Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU')
    )
}

function Collect-ServiceState {
    $result = New-SourceResult 'services_state' 'Win32_Service'
    try {
        Get-CimInstance Win32_Service -ErrorAction Stop |
            Select-Object Name,DisplayName,State,StartMode,StartName,PathName |
            ForEach-Object { $result.records.Add($_) }
    } catch { Add-SourceError $result $_ 'GetServiceState' 'Win32_Service' }
    return Complete-SourceResult $result
}

function Invoke-PortableSourceGroup([string]$Group, [object[]]$Specs, [string]$CollectionRoot, $Metadata, [long]$LimitBytes=0) {
    $directory = Join-Path $CollectionRoot $Group
    $null = New-Item -ItemType Directory -Path $directory -Force -ErrorAction Stop
    $summaryPath = Join-Path $CollectionRoot ($Group + '.json')
    $sources = New-Object System.Collections.Generic.List[object]
    $summary = [ordered]@{
        schema_version='2.0'; metadata=$Metadata; status='in_progress'
        started_at=[DateTime]::UtcNow.ToString('o'); finished_at=$null
        sources=@(); counts=[ordered]@{}; max_artifact_bytes=$LimitBytes
        scope=$ProfileScope; timeout_mode='cooperative'; pending_sources=@($Specs | ForEach-Object { $_.name })
    }
    $null = Write-PortableJson $summaryPath $summary
    foreach ($spec in $Specs) {
        $script:PortableDeadline = if ($SourceTimeoutSeconds -gt 0) { [DateTime]::UtcNow.AddSeconds($SourceTimeoutSeconds) } else { $null }
        try {
            if ($spec.ContainsKey('selected') -and -not $spec.selected) {
                $result=New-SourceResult $spec.name $null
                Add-PortableSourceNotice $result 'skipped' 'SelectSource' $spec.name 'Excluded by source selection'
            } else { $result = Invoke-PortableSpec $spec $CollectionRoot $LimitBytes }
            if ($null -eq $result -or $null -eq $result.records) { throw 'Source returned no result envelope' }
            # Some imported collectors assign children after computing their status.
            $result = Complete-SourceResult $result
        } catch {
            $result = New-SourceResult $spec.name $null
            Add-SourceError $result $_ 'CollectSource' $spec.name
            $result = Complete-SourceResult $result
        }
        $script:PortableDeadline=$null
        $result.output_file = Join-Path $directory ($spec.name + '.raw.json')
        try {
            $null = Write-PortableJson $result.output_file ([ordered]@{
                schema_version='2.0'; metadata=$Metadata; source=(Get-SourceSummary $result); records=$result.records.ToArray()
            })
        } catch {
            Add-SourceError $result $_ 'WriteSourceResult' $result.output_file
            $result.status = 'failed'
            $result.output_file = $null
        }
        $sources.Add((Get-SourceSummary $result))
        $summary.sources = $sources.ToArray()
        $summary.counts[$spec.name] = $result.records.Count
        $summary.pending_sources = @($Specs | Where-Object { $_.name -notin @($sources | ForEach-Object { $_.source }) } | ForEach-Object { $_.name })
        # Each completed source is durable even when a later source fails or hangs.
        $null = Write-PortableJson $summaryPath $summary
    }
    $summary.status = 'success'
    $selectedResults=@($sources | Where-Object { @($_.errors | Where-Object {$_.operation -eq 'SelectSource'}).Count -eq 0 })
    if ($selectedResults.Count -eq 0) { $summary.status='skipped' }
    $problematic = @($selectedResults | Where-Object { $_.status -notin @('success','not_applicable') })
    if ($problematic.Count -gt 0) {
        $summary.status = 'partial'
        if (@($selectedResults | Where-Object { $_.status -in @('success','partial') }).Count -eq 0) {
            $statuses = @($selectedResults | ForEach-Object { $_.status } | Select-Object -Unique)
            $summary.status = 'failed'
            if ($statuses.Count -eq 1) { $summary.status = $statuses[0] }
        }
    }
    $summary.finished_at = [DateTime]::UtcNow.ToString('o')
    $null = Write-PortableJson $summaryPath $summary
    return $summary
}

function Get-PortableLogSpecs {
    return @(
        @{name='services';command='Collect-Services'},
        @{name='services_state';command='Collect-ServiceState'},
        @{name='explorer_history';command='Collect-ExplorerHistory'},
        @{name='office_mru';command='Collect-OfficeMru'},
        @{name='powershell_history';command='Collect-PowerShellHistory';files=$true},
        @{name='rdp_history';command='Collect-RdpHistory'},
        @{name='scheduled_tasks';command='Collect-ScheduledTasks'},
        @{name='installation_logs';command='Collect-InstallationLogs';files=$true},
        @{name='userassist';command='Collect-UserAssist'},
        @{name='service_events';command='Collect-ServiceEvents'}
    )
}

function Get-PortableRecentSpecs {
    return @(
        @{name='recent_files';command='Collect-RecentFiles';files=$true}
    )
}

function Test-PortableDeadline {
    if ($null -ne $script:PortableDeadline -and [DateTime]::UtcNow -gt $script:PortableDeadline) {
        $exception = [TimeoutException]::new('Cooperative source deadline exceeded')
        $exception.Data['portable_status']='timeout'
        throw $exception
    }
}

function Get-PortableRegistryPath([string]$Relative) {
    $root='HKCU:'
    if ($null -ne $script:PortableProfile) { $root=$script:PortableProfile.registry_root }
    if (-not $root) {
        $exception=[IO.FileNotFoundException]::new('User hive is not loaded; offline hives are not mounted')
        $exception.Data['portable_status']='not_found'; throw $exception
    }
    return $root + '\' + $Relative
}

function Get-PortableRegistryDescendants([string]$Path, $Result) {
    $queue=New-Object 'System.Collections.Generic.Queue[string]'
    $queue.Enqueue($Path)
    while($queue.Count -gt 0){
        Test-PortableDeadline
        $parent=$queue.Dequeue()
        try{
            Get-ChildItem -LiteralPath $parent -ErrorAction Stop | ForEach-Object {
                $next=if($_.PSPath){[string]$_.PSPath}else{'Registry::'+$_.Name}
                $queue.Enqueue($next)
                Write-Output $_
            }
        }catch{Add-SourceError $Result $_ 'EnumerateRegistrySubkeys' $parent}
    }
}

function Get-PortableProfileDirectory([string]$Name) {
    if ($null -ne $script:PortableProfile) { return [string]$script:PortableProfile[$Name] }
    switch ($Name) { 'path' {return $env:USERPROFILE}; 'appdata' {return $env:APPDATA}; 'localappdata' {return $env:LOCALAPPDATA}; 'documents' {return Join-PortableOptionalPath $env:USERPROFILE 'Documents'} }
}

function Resolve-PortableProfilePaths($Profile, $Result) {
    $Profile['path_source']=$(if($Profile.current){'environment_fallback'}else{'registered_profile'})
    if($Profile.current -and $Profile.sid){
        $key=$null
        try{
            $key=Get-Item -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$Profile.sid) -ErrorAction Stop
            $path=[string]$key.GetValue('ProfileImagePath')
            if($path){$Profile.path=$path;$Profile.path_source='registered_profile';$Profile.appdata=Join-PortableOptionalPath $path 'AppData\Roaming';$Profile.localappdata=Join-PortableOptionalPath $path 'AppData\Local'}
        }catch{Add-SourceError $Result $_ 'ResolveCurrentProfile' $Profile.sid}
        finally{if($key){$key.Dispose()}}
    }
    $Profile['documents']=Join-PortableOptionalPath $Profile.path 'Documents'
    if($Profile.registry_root){
        $key=$null;$path=$Profile.registry_root+'\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        try{
            $key=Get-Item -LiteralPath $path -ErrorAction Stop
            foreach($entry in @(@{name='AppData';field='appdata'},@{name='Local AppData';field='localappdata'},@{name='Personal';field='documents'})){
                $raw=[string]$key.GetValue($entry.name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                if(-not $raw){continue}
                if($Profile.path){$raw=$raw.Replace('%USERPROFILE%',[string]$Profile.path)}
                if(-not $Profile.current -and $raw -match '(?i)%(USERPROFILE|APPDATA|LOCALAPPDATA|USERNAME|HOMEPATH|HOMEDRIVE)%'){
                    Add-PortableSourceNotice $Result 'skipped' 'ResolveProfileFolder' $path 'User-specific environment variable cannot be expanded in another profile';continue
                }
                $Profile[$entry.field]=Get-PortableLocalPath $raw
            }
        }catch{Add-SourceError $Result $_ 'ResolveProfileFolders' $path}
        finally{if($key){$key.Dispose()}}
    }
}

function Collect-PortableProfiles {
    $r=New-SourceResult 'profiles' 'Current identity and HKLM ProfileList; loaded HKU only'
    $sid=$null; $identity=$null
    try { $identity=[Security.Principal.WindowsIdentity]::GetCurrent(); $sid=$identity.User.Value }
    catch { Add-SourceError $r $_ 'CurrentSID' '' }
    finally { if ($identity) { $identity.Dispose() } }
    $r.records.Add([ordered]@{sid=$sid;path=$env:USERPROFILE;appdata=$env:APPDATA;localappdata=$env:LOCALAPPDATA;registry_root='HKCU:';current=$true})
    if ($ProfileScope -eq 'Accessible') {
        $root='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        try {
            Get-ChildItem -LiteralPath $root -ErrorAction Stop | ForEach-Object {
                $key=$_
                try {
                    Test-PortableDeadline
                    if ($key.PSChildName -ne $sid -and $key.PSChildName -match '^S-1-\d+(-\d+)+$') {
                        $path=[string]$key.GetValue('ProfileImagePath')
                        $hive='Registry::HKEY_USERS\'+$key.PSChildName; $loaded=$false; $hiveKey=$null
                        try { $hiveKey=Get-Item -LiteralPath $hive -ErrorAction Stop; $loaded=$true }
                        catch { Add-SourceError $r $_ 'InspectLoadedHive' $hive }
                        finally { if ($hiveKey) { $hiveKey.Dispose() } }
                        $r.records.Add([ordered]@{sid=$key.PSChildName;path=$path;appdata=(Join-PortableOptionalPath $path 'AppData\Roaming');localappdata=(Join-PortableOptionalPath $path 'AppData\Local');registry_root=$(if($loaded){$hive}else{$null});current=$false})
                    }
                } catch { Add-SourceError $r $_ 'ReadProfile' $key.Name }
                finally { $key.Dispose() }
            }
        } catch { Add-SourceError $r $_ 'EnumerateProfiles' $root }
    }
    foreach($profile in $r.records){Resolve-PortableProfilePaths $profile $r}
    $script:PortableProfiles=$r.records.ToArray()
    return Complete-SourceResult $r
}

function Invoke-PortableReadCommand([string]$Executable, [string[]]$Arguments) {
    Test-PortableDeadline
    $path=$Executable
    if($env:SystemRoot -and $Executable -in @('sc.exe','netsh.exe','ipconfig.exe','route.exe','arp.exe','netstat.exe','tasklist.exe','winrm.cmd','klist.exe')){$path=Join-Path $env:SystemRoot ('System32\'+$Executable)}
    $command=Get-Command $path -CommandType Application -ErrorAction Stop
    $previousPreference=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $lines=@(& $command.Source @Arguments 2>&1)
        $exitCode=$LASTEXITCODE
    } finally { $ErrorActionPreference=$previousPreference }
    return [ordered]@{command=$Executable;arguments=$Arguments;exit_code=$exitCode;raw=@($lines | ForEach-Object {[string]$_})}
}

function Add-PortableCommandResult($Result, [string]$Executable, [string[]]$Arguments) {
    try {
        $record=Invoke-PortableReadCommand $Executable $Arguments
        $Result.records.Add($record)
        if ($record.exit_code -ne 0) { Add-PortableSourceNotice $Result 'failed' 'NativeCommand' $Executable ('Exit code '+$record.exit_code+'; see raw output') }
    } catch { Add-SourceError $Result $_ 'NativeCommand' $Executable }
}

function Get-PortableLocalPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Path is empty' }
    $expanded=[Environment]::ExpandEnvironmentVariables($Path)
    if ($expanded -match '^\\\\|^//|^[a-z]+://' -or $expanded -match '%[^%]+%') {
        $exception=[IO.InvalidDataException]::new('Remote, device or unresolved path is outside local collection scope')
        $exception.Data['portable_status']='skipped'; throw $exception
    }
    if (-not [IO.Path]::IsPathRooted($expanded)) { throw 'Expected absolute local path' }
    return [IO.Path]::GetFullPath($expanded)
}

function Find-PortableFiles($Result, [string]$Root, [string[]]$Patterns, [int]$Depth=0, [switch]$MissingIsNormal) {
    $queue=New-Object 'System.Collections.Generic.Queue[object]'
    $queue.Enqueue(@{path=$Root;depth=0})
    while ($queue.Count -gt 0) {
        Test-PortableDeadline
        $item=$queue.Dequeue()
        try {
            $path=Get-PortableLocalPath $item.path
            $directory=Get-Item -LiteralPath $path -Force -ErrorAction Stop
            if (-not $directory.PSIsContainer) { throw 'Expected directory' }
            if (($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or ($script:PortableOutput -and (Test-PortablePathWithin $directory.FullName $script:PortableOutput))) {
                Add-PortableSourceNotice $Result 'skipped' 'DiscoverFiles' $path 'Reparse directory or output excluded'; continue
            }
            Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop | ForEach-Object {
                Test-PortableDeadline
                if (($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    Add-PortableSourceNotice $Result 'skipped' 'DiscoverFiles' $_.FullName 'Reparse entry excluded'
                } elseif ($_.PSIsContainer) {
                    if ($item.depth -lt $Depth) { $queue.Enqueue(@{path=$_.FullName;depth=$item.depth+1}) }
                } else {
                    foreach ($pattern in $Patterns) { if ($_.Name -like $pattern) { Write-Output $_.FullName; break } }
                }
            }
        } catch {
            $missing = $_.CategoryInfo.Category -eq 'ObjectNotFound' -or $_.Exception -is [IO.DirectoryNotFoundException] -or $_.Exception -is [IO.FileNotFoundException]
            if (-not ($MissingIsNormal -and $missing)) { Add-SourceError $Result $_ 'DiscoverFiles' $item.path }
        }
    }
}

function Save-PortableCandidate($Result, [string]$Path, [string]$Category, [string]$Group, [long]$Limit=0, $Profile=$null) {
    Test-PortableDeadline
    try {
        $full=Get-PortableLocalPath $Path
        if (Test-PortablePathWithin $full $script:PortableOutput) { throw 'Output excluded from collection' }
        if (@($Result.records | Where-Object { $_.path -eq $full }).Count -gt 0) { return }
        $destination=Join-Path (Join-Path (Join-Path $script:PortableOutput $Group) 'files') $Result.source
        $record=Copy-PortableRawFile $full $destination $Limit
        $record['category']=$Category
        $record['profile_sid']=$(if($Profile){$Profile.sid}else{$null})
        $record['profile_path']=$(if($Profile){$Profile.path}else{$null})
        $Result.records.Add($record)
        if ($script:PortableAclPaths) {
            $script:PortableAclPaths[$full]=$true
            $script:PortableAclPaths[[IO.Path]::GetDirectoryName($full)]=$true
        }
        if ($record.source_changed) { Add-PortableSourceNotice $Result 'partial' 'CopyFile' $full 'Source changed during copy' }
    } catch { Add-SourceError $Result $_ 'CopyFile' $Path }
}

function Collect-PortableIdentitySource {
    $r=New-SourceResult 'token' 'Current process token and whoami'
    $data=Get-PortableIdentity
    $r.records.Add($data)
    foreach ($failure in $data.errors) { Add-PortableSourceNotice $r 'failed' $failure.operation '' $failure.message }
    return Complete-SourceResult $r
}

function Collect-PortableOS {
    $r=New-SourceResult 'os' 'Win32_OperatingSystem / Win32_QuickFixEngineering'
    foreach ($class in @('Win32_OperatingSystem','Win32_QuickFixEngineering')) {
        try {
            Get-CimInstance -ClassName $class -OperationTimeoutSec 30 -ErrorAction Stop | ForEach-Object {
                Test-PortableDeadline
                $record=if ($class -eq 'Win32_OperatingSystem') { $_ | Select-Object Caption,Version,BuildNumber,OSArchitecture,InstallDate,LastBootUpTime,SystemDirectory,WindowsDirectory } else { $_ | Select-Object HotFixID,Description,InstalledOn,InstalledBy }
                $r.records.Add([ordered]@{class=$class;data=$record})
            }
        } catch { Add-SourceError $r $_ 'ReadOS' $class }
    }
    return Complete-SourceResult $r
}

function Read-PortableXml([string]$Path) {
    $settings=[Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver=$null
    $settings.MaxCharactersInDocument=16777216
    $reader=$null
    try {
        $reader=[Xml.XmlReader]::Create($Path,$settings)
        $document=[Xml.XmlDocument]::new(); $document.XmlResolver=$null; $document.Load($reader)
        return ,$document
    } finally { if ($reader) { $reader.Dispose() } }
}

function Collect-PortableRoles {
    $r=New-SourceResult 'roles' 'Installed role registry keys'
    foreach ($spec in @(
        @{name='iis';path='HKLM:\SOFTWARE\Microsoft\InetStp'},
        @{name='sql_server';path='HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server'},
        @{name='exchange';path='HKLM:\SOFTWARE\Microsoft\ExchangeServer'},
        @{name='globalprotect';path='HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect\PanSetup'}
    )) {
        $key=$null
        try {
            $key=Get-Item -LiteralPath $spec.path -ErrorAction Stop
            $values=New-Object System.Collections.Generic.List[object]
            foreach ($name in @($key.GetValueNames())) { $values.Add((Read-RawRegistryValue $key $name)) }
            $r.records.Add([ordered]@{role=$spec.name;path=$spec.path;present=$true;values=$values.ToArray()})
        } catch { Add-SourceError $r $_ 'DetectRole' $spec.path }
        finally { if($key){$key.Dispose()} }
    }
    return Complete-SourceResult $r
}

function Collect-PortableIIS {
    $r=New-SourceResult 'iis' 'IIS global config, worker configs, site and application directories'
    $paths=New-Object System.Collections.Generic.List[string]
    if ($env:windir) { $paths.Add((Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config')) }
    try {
        Get-CimInstance Win32_Process -Filter "Name='w3wp.exe'" -OperationTimeoutSec 30 -ErrorAction Stop | ForEach-Object {
            $r.records.Add([ordered]@{kind='worker';pid=[int]$_.ProcessId;command_line=$_.CommandLine;path=$_.ExecutablePath})
            if ($_.CommandLine -match '(?i)(?:^|\s)-h\s+"([^"]+)"') { $paths.Add($matches[1]) }
        }
    } catch { Add-SourceError $r $_ 'DiscoverWorkers' 'Win32_Process/w3wp.exe' }
    $roots=New-Object System.Collections.Generic.List[string]
    $roots.Add((Join-PortableOptionalPath $env:SystemDrive 'inetpub\wwwroot'))
    foreach ($path in @($paths | Select-Object -Unique)) {
        $before=$r.records.Count
        Save-PortableCandidate $r $path 'iis_configuration' 'configs' $MaxFileBytes
        if ($r.records.Count -eq $before) { continue }
        $copy=$r.records[$r.records.Count-1]
        try {
            $doc=Read-PortableXml $copy.saved_path
            foreach ($site in $doc.SelectNodes('/configuration/system.applicationHost/sites/site')) {
                $bindings=@($site.SelectNodes('./bindings/binding') | ForEach-Object { [ordered]@{protocol=$_.GetAttribute('protocol');binding_information=$_.GetAttribute('bindingInformation')} })
                foreach ($app in $site.SelectNodes('./application')) {
                    foreach ($directory in $app.SelectNodes('./virtualDirectory')) {
                        $rawPath=$directory.GetAttribute('physicalPath')
                        $r.records.Add([ordered]@{kind='site_directory';site=$site.GetAttribute('name');site_id=$site.GetAttribute('id');application=$app.GetAttribute('path');pool=$app.GetAttribute('applicationPool');virtual_path=$directory.GetAttribute('path');physical_path_raw=$rawPath;bindings=$bindings;source_file=$path})
                        try { $local=Get-PortableLocalPath $rawPath; $roots.Add($local); $script:PortableAclPaths[$local]=$true }
                        catch { Add-SourceError $r $_ 'ResolveIISDirectory' $rawPath }
                    }
                }
            }
            foreach ($pool in $doc.SelectNodes('/configuration/system.applicationHost/applicationPools/add')) {
                $r.records.Add([ordered]@{kind='application_pool';name=$pool.GetAttribute('name');raw_xml=$pool.OuterXml;source_file=$path})
            }
        } catch { Add-SourceError $r $_ 'ParseIISLocations' $path }
    }
    $script:PortableIISRoots=@($roots | Where-Object { $_ } | Select-Object -Unique)
    $r.records.Add([ordered]@{kind='discovery_roots';paths=$script:PortableIISRoots;note='Only local paths are followed; fallback inetpub/wwwroot included'})
    return Complete-SourceResult $r
}

function Get-PortableConfigSpecs {
    $specs=New-Object System.Collections.Generic.List[object]
    foreach ($relative in @('Panther\unattend.xml','Panther\unattend-original.xml','System32\Sysprep\Panther\unattend.xml','System32\inetsrv\config\applicationHost.config')) {
        $specs.Add(@{path=(Join-PortableOptionalPath $env:windir $relative);category='windows_setup_or_iis'})
    }
    $specs.Add(@{path=(Join-PortableOptionalPath $env:ProgramData 'Microsoft\Network\Connections\Pbk\rasphone.pbk');category='vpn_ras'})
    foreach ($profile in $script:PortableProfiles) {
        foreach ($item in @(
            @{base=$profile.path;child='.gitconfig';category='git'},@{base=$profile.path;child='.git-credentials';category='git'},
            @{base=$profile.path;child='.aws\config';category='aws'},@{base=$profile.path;child='.aws\credentials';category='aws'},
            @{base=$profile.appdata;child='postgresql\pgpass.conf';category='postgresql'},@{base=$profile.appdata;child='postgresql\pg_service.conf';category='postgresql'},
            @{base=$profile.appdata;child='Microsoft\Network\Connections\Pbk\rasphone.pbk';category='vpn_ras'}
        )) { $specs.Add(@{path=(Join-PortableOptionalPath $item.base $item.child);category=$item.category;profile=$profile}) }
        foreach ($item in @(
            @{base=$profile.path;child='OpenVPN\config';patterns=@('*.ovpn');category='vpn_openvpn';depth=2},
            @{base=$profile.localappdata;child='Cisco\Cisco Secure Client\VPN';patterns=@('*.xml');category='vpn_cisco';depth=5},
            @{base=$profile.appdata;child='Microsoft\UserSecrets';patterns=@('secrets.json');category='dotnet';depth=5}
        )) { $specs.Add(@{root=(Join-PortableOptionalPath $item.base $item.child);patterns=$item.patterns;category=$item.category;depth=$item.depth;profile=$profile}) }
    }
    $programRoots=@($env:ProgramFiles,${env:ProgramFiles(x86)},$env:ProgramW6432 | Where-Object { $_ } | Select-Object -Unique)
    foreach ($programRoot in $programRoots) {
        $specs.Add(@{root=(Join-Path $programRoot 'Microsoft SQL Server');patterns=@('ConfigurationFile.ini');category='sql_server';depth=5})
        $specs.Add(@{root=(Join-Path $programRoot 'Microsoft Exchange Server\V15');patterns=@('*.config');category='exchange';depth=4})
        $specs.Add(@{root=(Join-Path $programRoot 'Microsoft Exchange Server\V15\Config');patterns=@('*');category='exchange';depth=2})
        $specs.Add(@{root=(Join-Path $programRoot 'OpenVPN\config');patterns=@('*.ovpn');category='vpn_openvpn';depth=2})
    }
    foreach ($item in @(
        @{child='Cisco\Cisco Secure Client\VPN';patterns=@('*.xml');category='vpn_cisco';depth=5},
        @{child='OpenVPN\config';patterns=@('*.ovpn');category='vpn_openvpn';depth=2},
        @{child='WireGuard\Configurations';patterns=@('*.conf*');category='vpn_wireguard';depth=2},
        @{child='Ivanti';patterns=@('*.pulsepreconfig');category='vpn_ivanti';depth=4},
        @{child='Pulse Secure';patterns=@('*.pulsepreconfig');category='vpn_ivanti';depth=4},
        @{child='Fortinet';patterns=@('*.xml','*.conf');category='vpn_fortinet';depth=4},
        @{child='Microsoft\UserSecrets';patterns=@('secrets.json');category='dotnet';depth=5}
    )) { $specs.Add(@{root=(Join-PortableOptionalPath $env:ProgramData $item.child);patterns=$item.patterns;category=$item.category;depth=$item.depth}) }
    foreach ($root in $script:PortableIISRoots) { $specs.Add(@{root=$root;patterns=@('web.config','appsettings*.json');category='iis_application';depth=5}) }
    foreach($sqlRoot in @('HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server')){
        $instances=$null
        try {
            $instances=Get-Item -LiteralPath ($sqlRoot+'\Instance Names\SQL') -ErrorAction Stop
            foreach($name in $instances.GetValueNames()){
                $instance=[string]$instances.GetValue($name);$setup=$null
                try {
                    $setup=Get-Item -LiteralPath ($sqlRoot+'\'+$instance+'\Setup') -ErrorAction Stop
                    foreach($property in @('SQLPath','SQLBinRoot')){
                        $path=[string]$setup.GetValue($property)
                        if($path){$specs.Add(@{root=$path;patterns=@('ConfigurationFile.ini');depth=5;category='sql_server'})}
                    }
                }catch{if($script:PortableConfigDiscoveryResult){Add-SourceError $script:PortableConfigDiscoveryResult $_ 'DiscoverSQLInstancePath' $instance}}
                finally{if($setup){$setup.Dispose()}}
            }
        }catch{if($script:PortableConfigDiscoveryResult){Add-SourceError $script:PortableConfigDiscoveryResult $_ 'DiscoverSQLInstances' $sqlRoot}}
        finally{if($instances){$instances.Dispose()}}
    }
    # Registered installation paths augment, rather than replace, standard locations.
    foreach ($item in @(
        @{key='HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup';name='MsiInstallPath';patterns=@('*.config');category='exchange'},
        @{key='HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server';name='SQLPath';patterns=@('ConfigurationFile.ini');category='sql_server'}
    )) {
        $key=$null
        try { $key=Get-Item -LiteralPath $item.key -ErrorAction Stop; $path=[string]$key.GetValue($item.name); if($path){$specs.Add(@{root=$path;patterns=$item.patterns;depth=5;category=$item.category})} }
        catch { if($script:PortableConfigDiscoveryResult){Add-SourceError $script:PortableConfigDiscoveryResult $_ 'DiscoverInstallPath' $item.key} }
        finally {if($key){$key.Dispose()}}
    }
    return $specs.ToArray()
}

function Collect-PortableConfigs {
    $r=New-SourceResult 'config_files' 'Targeted local configuration files'
    $script:PortableConfigDiscoveryResult=$r
    try {
        foreach ($spec in @(Get-PortableConfigSpecs)) {
            Test-PortableDeadline
            if ($spec.ContainsKey('path')) { Save-PortableCandidate $r $spec.path $spec.category 'configs' $MaxFileBytes $spec.profile }
            else {
                foreach ($path in @(Find-PortableFiles $r $spec.root $spec.patterns $spec.depth -MissingIsNormal)) { Save-PortableCandidate $r $path $spec.category 'configs' $MaxFileBytes $spec.profile }
            }
        }
        # Follow explicit local configSource/appSettings file references only within
        # each web.config's directory. No URL fetch or arbitrary path expansion.
        foreach ($record in @($r.records.ToArray())) {
            if ($record.name -ne 'web.config') { continue }
            try {
                $doc=Read-PortableXml $record.saved_path
                $directory=[IO.Path]::GetDirectoryName($record.path)
                foreach ($node in $doc.SelectNodes('//*[@configSource] | /configuration/appSettings[@file]')) {
                    $relative=$node.GetAttribute('configSource'); if(-not $relative){$relative=$node.GetAttribute('file')}
                    $target=[IO.Path]::GetFullPath((Join-Path $directory $relative))
                    if (-not (Test-PortablePathWithin $target $directory)) { Add-PortableSourceNotice $r 'skipped' 'ConfigReference' $target 'Reference escapes application directory'; continue }
                    Save-PortableCandidate $r $target 'iis_external_config' 'configs' $MaxFileBytes
                }
            } catch { Add-SourceError $r $_ 'ReadConfigReferences' $record.path }
        }
    } catch { Add-SourceError $r $_ 'CollectConfigurations' '' }
    finally { $script:PortableConfigDiscoveryResult=$null }
    return Complete-SourceResult $r
}

function Collect-PortableSharedTextFiles {
    $r=New-SourceResult 'shared_text_files' 'Local non-administrative SMB share paths; raw text files only'
    $seen=@{}
    if ($null -eq $script:PortableAclPaths) { $script:PortableAclPaths=@{} }
    try {
        Get-SmbShare -ErrorAction Stop | Where-Object {
            $_.Path -and $_.Name -notmatch '\$$' -and $_.Special -ne $true
        } | ForEach-Object {
            Test-PortableDeadline
            $share=$_
            $root=[string]$share.Path
            try {
                $local=Get-PortableLocalPath $root
                $script:PortableAclPaths[$local]=$true
                foreach($path in @(Find-PortableFiles $r $local @('*.txt') $SharedTextSearchDepth -MissingIsNormal)) {
                    if($seen.ContainsKey($path)){continue}
                    $seen[$path]=$true
                    $before=$r.records.Count
                    Save-PortableCandidate $r $path 'smb_share_text' 'configs' $MaxSharedTextFileBytes
                    if($r.records.Count -gt $before){$r.records[$r.records.Count-1]['share_name']=$share.Name;$r.records[$r.records.Count-1]['share_path']=$local}
                }
            } catch { Add-SourceError $r $_ 'CollectShareTextFiles' $root }
        }
    } catch { Add-SourceError $r $_ 'ReadSMBShares' 'SMB' }
    return Complete-SourceResult $r
}

function Collect-PortableBrowser {
    $r=New-SourceResult 'browser_files' 'Raw history, bookmarks and settings; no decryption'
    foreach ($profile in $script:PortableProfiles) {
        foreach ($browser in @(
            @{name='chrome';root=(Join-PortableOptionalPath $profile.localappdata 'Google\Chrome\User Data');patterns=@('History','History-wal','History-shm','Bookmarks','Preferences','Secure Preferences','Local State')},
            @{name='edge';root=(Join-PortableOptionalPath $profile.localappdata 'Microsoft\Edge\User Data');patterns=@('History','History-wal','History-shm','Bookmarks','Preferences','Secure Preferences','Local State')},
            @{name='brave';root=(Join-PortableOptionalPath $profile.localappdata 'BraveSoftware\Brave-Browser\User Data');patterns=@('History','History-wal','History-shm','Bookmarks','Preferences','Local State')},
            @{name='chromium';root=(Join-PortableOptionalPath $profile.localappdata 'Chromium\User Data');patterns=@('History','History-wal','History-shm','Bookmarks','Preferences','Local State')},
            @{name='firefox';root=(Join-PortableOptionalPath $profile.appdata 'Mozilla\Firefox');patterns=@('profiles.ini','installs.ini','places.sqlite','places.sqlite-wal','places.sqlite-shm','prefs.js','containers.json','extensions.json')}
        )) {
            try {
                foreach ($path in @(Find-PortableFiles $r $browser.root $browser.patterns 3)) { Save-PortableCandidate $r $path $browser.name 'browser' $MaxArtifactBytes $profile }
            } catch { Add-SourceError $r $_ 'CollectBrowser' $browser.name }
        }
    }
    return Complete-SourceResult $r
}

function Collect-PortableFileACL {
    $r=New-SourceResult 'file_acl' 'Collected config files, parent directories, service binary paths'
    try {
        Get-CimInstance Win32_Service -OperationTimeoutSec 30 -ErrorAction Stop | ForEach-Object {
            $command=[Environment]::ExpandEnvironmentVariables([string]$_.PathName)
            $binary=$null
            if($command -match '^\s*"([^"]+)"'){$binary=$matches[1]}
            elseif($command -match '^\s*(.+?\.(?:exe|sys|dll))(?=\s|$)'){$binary=$matches[1]}
            if($binary -and [IO.Path]::IsPathRooted($binary)){$script:PortableAclPaths[$binary]=$true;$script:PortableAclPaths[[IO.Path]::GetDirectoryName($binary)]=$true}
        }
    } catch { Add-SourceError $r $_ 'DiscoverServicePaths' 'Win32_Service' }
    foreach ($path in @($script:PortableAclPaths.Keys)) {
        try {
            Test-PortableDeadline
            $local=Get-PortableLocalPath $path
            $acl=Get-Acl -LiteralPath $local -ErrorAction Stop
            $r.records.Add([ordered]@{path=$local;owner=$acl.Owner;group=$acl.Group;sddl=$acl.Sddl;access=@($acl.Access | ForEach-Object {[ordered]@{identity=[string]$_.IdentityReference;rights=[string]$_.FileSystemRights;type=[string]$_.AccessControlType;inherited=$_.IsInherited}});effective_access_evaluated=$false})
        } catch { Add-SourceError $r $_ 'ReadFileACL' $path }
    }
    return Complete-SourceResult $r
}

function Collect-PortableServiceACL {
    $r=New-SourceResult 'service_acl' 'Service security descriptors via sc.exe sdshow'
    try {
        Get-CimInstance Win32_Service -OperationTimeoutSec 30 -ErrorAction Stop | ForEach-Object {
            Test-PortableDeadline
            $name=[string]$_.Name
            try {
                $record=Invoke-PortableReadCommand 'sc.exe' @('sdshow',$name)
                $record['service']=$name; $record['effective_access_evaluated']=$false; $r.records.Add($record)
                if($record.exit_code -ne 0){Add-PortableSourceNotice $r $(if($record.exit_code -eq 5){'access_denied'}else{'failed'}) 'ReadServiceACL' $name ('Exit code '+$record.exit_code)}
            } catch { Add-SourceError $r $_ 'ReadServiceACL' $name }
        }
    } catch { Add-SourceError $r $_ 'EnumerateServices' 'Win32_Service' }
    return Complete-SourceResult $r
}

function Collect-PortableNetwork([string]$Name) {
    $r=New-SourceResult $Name 'Local network state; no scanning'
    $fallback=$null
    try {
        switch ($Name) {
            'interfaces' { $fallback=@('ipconfig.exe','/all'); Get-NetAdapter -ErrorAction Stop | ForEach-Object {$r.records.Add(($_ | Select-Object Name,InterfaceDescription,ifIndex,MacAddress,Status,LinkSpeed,Virtual))} }
            'addresses' { $fallback=@('ipconfig.exe','/all'); Get-NetIPAddress -ErrorAction Stop | ForEach-Object {$r.records.Add([ordered]@{interface=$_.InterfaceAlias;interface_index=[int]$_.InterfaceIndex;address=$_.IPAddress;prefix_length=[int]$_.PrefixLength;address_family=[string]$_.AddressFamily;address_family_raw=[int]$_.AddressFamily;state=[string]$_.AddressState;state_raw=[int]$_.AddressState})} }
            'routes' { $fallback=@('route.exe','print'); Get-NetRoute -ErrorAction Stop | ForEach-Object {$r.records.Add([ordered]@{destination=$_.DestinationPrefix;next_hop=$_.NextHop;interface=$_.InterfaceAlias;interface_index=[int]$_.ifIndex;metric=$_.RouteMetric;protocol=[string]$_.Protocol;policy_store=[string]$_.PolicyStore;address_family=[string]$_.AddressFamily})} }
            'dns_servers' { $fallback=@('ipconfig.exe','/all'); Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object {$r.records.Add([ordered]@{interface=$_.InterfaceAlias;interface_index=[int]$_.InterfaceIndex;address_family=[string]$_.AddressFamily;servers=@($_.ServerAddresses)})} }
            'dns_cache' { $fallback=@('ipconfig.exe','/displaydns'); Get-DnsClientCache -ErrorAction Stop | ForEach-Object {$r.records.Add(($_ | Select-Object Entry,Type,Data,Status,TimeToLive,Timestamp))} }
            'neighbors' { $fallback=@('arp.exe','-a'); Get-NetNeighbor -ErrorAction Stop | ForEach-Object {$r.records.Add([ordered]@{address=$_.IPAddress;mac=$_.LinkLayerAddress;state=[string]$_.State;state_raw=[int]$_.State;interface=$_.InterfaceAlias;interface_index=[int]$_.ifIndex;address_family=[string]$_.AddressFamily})} }
            'tcp' { $fallback=@('netstat.exe','-ano'); Get-NetTCPConnection -ErrorAction Stop | ForEach-Object {$r.records.Add([ordered]@{local_address=$_.LocalAddress;local_port=[int]$_.LocalPort;remote_address=$_.RemoteAddress;remote_port=[int]$_.RemotePort;state=[string]$_.State;state_raw=[int]$_.State;pid=[int]$_.OwningProcess;creation_time=$_.CreationTime})} }
            'udp' { $fallback=@('netstat.exe','-ano'); Get-NetUDPEndpoint -ErrorAction Stop | ForEach-Object {$r.records.Add([ordered]@{local_address=$_.LocalAddress;local_port=[int]$_.LocalPort;pid=[int]$_.OwningProcess;creation_time=$_.CreationTime})} }
            'processes' {
                $fallback=@('tasklist.exe','/fo','csv','/nh')
                Get-CimInstance Win32_Process -OperationTimeoutSec 30 -ErrorAction Stop | ForEach-Object {
                    Test-PortableDeadline
                    $r.records.Add([ordered]@{pid=[int]$_.ProcessId;parent_pid=[int]$_.ParentProcessId;name=$_.Name;path=$_.ExecutablePath;command_line=$_.CommandLine;creation_time=$_.CreationDate;session_id=$_.SessionId;details_status=$(if($_.ExecutablePath -and $_.CommandLine){'available'}else{'unavailable'});details_note=$(if(-not $_.ExecutablePath -or -not $_.CommandLine){'Provider returned null; access restriction, system process or process exit not distinguished'}else{$null})})
                }
            }
            'firewall' {
                $fallback=@('netsh.exe','advfirewall','show','allprofiles')
                Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {$r.records.Add([ordered]@{kind='profile';data=($_ | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowInboundRules,AllowLocalFirewallRules)})}
                Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
                    Test-PortableDeadline
                    $rule=$_
                    $record=[ordered]@{kind='rule';name=$rule.Name;display_name=$rule.DisplayName;enabled=[string]$rule.Enabled;direction=[string]$rule.Direction;action=[string]$rule.Action;profile=[string]$rule.Profile;ports=@();addresses=@();application=@()}
                    try {
                        $record.ports=@($rule | Get-NetFirewallPortFilter -ErrorAction Stop | Select-Object Protocol,LocalPort,RemotePort)
                        $record.addresses=@($rule | Get-NetFirewallAddressFilter -ErrorAction Stop | Select-Object LocalAddress,RemoteAddress)
                        $record.application=@($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop | Select-Object Program,Package)
                    } catch {Add-SourceError $r $_ 'ReadFirewallFilters' $rule.Name}
                    $r.records.Add($record)
                }
            }
            'proxy' { Add-PortableCommandResult $r 'netsh.exe' @('winhttp','show','proxy'); $key=$null; try{$key=Get-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop;foreach($name in @('ProxyEnable','ProxyServer','ProxyOverride','AutoConfigURL')){if($key.GetValueNames() -contains $name){$r.records.Add((Read-RawRegistryValue $key $name))}}}finally{if($key){$key.Dispose()}} }
            'management' {
                try{$r.records.Add([ordered]@{kind='smb_server';data=(Get-SmbServerConfiguration -ErrorAction Stop | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EnableSecuritySignature,EncryptData)})}catch{Add-SourceError $r $_ 'ReadSMBConfiguration' 'SMB'}
                try{Get-SmbShare -ErrorAction Stop | ForEach-Object {
                    $share=$_
                    $access=@()
                    try {$access=@(Get-SmbShareAccess -Name $share.Name -ErrorAction Stop | Select-Object Name,ScopeName,AccountName,AccessControlType,AccessRight)} catch {Add-SourceError $r $_ 'ReadSMBShareAccess' $share.Name}
                    if($share.Path){$script:PortableAclPaths[[string]$share.Path]=$true}
                    $r.records.Add([ordered]@{kind='smb_share';data=($share | Select-Object Name,Path,Description,EncryptData,Special,Temporary);share_access=$access;effective_access_evaluated=$false})
                }}catch{Add-SourceError $r $_ 'ReadSMBShares' 'SMB'}
                Add-PortableCommandResult $r 'winrm.cmd' @('enumerate','winrm/config/listener')
            }
            default { throw "Unknown network source: $Name" }
        }
    } catch {
        Add-SourceError $r $_ 'ReadNetworkState' $Name
        if ($fallback) { Add-PortableCommandResult $r $fallback[0] @($fallback | Select-Object -Skip 1) }
    }
    return Complete-SourceResult $r
}

function Get-PortableDomainQueries {
    $common=@('distinguishedname','samaccountname','description','objectsid','objectguid','objectclass')
    return @(
        @{name='all_users';filter='(&(objectCategory=person)(objectClass=user))';properties=($common+@('useraccountcontrol','lastlogontimestamp','pwdlastset','memberof','serviceprincipalname','mail'))},
        @{name='computers';filter='(objectCategory=computer)';properties=($common+@('dnshostname','operatingsystem','useraccountcontrol','lastlogontimestamp','msds-allowedtoactonbehalfofotheridentity'))},
        @{name='spn_accounts';filter='(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))';properties=($common+@('serviceprincipalname'))},
        @{name='asrep_targets';filter='(userAccountControl:1.2.840.113556.1.4.803:=4194304)';properties=$common},
        @{name='gpo_list';filter='(objectCategory=groupPolicyContainer)';properties=@('distinguishedname','displayname','gpcfilesyspath')},
        @{name='admin_objects';filter='(adminCount=1)';properties=($common+@('admincount','memberof'))},
        @{name='delegations';filter='(msDS-AllowedToDelegateTo=*)';properties=($common+@('msds-allowedtodelegateto','useraccountcontrol'))},
        @{name='gmsa_accounts';filter='(objectClass=msDS-GroupManagedServiceAccount)';properties=($common+@('memberof'))},
        @{name='groups';filter='(objectCategory=group)';properties=($common+@('member','memberof','grouptype'))}
    )
}

function Convert-PortableADAttribute($Value) {
    if ($Value -is [byte[]]) { return [ordered]@{encoding='base64';length=$Value.Length;value=[Convert]::ToBase64String($Value)} }
    if ($null -ne $Value -and $Value.GetType().Name -eq '__ComObject') {
        $high=$Value.GetType().InvokeMember('HighPart','GetProperty',$null,$Value,$null)
        $low=$Value.GetType().InvokeMember('LowPart','GetProperty',$null,$Value,$null)
        $ticks=([long]$high -shl 32) -bor ([long]$low -band 0xffffffffL)
        return $ticks
    }
    return $Value
}
function Get-PortableLDAPContext {
    if($null -ne $script:PortableLDAPContext){return $script:PortableLDAPContext}
    $ctx=[ordered]@{status='success';base=$null;path=$null;root_dse=$null;computer=$null;error_record=$null;reason=$null;diagnostic=$null}
    $root=$null;$entry=$null;$probe=$null
    try {
        Test-PortableDeadline
        $ctx.computer=Get-CimInstance Win32_ComputerSystem -OperationTimeoutSec 30 -ErrorAction Stop | Select-Object Name,Domain,PartOfDomain,DomainRole,Manufacturer,Model
        if(-not $ctx.computer.PartOfDomain){
            $ctx.status='not_applicable';$ctx.reason='Computer is not joined to Active Directory'
        } else {
            $root=New-Object DirectoryServices.DirectoryEntry ('LDAP://'+$ctx.computer.Domain+'/RootDSE')
            $root.psbase.RefreshCache(@('defaultNamingContext','rootDomainNamingContext','configurationNamingContext','dnsHostName'))
            $dse=[ordered]@{}
            foreach($name in @('defaultNamingContext','rootDomainNamingContext','configurationNamingContext','dnsHostName')){
                $values=$root.psbase.Properties[$name]
                $dse[$name]=if($null -ne $values -and $values.Count -gt 0){[string]$values[0]}else{$null}
            }
            if(-not $dse.defaultNamingContext){throw [InvalidOperationException]::new('RootDSE did not return defaultNamingContext')}
            $ctx.base=$dse.defaultNamingContext;$ctx.root_dse=$dse
            $server=if($dse.dnsHostName){$dse.dnsHostName}else{$ctx.computer.Domain}
            $ctx.path='LDAP://'+$server+'/'+$ctx.base
            $entry=New-Object DirectoryServices.DirectoryEntry $ctx.path
            $probe=New-Object DirectoryServices.DirectorySearcher $entry
            $probe.SearchScope=[DirectoryServices.SearchScope]::Base;$probe.Filter='(objectClass=*)'
            if($SourceTimeoutSeconds -gt 0){$probe.ClientTimeout=[TimeSpan]::FromSeconds($SourceTimeoutSeconds);$probe.ServerTimeLimit=$probe.ClientTimeout}
            if($null -eq $probe.FindOne()){throw [InvalidOperationException]::new('LDAP base query returned no object')}
        }
    } catch {
        $ctx.error_record=$_;$exception=$_.Exception
        while($null -ne $exception.InnerException){$exception=$exception.InnerException}
        $ctx.status='failed';$ctx.reason='LDAP availability probe failed'
        if($exception -is [UnauthorizedAccessException] -or ($exception.HResult -band 0xffff) -in @(5,1326,1330,1331,1385,1909,1311,1355,1722,0x203a,0x030c,0x030e) -or $exception -is [TimeoutException]){
            $ctx.status='unavailable';$ctx.reason='LDAP authentication or domain connectivity unavailable in current context'
        }
        $ctx.diagnostic=[ordered]@{message=$exception.Message;hresult=$exception.HResult;exception_type=$exception.GetType().FullName;error_id=$_.FullyQualifiedErrorId}
    } finally {foreach($obj in @($probe,$entry,$root)){Dispose-PortableResource $obj}}
    $script:PortableLDAPContext=$ctx
    return $ctx
}

function Set-PortableLDAPUnavailable($Result,$Context) {
    $Result.availability=[ordered]@{status=$Context.status;reason=$Context.reason;diagnostic=$Context.diagnostic;query_executed=$false;dependency='domain.context'}
    $Result.status=if($Context.status -eq 'not_applicable'){'not_applicable'}else{'skipped'}
}

function Convert-PortableDomainACLRecord($Item) {
    $p=$Item.Properties
    $dn=if($p['distinguishedname'].Count -gt 0){[string]$p['distinguishedname'][0]}else{$null}
    $record=[ordered]@{distinguished_name=$dn;name=$null;object_class=@($p['objectclass'] | ForEach-Object {[string]$_});object_sid=$null;object_guid=$null;admin_count=$null;owner_sid=$null;sddl=$null;security_descriptor=$null;descriptor_status='missing';aces=@()}
    foreach($name in @('samaccountname','name')){if($p[$name].Count -gt 0 -and -not $record.name){$record.name=[string]$p[$name][0]}}
    if($p['objectsid'].Count -gt 0){$record.object_sid=Convert-PortableADAttribute $p['objectsid'][0]}
    if($p['objectguid'].Count -gt 0){$record.object_guid=Convert-PortableADAttribute $p['objectguid'][0]}
    if($p['admincount'].Count -gt 0){$record.admin_count=$p['admincount'][0]}
    if($p['ntsecuritydescriptor'].Count -eq 0){return $record}
    $bytes=[byte[]]$p['ntsecuritydescriptor'][0]
    $record.security_descriptor=Convert-PortableADAttribute $bytes
    try {
        $sd=New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm($bytes)
        $owner=$sd.GetOwner([System.Security.Principal.SecurityIdentifier])
        $record.owner_sid=[string]$owner.Value
        $sections=[System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Group -bor [System.Security.AccessControl.AccessControlSections]::Access
        $record.sddl=$sd.GetSecurityDescriptorSddlForm($sections)
        $record['dacl_protected']=[bool]$sd.AreAccessRulesProtected
        $aces=New-Object System.Collections.Generic.List[object]
        foreach($ace in $sd.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])){
            Test-PortableDeadline
            $aces.Add([ordered]@{trustee_sid=[string]$ace.IdentityReference.Value;access_type=[string]$ace.AccessControlType;rights_raw=[int]$ace.ActiveDirectoryRights;rights_text=[string]$ace.ActiveDirectoryRights;object_type=[string]$ace.ObjectType;is_inherited=[bool]$ace.IsInherited;inherited_object_type=[string]$ace.InheritedObjectType;inheritance_type=[string]$ace.InheritanceType;inheritance_flags=[int]$ace.InheritanceFlags;propagation_flags=[int]$ace.PropagationFlags;object_flags=[int]$ace.ObjectFlags})
        }
        $record.aces=$aces.ToArray();$record.descriptor_status='success'
    } catch {
        if($_.Exception -is [TimeoutException]){throw}
        $record.descriptor_status='decode_failed';$record['descriptor_error']=$_.Exception.Message
    }
    return $record
}

function Collect-PortableDomainACL {
    $r=New-SourceResult 'domain_acl' 'Active Directory object security descriptors (DACL/Owner/Group; no SACL)'
    $ctx=Get-PortableLDAPContext
    if($ctx.status -ne 'success'){Set-PortableLDAPUnavailable $r $ctx;return Complete-SourceResult $r}
    $entry=$null;$searcher=$null;$found=$null
    try {
        $entry=New-Object DirectoryServices.DirectoryEntry $ctx.path
        $searcher=New-Object DirectoryServices.DirectorySearcher $entry
        $searcher.PageSize=500
        $searcher.SecurityMasks=[System.DirectoryServices.SecurityMasks]::Owner -bor [System.DirectoryServices.SecurityMasks]::Group -bor [System.DirectoryServices.SecurityMasks]::Dacl
        $searcher.Filter='(|(objectCategory=person)(objectCategory=group)(objectCategory=computer)(objectCategory=groupPolicyContainer)(objectClass=domainDNS)(objectClass=organizationalUnit))'
        foreach($property in @('distinguishedname','samaccountname','name','objectsid','objectguid','objectclass','admincount','ntsecuritydescriptor')){$null=$searcher.PropertiesToLoad.Add($property)}
        if($SourceTimeoutSeconds -gt 0){$searcher.ClientTimeout=[TimeSpan]::FromSeconds($SourceTimeoutSeconds);$searcher.ServerTimeLimit=$searcher.ClientTimeout}
        $found=$searcher.FindAll()
        foreach($item in $found){
            Test-PortableDeadline
            if($MaxDomainRecords -gt 0 -and $r.records.Count -ge $MaxDomainRecords){Add-PortableSourceNotice $r 'partial' 'LDAPLimit' $ctx.base 'MaxDomainRecords reached';break}
            try {
                $record=Convert-PortableDomainACLRecord $item
                $r.records.Add($record)
                if($record.descriptor_status -ne 'success'){Add-PortableSourceNotice $r 'partial' 'ReadSecurityDescriptor' $record.distinguished_name ('Descriptor status: '+$record.descriptor_status)}
            } catch {Add-SourceError $r $_ 'ReadSecurityDescriptor' $item.Path}
        }
    } catch {Add-SourceError $r $_ 'LDAPSecurityDescriptorQuery' $ctx.path}
    finally {foreach($obj in @($found,$searcher,$entry)){Dispose-PortableResource $obj}}
    return Complete-SourceResult $r
}

function Collect-PortableLDAP($Query) {
    $r=New-SourceResult $Query.name ([ordered]@{filter=$Query.filter;base=$null;scope='current_domain';page_size=500;max_records=$MaxDomainRecords})
    $ctx=Get-PortableLDAPContext
    if($ctx.status -ne 'success'){Set-PortableLDAPUnavailable $r $ctx;return Complete-SourceResult $r}
    $entry=$null; $searcher=$null; $found=$null
    try {
        Test-PortableDeadline
        $base=$ctx.base
        $r.location.base=$base
        $entry=New-Object DirectoryServices.DirectoryEntry $ctx.path
        $searcher=New-Object DirectoryServices.DirectorySearcher $entry
        $searcher.Filter=$Query.filter; $searcher.PageSize=500
        if($SourceTimeoutSeconds -gt 0){$searcher.ClientTimeout=[TimeSpan]::FromSeconds($SourceTimeoutSeconds);$searcher.ServerTimeLimit=$searcher.ClientTimeout}
        foreach ($property in $Query.properties) { $null=$searcher.PropertiesToLoad.Add($property) }
        $found=$searcher.FindAll()
        foreach ($item in $found) {
            Test-PortableDeadline
            if($MaxDomainRecords -gt 0 -and $r.records.Count -ge $MaxDomainRecords){Add-PortableSourceNotice $r 'partial' 'LDAPLimit' $base 'MaxDomainRecords reached; result is truncated';break}
            $attributes=[ordered]@{}
            foreach ($property in $item.Properties.PropertyNames) {
                if($property -match ';range=\d+-\d+$'){Add-PortableSourceNotice $r 'partial' 'LDAPAttributeRange' $item.Path ('Server returned a partial attribute range: '+$property)}
                $values=New-Object System.Collections.Generic.List[object]
                foreach ($value in $item.Properties[$property]) { $values.Add((Convert-PortableADAttribute $value)) }
                $attributes[$property]=$values.ToArray()
            }
            $record=[ordered]@{path=$item.Path;attributes=$attributes}
            if($Query.name -eq 'computers'){$record['has_rbcd']=$item.Properties['msds-allowedtoactonbehalfofotheridentity'].Count -gt 0}
            $r.records.Add($record)
        }
    } catch {Add-SourceError $r $_ 'LDAPQuery' $Query.filter}
    finally {foreach($resource in @($found,$searcher,$entry)){Dispose-PortableResource $resource}}
    return Complete-SourceResult $r
}

function Collect-PortableDomainContext {
    $r=New-SourceResult 'context' 'Computer domain membership and LDAP availability'
    $ctx=Get-PortableLDAPContext
    if($null -ne $ctx.computer){$r.records.Add([ordered]@{kind='computer_system';data=$ctx.computer})}
    $r.availability=[ordered]@{status=$ctx.status;reason=$ctx.reason;diagnostic=$ctx.diagnostic}
    $r.records.Add([ordered]@{kind='ldap_availability';data=$r.availability})
    if($ctx.status -ne 'success'){
        $r.status=$ctx.status
        if($ctx.status -eq 'failed'){Add-SourceError $r $ctx.error_record 'LDAPPreflight' 'ComputerDomain'}
        return Complete-SourceResult $r
    }
    $r.records.Add([ordered]@{kind='root_dse';data=$ctx.root_dse})
    $domain=$null
    try {
        $domain=[DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        foreach($dc in $domain.DomainControllers){try{$r.records.Add([ordered]@{kind='controller';name=$dc.Name;ip_address=$dc.IPAddress;site=$dc.SiteName;roles=@($dc.Roles | ForEach-Object{[string]$_})})}finally{Dispose-PortableResource $dc}}
        foreach($trust in $domain.GetAllTrustRelationships()){$r.records.Add([ordered]@{kind='trust';source=$trust.SourceName;target=$trust.TargetName;direction=[string]$trust.TrustDirection;type=[string]$trust.TrustType})}
    } catch {Add-SourceError $r $_ 'DomainDiscovery' 'ComputerDomain'}
    finally {Dispose-PortableResource $domain}
    return Complete-SourceResult $r
}


function Collect-PortableLogons {
    $r=New-SourceResult 'logons' 'Win32_LogonSession: types 2,10,11; not proof of present activity'
    try {
        Get-CimInstance Win32_LogonSession -OperationTimeoutSec 30 -ErrorAction Stop | Where-Object {$_.LogonType -in @(2,10,11)} | ForEach-Object {
            Test-PortableDeadline
            $session=$_
            $record=[ordered]@{logon_id=$session.LogonId;type=$session.LogonType;start_time=$session.StartTime;authentication_package=$session.AuthenticationPackage;accounts=@()}
            try {$record.accounts=@(Get-CimAssociatedInstance -InputObject $session -Association Win32_LoggedOnUser -ResultClassName Win32_Account -OperationTimeoutSec 30 -ErrorAction Stop | Select-Object Name,Domain,SID)}
            catch {Add-SourceError $r $_ 'ResolveLogonAccounts' ([string]$session.LogonId)}
            $r.records.Add($record)
        }
    } catch {Add-SourceError $r $_ 'EnumerateLogons' 'Win32_LogonSession'}
    return Complete-SourceResult $r
}

function Collect-PortableTickets {
    $r=New-SourceResult 'kerberos_tickets' 'Current logon context: ticket metadata only'
    Add-PortableCommandResult $r 'klist.exe' @('tickets')
    return Complete-SourceResult $r
}

function Get-PortableCatalog {
    $catalog=[ordered]@{
        identity=@(@{name='token';command='Collect-PortableIdentitySource'},@{name='os';command='Collect-PortableOS'},@{name='profiles';command='Collect-PortableProfiles'})
        logs=@(Get-PortableLogSpecs)
        recent=@(Get-PortableRecentSpecs)
        configs=@(@{name='roles';command='Collect-PortableRoles'},@{name='iis';command='Collect-PortableIIS'},@{name='config_files';command='Collect-PortableConfigs'},@{name='shared_text_files';command='Collect-PortableSharedTextFiles'})
        network=@()
        domain=@(@{name='context';command='Collect-PortableDomainContext'})
        browser=@(@{name='browser_files';command='Collect-PortableBrowser'})
        permissions=@(@{name='file_acl';command='Collect-PortableFileACL'},@{name='service_acl';command='Collect-PortableServiceACL'},@{name='domain_acl';command='Collect-PortableDomainACL'})
    }
    foreach($spec in $catalog.logs){if($spec.name -in @('explorer_history','office_mru','powershell_history','rdp_history')){$spec['user']=$true}}
    foreach($spec in $catalog.recent){$spec['user']=$true}
    foreach($name in @('interfaces','addresses','routes','dns_servers','dns_cache','neighbors','tcp','udp','processes','firewall','proxy','management')){
        $catalog.network+=@{name=$name;command='Collect-PortableNetwork';arguments=@{Name=$name}}
    }
    foreach($query in @(Get-PortableDomainQueries)){$catalog.domain+=@{name=$query.name;command='Collect-PortableLDAP';arguments=@{Query=$query}}}
    $catalog.domain+=@(@{name='logons';command='Collect-PortableLogons'},@{name='kerberos_tickets';command='Collect-PortableTickets'})
    return $catalog
}

function Select-PortableCatalog($Catalog, [string[]]$Include=@('all'), [string[]]$Exclude=@()) {
    $includeTokens=@($Include | ForEach-Object {$_ -split ','} | ForEach-Object {$_.Trim().ToLowerInvariant()} | Where-Object {$_})
    $excludeTokens=@($Exclude | ForEach-Object {$_ -split ','} | ForEach-Object {$_.Trim().ToLowerInvariant()} | Where-Object {$_})
    if($includeTokens.Count -eq 0){throw 'Sources cannot be empty'}
    $valid=@('all')+@($Catalog.Keys)
    foreach($group in $Catalog.Keys){foreach($spec in $Catalog[$group]){$valid+=($group+'.'+$spec.name)}}
    foreach($token in @($includeTokens+$excludeTokens)){if($token -notin $valid){throw "Unknown source selector: $token"}}
    foreach($group in $Catalog.Keys){foreach($spec in $Catalog[$group]){
        $qualified=$group+'.'+$spec.name
        $spec['selected']=('all' -in $includeTokens -or $group -in $includeTokens -or $qualified -in $includeTokens) -and -not ('all' -in $excludeTokens -or $group -in $excludeTokens -or $qualified -in $excludeTokens)
        $spec['selection_reason']=$(if($spec.selected){'requested'}else{'excluded_by_selection'})
    }}
    # Explicit, visible dependencies; exclusions always win.
    $needsDomain=@($Catalog.domain+$Catalog.permissions | Where-Object {$_.selected -and $_.command -in @('Collect-PortableLDAP','Collect-PortableDomainACL')}).Count -gt 0
    if($needsDomain -and 'domain.context' -notin $excludeTokens -and 'domain' -notin $excludeTokens -and 'all' -notin $excludeTokens){
        $contextSpec=$Catalog.domain | Where-Object {$_.name -eq 'context'}
        if(-not $contextSpec.selected){$contextSpec.selected=$true;$contextSpec.selection_reason='ldap_context_dependency'}
    }
    $needsProfiles=@($Catalog.logs+$Catalog.recent+$Catalog.configs+$Catalog.browser | Where-Object {$_.selected -and ($_.user -or $_.name -in @('config_files','browser_files'))}).Count -gt 0
    if($needsProfiles -and 'identity' -notin $excludeTokens -and 'identity.profiles' -notin $excludeTokens -and 'all' -notin $excludeTokens){
        $profileSpec=$Catalog.identity | Where-Object {$_.name -eq 'profiles'}
        if(-not $profileSpec.selected){$profileSpec.selected=$true;$profileSpec.selection_reason='profile_discovery_dependency'}
    }
    $configSpec=$Catalog.configs | Where-Object {$_.name -eq 'config_files'}
    if($configSpec.selected -and 'configs.iis' -notin $excludeTokens){$iis=$Catalog.configs | Where-Object {$_.name -eq 'iis'};if(-not $iis.selected){$iis.selected=$true;$iis.selection_reason='iis_discovery_dependency'}}
    return $Catalog
}

function Invoke-PortableSpec($Spec, [string]$CollectionRoot, [long]$LimitBytes) {
    $arguments=@{}
    if($Spec.arguments){foreach($key in $Spec.arguments.Keys){$arguments[$key]=$Spec.arguments[$key]}}
    if($Spec.files){$arguments.CollectionRoot=$CollectionRoot;$arguments.LimitBytes=$LimitBytes}
    if(-not $Spec.user){return & $Spec.command @arguments}
    $combined=New-SourceResult $Spec.name 'Selected profiles; loaded user hives only'
    $children=New-Object System.Collections.Generic.List[object]
    foreach($profile in $script:PortableProfiles){
        $script:PortableProfile=$profile
        try {
            Test-PortableDeadline
            $branch=& $Spec.command @arguments
            foreach($record in $branch.records){
                $record['profile_sid']=$profile.sid; $record['profile_path']=$profile.path
                $combined.records.Add($record)
            }
            foreach($failure in $branch.errors){$failure['profile_sid']=$profile.sid;$combined.errors.Add($failure)}
            $child=Get-SourceSummary $branch;$child['profile_sid']=$profile.sid;$child['profile_path']=$profile.path;$children.Add($child)
        } catch {Add-SourceError $combined $_ 'CollectProfileSource' $profile.path}
        finally {$script:PortableProfile=$null}
    }
    $combined.children=$children.ToArray()
    return Complete-SourceResult $combined
}

function Publish-PortableCheckpoint([string]$CollectionRoot, $Metadata, $Sections, $Errors, [string]$Status='in_progress') {
    $index=[ordered]@{
        schema_version='3.0';metadata=$Metadata;status=$Status;updated_at=[DateTime]::UtcNow.ToString('o')
        sections=$Sections;errors=@($Errors | ForEach-Object {$_})
        limits=[ordered]@{max_file_bytes=$MaxFileBytes;max_artifact_bytes=$MaxArtifactBytes;max_shared_text_file_bytes=$MaxSharedTextFileBytes;shared_text_search_depth=$SharedTextSearchDepth;max_total_bytes=$MaxTotalBytes;total_limit_scope='copied_original_file_bytes_only';copied_bytes=$script:PortableCopiedBytes;source_timeout_seconds=$SourceTimeoutSeconds;timeout_mode='cooperative_and_supported_provider_timeouts';max_domain_records=$MaxDomainRecords}
        profile_scope=$ProfileScope;selected_sources=$Sources;excluded_sources=$ExcludeSources
    }
    $null=Write-PortableJson (Join-Path $CollectionRoot 'portable_collection.json') $index
    return $index
}

function New-PortableArchive([string]$CollectionRoot) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    $archive=$CollectionRoot+'.zip';$temporary=$archive+'.partial'
    if([IO.File]::Exists($archive) -or [IO.File]::Exists($temporary)){throw 'Archive destination already exists'}
    try {
        [IO.Compression.ZipFile]::CreateFromDirectory($CollectionRoot,$temporary,[IO.Compression.CompressionLevel]::Optimal,$true)
        $check=[IO.Compression.ZipFile]::OpenRead($temporary)
        try {if($check.Entries.Count -eq 0){throw 'Empty archive'}}finally{$check.Dispose()}
        [IO.File]::Move($temporary,$archive)
        return [ordered]@{path=$archive;size=([IO.FileInfo]$archive).Length;sha256=(Get-FileHash -LiteralPath $archive -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()}
    } finally {if([IO.File]::Exists($temporary)){[IO.File]::Delete($temporary)}}
}

function Test-PortableWindows { return [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT }

function Invoke-PortableCollection {
    if(-not (Test-PortableWindows)){throw 'Collection requires Windows; use LibraryOnly or TestSerialization for portable tests'}
    $script:PortableLDAPContext=$null
    $catalog=Select-PortableCatalog (Get-PortableCatalog) $Sources $ExcludeSources
    $outDir=Resolve-OutputDirectory $OutputPath
    $script:PortableOutput=$outDir
    $script:PortableCopiedBytes=0L
    $script:PortableAclPaths=@{}
    $script:PortableProfile=$null
    $script:PortableProfiles=@([ordered]@{sid=$null;path=$env:USERPROFILE;appdata=$env:APPDATA;localappdata=$env:LOCALAPPDATA;registry_root='HKCU:';current=$true})
    $script:PortableIISRoots=@((Join-PortableOptionalPath $env:SystemDrive 'inetpub\wwwroot') | Where-Object {$_})
    $metadata=[ordered]@{schema_version='3.0';module='portable';hostname=$env:COMPUTERNAME;started_at=[DateTime]::UtcNow.ToString('o');powershell=$PSVersionTable.PSVersion.ToString();output_directory=$outDir;script_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant();raw_only=$true}
    $sections=[ordered]@{};$errors=New-Object System.Collections.Generic.List[object]
    foreach($group in $catalog.Keys){$sections[$group]=[ordered]@{path=(Join-Path $outDir ($group+'.json'));status='pending';size=0}}
    $null=Publish-PortableCheckpoint $outDir $metadata $sections $errors
    foreach($group in $catalog.Keys){
        $sections[$group].status='in_progress'
        $null=Publish-PortableCheckpoint $outDir $metadata $sections $errors
        try {
            $summary=Invoke-PortableSourceGroup $group $catalog[$group] $outDir $metadata $MaxArtifactBytes
            $sections[$group].status=$summary.status
            $sections[$group].size=([IO.FileInfo]$sections[$group].path).Length
            $sections[$group]['counts']=$summary.counts
            $sections[$group]['selected_count']=@($catalog[$group] | Where-Object {$_.selected}).Count
            foreach($source in $summary.sources){foreach($failure in $source.errors){
                if($failure.operation -ne 'SelectSource'){$errors.Add([ordered]@{source=($group+'.'+$source.source);status=$failure.status;operation=$failure.operation;path=$failure.path;message=$failure.message})}
            }}
        } catch {$sections[$group].status='failed';$errors.Add([ordered]@{source=$group;status='failed';message=$_.Exception.Message})}
        $null=Publish-PortableCheckpoint $outDir $metadata $sections $errors
    }
    $selectedGroups=@($catalog.Keys | Where-Object {@($catalog[$_] | Where-Object {$_.selected}).Count -gt 0})
    $status='success'
    if(@($selectedGroups | Where-Object {$sections[$_].status -ne 'success'}).Count -gt 0){$status='partial'}
    if($selectedGroups.Count -gt 0 -and @($selectedGroups | Where-Object {$sections[$_].status -in @('success','partial')}).Count -eq 0){$status='failed'}
    if($selectedGroups.Count -eq 0){$status='skipped'}
    $metadata['finished_at']=[DateTime]::UtcNow.ToString('o')
    $null=Publish-PortableCheckpoint $outDir $metadata $sections $errors $status
    $archiveResult=$null
    if($Archive){try{$archiveResult=New-PortableArchive $outDir}catch{$errors.Add([ordered]@{source='archive';status='failed';message=$_.Exception.Message});$status='partial';$null=Publish-PortableCheckpoint $outDir $metadata $sections $errors $status}}
    return [ordered]@{status=$status;output_directory=$outDir;result_file=(Join-Path $outDir 'portable_collection.json');sections=$sections;copied_bytes=$script:PortableCopiedBytes;errors=$errors.Count;archive=$archiveResult}
}


if ($LibraryOnly) { return }

# No collection or disk writes: exercises the same collection types as production.
if ($TestSerialization) {
    $ErrorActionPreference = 'Stop'
    foreach ($count in @(0, 1, 3)) {
        $testRecords = New-Object System.Collections.Generic.List[object]
        $testErrors = New-Object System.Collections.Generic.List[object]
        for ($i=0; $i -lt $count; $i++) { $testRecords.Add([ordered]@{name='synthetic'; number=$i}) }
        $testResult = [ordered]@{configs=$testRecords.ToArray(); errors=$testErrors.ToArray(); status='success'}
        $testJson = Convert-PortableJson (Convert-ToPlainObject $testResult)
        $decoded = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $testJson -ErrorAction Stop
        if ($decoded.status -ne 'success' -or @($decoded.configs).Count -ne $count -or @($decoded.errors).Count -ne 0) { throw 'Serialization self-test failed' }
    }
    Write-Output 'Serialization self-test PASS (0, 1, 3 records)'
    return
}

Invoke-PortableCollection
