# MCPGate Windows Installer (Pure .NET — Zero Cmdlets, Zero PSModulePath Dependency)
# Usage: irm https://raw.githubusercontent.com/aloneangel45/MCPGate/main/install.ps1 | iex
$ErrorActionPreference = 'Stop'

# Sanitize PSModulePath to prevent broken/stale module directory entries from causing autoload errors
if ($env:PSModulePath) {
    $CleanModules = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in ($env:PSModulePath -split ';')) {
        $trimmed = $entry.Trim()
        if ($trimmed -ne '' -and (-not $trimmed.StartsWith('\\')) -and [System.IO.Directory]::Exists($trimmed)) {
            $CleanModules.Add($trimmed)
        }
    }
    $env:PSModulePath = [string]::Join(';', $CleanModules)
}

if (-not ('System.IO.Compression.ZipFile' -as [type])) {
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem')
}

$Repo = if ($env:MCPGATE_REPO) { $env:MCPGATE_REPO } else { 'aloneangel45/MCPGate' }
$Version = if ($env:MCPGATE_VERSION) { $env:MCPGATE_VERSION } else { 'latest' }
$BaseUrl = if ($env:MCPGATE_BASE_URL) { $env:MCPGATE_BASE_URL } else { "https://github.com/$Repo/releases" }
$ApiUrl = if ($env:MCPGATE_API_URL) { $env:MCPGATE_API_URL } else { "https://api.github.com/repos/$Repo/releases/latest" }
$FallbackVersion = 'v1.0.1'

$ArchRaw = if ($env:MCPGATE_ARCH_OVERRIDE) {
    $env:MCPGATE_ARCH_OVERRIDE
} elseif ($env:PROCESSOR_ARCHITEW6432) {
    $env:PROCESSOR_ARCHITEW6432
} else {
    $env:PROCESSOR_ARCHITECTURE
}

$Arch = switch -Regex ($ArchRaw) {
    '^(AMD64|x86_64|amd64)$' { 'amd64'; break }
    '^(ARM64|aarch64|arm64)$' { 'arm64'; break }
    default { throw "[mcpgate] Unsupported Windows architecture: $ArchRaw" }
}

function Enable-Tls12 {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
}

function Resolve-LatestTag([string]$Endpoint, [string]$DefaultTag) {
    Enable-Tls12
    $wc = [System.Net.WebClient]::new()
    try {
        $wc.Headers.Add('Accept', 'application/vnd.github+json')
        $wc.Headers.Add('User-Agent', 'mcpgate-installer')
        $body = $wc.DownloadString($Endpoint)
        $m = [System.Text.RegularExpressions.Regex]::Match($body, '"tag_name"\s*:\s*"([^"]+)"')
        if ($m.Success -and -not [string]::IsNullOrWhiteSpace($m.Groups[1].Value)) {
            return $m.Groups[1].Value
        }
    } catch {
        return $DefaultTag
    } finally {
        $wc.Dispose()
    }
    return $DefaultTag
}

$Archive = "mcpgate-windows-$Arch.zip"
if ($Version -eq 'latest') {
    if ($env:MCPGATE_BASE_URL) {
        $DlPrefix = "$BaseUrl/latest/download"
    } else {
        $Tag = Resolve-LatestTag $ApiUrl $FallbackVersion
        $DlPrefix = "$BaseUrl/download/$Tag"
    }
} else {
    $Tag = if ($Version.StartsWith('v')) { $Version } else { "v$Version" }
    $DlPrefix = "$BaseUrl/download/$Tag"
}

$InstallDir = if ($env:MCPGATE_INSTALL_DIR) {
    $env:MCPGATE_INSTALL_DIR
} else {
    [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Programs', 'mcpgate', 'bin')
}

$TmpDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "mcpgate-install-" + [System.Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($TmpDir)

function Download-MCPGateFile([string]$Url, [string]$Dest) {
    if ($Url.StartsWith('file://', [System.StringComparison]::OrdinalIgnoreCase)) {
        $LocalSrc = ([System.Uri]$Url).LocalPath
        [System.IO.File]::Copy($LocalSrc, $Dest, $true)
        return
    }
    Enable-Tls12
    $wc = [System.Net.WebClient]::new()
    try {
        $wc.Headers.Add('User-Agent', 'mcpgate-installer')
        $wc.DownloadFile($Url, $Dest)
    } finally {
        $wc.Dispose()
    }
}

function Compute-Sha256Hex([string]$FilePath) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($FilePath)
    try {
        $hashBytes = $sha.ComputeHash($stream)
        return ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
    } finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

try {
    $ZipPath = [System.IO.Path]::Combine($TmpDir, $Archive)
    $SumPath = [System.IO.Path]::Combine($TmpDir, 'checksums.txt')

    [Console]::WriteLine("[mcpgate] Downloading $Archive from $DlPrefix...")
    Download-MCPGateFile "$DlPrefix/$Archive" $ZipPath
    Download-MCPGateFile "$DlPrefix/checksums.txt" $SumPath

    $Expected = $null
    foreach ($line in [System.IO.File]::ReadAllLines($SumPath)) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        $parts = $trimmed -split '\s+', 2
        if ($parts.Length -eq 2) {
            $fname = $parts[1].TrimStart('*')
            if ($fname -eq $Archive) {
                $Expected = $parts[0].ToLowerInvariant()
                break
            }
        }
    }

    if (-not $Expected) {
        throw "[mcpgate] Entry for $Archive not found in checksums.txt"
    }

    $Actual = Compute-Sha256Hex $ZipPath
    if ($Actual -ne $Expected) {
        throw "[mcpgate] SHA-256 mismatch for $Archive (expected $Expected, got $Actual)"
    }

    $ExtractDir = [System.IO.Path]::Combine($TmpDir, 'extracted')
    [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $ExtractDir)

    $ExeSrc = [System.IO.Path]::Combine($ExtractDir, 'mcpgate.exe')
    if (-not [System.IO.File]::Exists($ExeSrc)) {
        throw "[mcpgate] mcpgate.exe missing from archive $Archive"
    }

    [void][System.IO.Directory]::CreateDirectory($InstallDir)
    $ExeDest = [System.IO.Path]::Combine($InstallDir, 'mcpgate.exe')
    if ([System.IO.File]::Exists($ExeDest)) {
        $attrs = [System.IO.File]::GetAttributes($ExeDest)
        if (($attrs -band [System.IO.FileAttributes]::ReadOnly) -ne 0) {
            [System.IO.File]::SetAttributes($ExeDest, ($attrs -band (-bnot [System.IO.FileAttributes]::ReadOnly)))
        }
    }
    [System.IO.File]::Copy($ExeSrc, $ExeDest, $true)

    if (-not $env:MCPGATE_SKIP_PATH) {
        $UserPath = [System.Environment]::GetEnvironmentVariable('Path', 'User')
        if (-not $UserPath) { $UserPath = '' }
        $Entries = @()
        foreach ($seg in ($UserPath -split ';')) {
            if ($seg -ne '') { $Entries += $seg }
        }
        $AlreadyPresent = $false
        foreach ($e in $Entries) {
            if ([string]::Equals($e.TrimEnd('\'), $InstallDir.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
                $AlreadyPresent = $true
                break
            }
        }
        if (-not $AlreadyPresent) {
            $NewPath = if ($UserPath.EndsWith(';') -or $UserPath -eq '') { "$UserPath$InstallDir" } else { "$UserPath;$InstallDir" }
            [System.Environment]::SetEnvironmentVariable('Path', $NewPath, 'User')
            $env:Path = "$env:Path;$InstallDir"
        }
    }

    [Console]::WriteLine("[mcpgate] Installed successfully to $ExeDest")
} finally {
    if ([System.IO.Directory]::Exists($TmpDir)) {
        [System.IO.Directory]::Delete($TmpDir, $true)
    }
}
