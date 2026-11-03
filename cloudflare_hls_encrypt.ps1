<#
.SYNOPSIS
    Adaptive Windows HLS AES-128 Key Generator & Video Encryptor for Cloudflare Streaming / R2.
.DESCRIPTION
    - Generates a cryptographically secure 16-byte binary key (secret.key) using native .NET APIs (no OpenSSL required).
    - Generates a 16-byte hexadecimal Initialization Vector (IV) without using shell pipes.
    - Writes secret.keyinfo in UTF-8 without BOM so FFmpeg parses the Key URI cleanly.
    - Automatically locates FFmpeg on Windows (PATH, Winget, Chocolatey, Scoop, or local folder) and encrypts the video into HLS (.m3u8 + .ts segments) when an input video is available.
.PARAMETER InputVideo
    Optional path to the source video file (e.g., "input.mp4"). If omitted, the script auto-detects a single .mp4 in the current directory or generates keys only.
.PARAMETER KeyUri
    The URI written to line 1 of secret.keyinfo (e.g., "secret.key" or "https://media.yourdomain.com/secret.key").
.PARAMETER OutputDir
    Directory where secret.key, secret.keyinfo, index.m3u8, and .ts segments will be saved. Defaults to current directory.
.PARAMETER SegmentTime
    HLS segment duration in seconds. Defaults to 10.
.PARAMETER CopyCodec
    If set, uses "-c copy" instead of re-encoding with libx264/aac.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$InputVideo = "",

    [Parameter(Mandatory = $false)]
    [string]$KeyUri = "secret.key",

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = "",

    [Parameter(Mandatory = $false)]
    [int]$SegmentTime = 10,

    [Parameter(Mandatory = $false)]
    [switch]$CopyCodec
)

$ErrorActionPreference = "Stop"

# 1. Resolve working/output directory safely across all Windows PowerShell versions
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = (Get-Location).Path
}
if (-not (Test-Path -LiteralPath $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force > $null
}
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path

$KeyFilePath     = Join-Path $OutputDir "secret.key"
$KeyInfoFilePath = Join-Path $OutputDir "secret.keyinfo"
$PlaylistPath    = Join-Path $OutputDir "index.m3u8"
$SegmentPattern  = Join-Path $OutputDir "segment_%03d.ts"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Cloudflare HLS AES-128 Key & Video Encryption Tool (Windows)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Working Directory : $OutputDir"

# 2. Generate 16-byte binary key and 16-byte IV using native .NET Cryptography (no OpenSSL or pipe characters needed)
$keyBytes = New-Object byte[] 16
$ivBytes  = New-Object byte[] 16
$rng      = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($keyBytes)
$rng.GetBytes($ivBytes)

# Write exact 16-byte raw binary key file
[System.IO.File]::WriteAllBytes($KeyFilePath, $keyBytes)

# Convert IV bytes to 32-char lowercase hex string without pipes
$ivHex = [System.BitConverter]::ToString($ivBytes).Replace("-", "").ToLowerInvariant()
$keyHexPreview = [System.BitConverter]::ToString($keyBytes).Replace("-", "").ToLowerInvariant()

# 3. Write secret.keyinfo as UTF-8 WITHOUT BOM and with LF line endings (prevents FFmpeg URI corruption)
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$keyInfoContent = $KeyUri + "`n" + $KeyFilePath + "`n" + $ivHex
[System.IO.File]::WriteAllText($KeyInfoFilePath, $keyInfoContent, $utf8NoBom)

# 4. Verify generated key files
$keyFileSize = (Get-Item -LiteralPath $KeyFilePath).Length
if ($keyFileSize -ne 16) {
    throw "Key generation validation failed: expected 16 bytes, got $keyFileSize bytes."
}

Write-Host "[OK] Created 16-byte key     : $KeyFilePath" -ForegroundColor Green
Write-Host "     Key (Hex preview)       : $keyHexPreview" -ForegroundColor DarkGray
Write-Host "[OK] Created keyinfo file    : $KeyInfoFilePath" -ForegroundColor Green
Write-Host "     Line 1 (Key URI)        : $KeyUri" -ForegroundColor DarkGray
Write-Host "     Line 2 (Key File Path)  : $KeyFilePath" -ForegroundColor DarkGray
Write-Host "     Line 3 (16-Byte Hex IV) : $ivHex" -ForegroundColor DarkGray

# 5. Locate FFmpeg on Windows (PATH + common Winget / Chocolatey / Scoop locations)
function Find-FFmpegExecutable {
    $cmd = Get-Command "ffmpeg" -ErrorAction SilentlyContinue
    if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source)) {
        return $cmd.Source
    }

    $candidatePaths = @(
        (Join-Path $OutputDir "ffmpeg.exe"),
        "$env:LOCALAPPDATA\Microsoft\WinGet\Links\ffmpeg.exe",
        "C:\ProgramData\chocolatey\bin\ffmpeg.exe",
        "$env:USERPROFILE\scoop\shims\ffmpeg.exe",
        "C:\ffmpeg\bin\ffmpeg.exe"
    )

    # Search WinGet packages folder if present
    $wingetPkgRoot = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages"
    if (Test-Path -LiteralPath $wingetPkgRoot) {
        $foundWinget = Get-ChildItem -Path $wingetPkgRoot -Filter "ffmpeg.exe" -Recurse -ErrorAction SilentlyContinue
        if ($null -ne $foundWinget -and $foundWinget.Count -gt 0) {
            $candidatePaths += $foundWinget[0].FullName
        }
    }

    foreach ($path in $candidatePaths) {
        if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path)) {
            return $path
        }
    }
    return $null
}

# 6. Auto-detect input video if not specified
if ([string]::IsNullOrWhiteSpace($InputVideo)) {
    $mp4Files = @(Get-ChildItem -Path $OutputDir -Filter "*.mp4" -File -ErrorAction SilentlyContinue)
    if ($mp4Files.Count -eq 1) {
        $InputVideo = $mp4Files[0].FullName
        Write-Host "[INFO] Auto-detected video   : $InputVideo" -ForegroundColor Yellow
    } elseif ($mp4Files.Count -gt 1) {
        Write-Host "[INFO] Multiple .mp4 files found in directory. Pass -InputVideo 'filename.mp4' to encrypt a specific file." -ForegroundColor Yellow
    }
}

# 7. Run FFmpeg HLS encryption if an input video was provided or auto-detected
if (-not [string]::IsNullOrWhiteSpace($InputVideo)) {
    if (-not (Test-Path -LiteralPath $InputVideo)) {
        throw "Input video not found at path: $InputVideo"
    }
    $InputVideo = (Resolve-Path -LiteralPath $InputVideo).Path

    $ffmpegExe = Find-FFmpegExecutable
    if ([string]::IsNullOrWhiteSpace($ffmpegExe)) {
        Write-Host "[WARN] FFmpeg was not found on this system. Install it with: winget install Gyan.FFmpeg" -ForegroundColor Yellow
        Write-Host "       Your secret.key and secret.keyinfo files are ready to use once FFmpeg is installed." -ForegroundColor Yellow
        exit 0
    }

    Write-Host "[INFO] Using FFmpeg          : $ffmpegExe" -ForegroundColor Cyan
    Write-Host "[INFO] Encrypting video into HLS segments..." -ForegroundColor Cyan

    $ffmpegArgs = @(
        "-y",
        "-i", $InputVideo
    )

    if ($CopyCodec) {
        $ffmpegArgs += @("-c", "copy")
    } else {
        $ffmpegArgs += @("-c:v", "libx264", "-c:a", "aac")
    }

    $ffmpegArgs += @(
        "-hls_time", "$SegmentTime",
        "-hls_key_info_file", $KeyInfoFilePath,
        "-hls_playlist_type", "vod",
        "-hls_segment_filename", $SegmentPattern,
        $PlaylistPath
    )

    & $ffmpegExe @ffmpegArgs
    if ($LASTEXITCODE -ne 0) {
        throw "FFmpeg exited with error code $LASTEXITCODE"
    }

    Write-Host "[OK] Encrypted HLS playlist  : $PlaylistPath" -ForegroundColor Green
} else {
    Write-Host "[DONE] Key generation complete. To encrypt a video, place an .mp4 in this folder or run:" -ForegroundColor Cyan
    Write-Host "       .\cloudflare_hls_encrypt.ps1 -InputVideo `"input.mp4`" -KeyUri `"$KeyUri`"" -ForegroundColor White
}
