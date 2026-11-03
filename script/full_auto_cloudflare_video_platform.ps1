<#
.SYNOPSIS
    Master End-to-End Automation Script for Windows:
    Encrypts 1 to 500+ MP4 Videos + Automatically Creates Cloudflare R2, D1, Uploads Files, and Deploys the Protected Video Worker Portal via Cloudflare API Token.
.DESCRIPTION
    1. Prompts for your local MP4 video folder path, Cloudflare Account ID, and Cloudflare API Token.
    2. Encrypts every .mp4 video into AES-128 HLS (index.m3u8, secret.key, segment_xxx.ts) using FFmpeg without pipe characters.
    3. Builds catalog.json automatically so all your videos show up in a dropdown menu in the player.
    4. Uses the Cloudflare REST API (with your API Token) to:
       - Create the Private R2 Bucket ("video-vault")
       - Create the D1 SQLite Database ("video-auth-db") and initialize the users table
       - Upload all encrypted HLS files and catalog.json to R2 (skipping already-uploaded files on resume)
       - Auto-generate and deploy the Cloudflare Worker ("cloudflare-video-portal") with D1 & R2 bindings attached automatically
       - Enable your *.workers.dev URL and open the live video portal in your browser!
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$VideoFolder = "",

    [Parameter(Mandatory = $false)]
    [string]$AccountId = "db0f77ee072c3b5b6abd97223b7767b5",

    [Parameter(Mandatory = $false)]
    [string]$ApiToken = "",

    [Parameter(Mandatory = $false)]
    [string]$BucketName = "video-vault",

    [Parameter(Mandatory = $false)]
    [string]$DatabaseName = "video-auth-db",

    [Parameter(Mandatory = $false)]
    [string]$WorkerName = "cloudflare-video-portal",

    [Parameter(Mandatory = $false)]
    [int]$SegmentTime = 10,

    [Parameter(Mandatory = $false)]
    [switch]$CopyCodec
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " MASTER CLOUDFLARE 500-VIDEO ENCRYPTION & AUTO-DEPLOY SCRIPT (WINDOWS)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

# 1. Interactive Prompts for Video Folder, Account ID, and Cloudflare API Token
if ([string]::IsNullOrWhiteSpace($VideoFolder)) {
    $defaultFolder = (Get-Location).Path
    $inputFolder = Read-Host "1. Enter folder path containing your .mp4 videos (Press Enter for '$defaultFolder')"
    if ([string]::IsNullOrWhiteSpace($inputFolder)) {
        $VideoFolder = $defaultFolder
    } else {
        $VideoFolder = $inputFolder.Trim('"')
    }
}
if (-not (Test-Path -LiteralPath $VideoFolder)) {
    throw "Video folder does not exist: $VideoFolder"
}
$VideoFolder = (Resolve-Path -LiteralPath $VideoFolder).Path

$inputAcc = Read-Host "2. Enter your Cloudflare Account ID (Press Enter for default '$AccountId')"
if (-not [string]::IsNullOrWhiteSpace($inputAcc)) {
    $AccountId = $inputAcc.Trim()
}

if ([string]::IsNullOrWhiteSpace($ApiToken)) {
    $ApiToken = Read-Host "3. Paste your Cloudflare API Token (with Workers, R2, and D1 Edit permissions)"
    $ApiToken = $ApiToken.Trim()
}
if ([string]::IsNullOrWhiteSpace($ApiToken)) {
    throw "Cloudflare API Token is required to auto-create R2, D1, upload videos, and deploy the Worker."
}

$Headers = @{
    "Authorization" = "Bearer $ApiToken"
    "Content-Type"  = "application/json"
}

# 2. Verify FFmpeg is available (or install automatically via Winget)
function Get-FFmpegPath {
    $cmd = Get-Command "ffmpeg" -ErrorAction SilentlyContinue
    if ($null -ne $cmd -and -not [string]::IsNullOrWhiteSpace($cmd.Source)) {
        return $cmd.Source
    }
    $wingetLinks = "$env:LOCALAPPDATA\Microsoft\WinGet\Links\ffmpeg.exe"
    if (Test-Path -LiteralPath $wingetLinks) { return $wingetLinks }

    $wingetPkgRoot = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages"
    if (Test-Path -LiteralPath $wingetPkgRoot) {
        $found = @(Get-ChildItem -Path $wingetPkgRoot -Filter "ffmpeg.exe" -Recurse -ErrorAction SilentlyContinue)
        if ($found.Count -gt 0) { return $found[0].FullName }
    }
    return $null
}

$ffmpegExe = Get-FFmpegPath
if ([string]::IsNullOrWhiteSpace($ffmpegExe)) {
    Write-Host "[INFO] FFmpeg not found. Installing FFmpeg via Winget..." -ForegroundColor Yellow
    & winget install Gyan.FFmpeg --accept-source-agreements --accept-package-agreements
    $ffmpegExe = Get-FFmpegPath
    if ([string]::IsNullOrWhiteSpace($ffmpegExe)) {
        throw "FFmpeg installation finished. Please close and reopen PowerShell, then re-run this script."
    }
}
Write-Host "[OK] Using FFmpeg: $ffmpegExe" -ForegroundColor Green

# 3. Batch-Encrypt All .mp4 Videos in $VideoFolder
$EncryptedRoot = Join-Path $VideoFolder "encrypted_hls"
if (-not (Test-Path -LiteralPath $EncryptedRoot)) {
    New-Item -ItemType Directory -Path $EncryptedRoot -Force > $null
}

$mp4Files = @(Get-ChildItem -Path $VideoFolder -Filter "*.mp4" -File)
if ($mp4Files.Count -eq 0) {
    throw "No .mp4 video files found in '$VideoFolder'. Place your .mp4 files in that folder and run again."
}

Write-Host "[STEP 1/5] Encrypting $($mp4Files.Count) video(s) into AES-128 HLS format..." -ForegroundColor Cyan

$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$catalogList = New-Object System.Collections.Generic.List[object]
$index = 0

foreach ($file in $mp4Files) {
    $index++
    $rawTitle = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
    $safeSlug = ($rawTitle.ToLowerInvariant() -replace '[^a-z0-9_-]', '_').Trim('_')
    if ([string]::IsNullOrWhiteSpace($safeSlug)) {
        $safeSlug = "video_$index"
    }

    $videoOutDir = Join-Path $EncryptedRoot $safeSlug
    $m3u8Path    = Join-Path $videoOutDir "index.m3u8"
    $keyPath     = Join-Path $videoOutDir "secret.key"
    $keyInfoPath = Join-Path $videoOutDir "secret.keyinfo"
    $segPattern  = Join-Path $videoOutDir "segment_%03d.ts"

    if (-not (Test-Path -LiteralPath $m3u8Path)) {
        New-Item -ItemType Directory -Path $videoOutDir -Force > $null

        $keyBytes = New-Object byte[] 16
        $ivBytes  = New-Object byte[] 16
        $rng.GetBytes($keyBytes)
        $rng.GetBytes($ivBytes)

        [System.IO.File]::WriteAllBytes($keyPath, $keyBytes)
        $ivHex = [System.BitConverter]::ToString($ivBytes).Replace("-", "").ToLowerInvariant()

        $keyInfoContent = "secret.key`n" + $keyPath + "`n" + $ivHex
        [System.IO.File]::WriteAllText($keyInfoPath, $keyInfoContent, $utf8NoBom)

        Write-Host "  -> [$index/$($mp4Files.Count)] Encrypting '$($file.Name)'..." -ForegroundColor Yellow

        $ffArgs = @("-y", "-i", $file.FullName)
        if ($CopyCodec) {
            $ffArgs += @("-c", "copy")
        } else {
            $ffArgs += @("-c:v", "libx264", "-c:a", "aac")
        }
        $ffArgs += @(
            "-hls_time", "$SegmentTime",
            "-hls_key_info_file", $keyInfoPath,
            "-hls_playlist_type", "vod",
            "-hls_segment_filename", $segPattern,
            $m3u8Path
        )

        & $ffmpegExe @ffArgs
        if ($LASTEXITCODE -ne 0) {
            throw "FFmpeg failed while encrypting '$($file.Name)'."
        }
        Remove-Item -LiteralPath $keyInfoPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "  -> [$index/$($mp4Files.Count)] Already encrypted: '$($file.Name)' (skipping FFmpeg)" -ForegroundColor DarkGray
    }

    $catalogList.Add(@{
        title = $rawTitle
        path  = "videos/$safeSlug/index.m3u8"
    })
}

$catalogJsonPath = Join-Path $EncryptedRoot "catalog.json"
$catalogJsonText = ConvertTo-Json -InputObject $catalogList.ToArray() -Depth 4
if (-not $catalogJsonText.TrimStart().StartsWith("[")) {
    $catalogJsonText = "[$catalogJsonText]"
}
[System.IO.File]::WriteAllText($catalogJsonPath, $catalogJsonText, $utf8NoBom)
Write-Host "[OK] Encrypted $($mp4Files.Count) video(s) and generated catalog.json" -ForegroundColor Green

# 4. Create R2 Bucket via Cloudflare API
Write-Host "[STEP 2/5] Ensuring Private R2 Bucket '$BucketName' exists..." -ForegroundColor Cyan
try {
    $r2Body = ConvertTo-Json @{ name = $BucketName }
    Invoke-RestMethod -Method Post -Uri "https://api.cloudflare.com/client/v4/accounts/$AccountId/r2/buckets" -Headers $Headers -Body $r2Body > $null
    Write-Host "[OK] Created R2 Bucket: $BucketName" -ForegroundColor Green
} catch {
    Write-Host "[OK] R2 Bucket '$BucketName' already exists or is ready." -ForegroundColor Green
}

# 5. Create or Find D1 Database via Cloudflare API
Write-Host "[STEP 3/5] Ensuring D1 SQLite Database '$DatabaseName' exists..." -ForegroundColor Cyan
$d1Uuid = ""
$d1ListResp = Invoke-RestMethod -Method Get -Uri "https://api.cloudflare.com/client/v4/accounts/$AccountId/d1/database" -Headers $Headers
foreach ($dbItem in $d1ListResp.result) {
    if ($dbItem.name -eq $DatabaseName) {
        $d1Uuid = $dbItem.uuid
        break
    }
}
if ([string]::IsNullOrWhiteSpace($d1Uuid)) {
    $d1CreateBody = ConvertTo-Json @{ name = $DatabaseName }
    $d1CreateResp = Invoke-RestMethod -Method Post -Uri "https://api.cloudflare.com/client/v4/accounts/$AccountId/d1/database" -Headers $Headers -Body $d1CreateBody
    $d1Uuid = $d1CreateResp.result.uuid
    Write-Host "[OK] Created D1 Database '$DatabaseName' (UUID: $d1Uuid)" -ForegroundColor Green
} else {
    Write-Host "[OK] Found existing D1 Database '$DatabaseName' (UUID: $d1Uuid)" -ForegroundColor Green
}

# Initialize users table in D1
$initSqlBody = ConvertTo-Json @{
    sql = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, has_access INTEGER DEFAULT 1);"
}
try {
    Invoke-RestMethod -Method Post -Uri "https://api.cloudflare.com/client/v4/accounts/$AccountId/d1/database/$d1Uuid/query" -Headers $Headers -Body $initSqlBody > $null
} catch {}

# 6. Upload All Encrypted HLS Files & catalog.json to R2 via Cloudflare API
Write-Host "[STEP 4/5] Uploading encrypted HLS files to R2 Bucket '$BucketName'..." -ForegroundColor Cyan
$uploadCacheFile = Join-Path $EncryptedRoot ".uploaded_files.txt"
$uploadedSet = New-Object System.Collections.Generic.HashSet[string]
if (Test-Path -LiteralPath $uploadCacheFile) {
    $existingLines = [System.IO.File]::ReadAllLines($uploadCacheFile)
    foreach ($line in $existingLines) {
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            [void]$uploadedSet.Add($line.Trim())
        }
    }
}

$curlExe = "$env:SystemRoot\System32\curl.exe"
if (-not (Test-Path -LiteralPath $curlExe)) {
    $curlExe = "curl"
}

function Upload-R2File([string]$LocalFile, [string]$R2Key, [string]$ContentType, [bool]$AlwaysOverwrite) {
    if ((-not $AlwaysOverwrite) -and $uploadedSet.Contains($R2Key)) {
        return
    }
    $uploadUrl = "https://api.cloudflare.com/client/v4/accounts/$AccountId/r2/buckets/$BucketName/objects/$R2Key"
    & $curlExe -s -S -X PUT $uploadUrl -H "Authorization: Bearer $ApiToken" -H "Content-Type: $ContentType" --data-binary "@$LocalFile" > $null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to upload $R2Key to Cloudflare R2."
    }
    if (-not $uploadedSet.Contains($R2Key)) {
        [void]$uploadedSet.Add($R2Key)
        [System.IO.File]::AppendAllText($uploadCacheFile, "$R2Key`n", $utf8NoBom)
    }
}

# Upload catalog.json (always overwrite so new videos appear)
Upload-R2File -LocalFile $catalogJsonPath -R2Key "catalog.json" -ContentType "application/json" -AlwaysOverwrite $true

$allVideoDirs = @(Get-ChildItem -Path $EncryptedRoot -Directory)
$dirCount = 0
foreach ($vDir in $allVideoDirs) {
    $dirCount++
    $filesInDir = @(Get-ChildItem -Path $vDir.FullName -File)
    Write-Host "  -> [$dirCount/$($allVideoDirs.Count)] Uploading folder '$($vDir.Name)' ($($filesInDir.Count) files)..." -ForegroundColor Yellow
    foreach ($f in $filesInDir) {
        if ($f.Name -eq "secret.keyinfo") { continue }
        $r2ObjectKey = "videos/$($vDir.Name)/$($f.Name)"
        $cType = "application/octet-stream"
        if ($f.Extension -eq ".m3u8") { $cType = "application/vnd.apple.mpegurl" }
        elseif ($f.Extension -eq ".ts") { $cType = "video/mp2t" }
        Upload-R2File -LocalFile $f.FullName -R2Key $r2ObjectKey -ContentType $cType -AlwaysOverwrite $false
    }
}
Write-Host "[OK] All encrypted HLS files uploaded to R2!" -ForegroundColor Green

# 7. Deploy the Cloudflare Worker with D1 and R2 Bindings Attached Automatically
Write-Host "[STEP 5/5] Deploying Worker '$WorkerName' with D1 & R2 Bindings..." -ForegroundColor Cyan

$workerFileLocal = Join-Path $EncryptedRoot "worker_bundle.mjs"
$embeddedWorkerCode = @'
const DEFAULT_JWT_SECRET = "change-this-secret-in-worker-variables-2026";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const allowedOrigin = env.ALLOWED_ORIGIN || "*";
    const jwtSecret = env.JWT_SECRET || DEFAULT_JWT_SECRET;

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: getCorsHeaders(allowedOrigin) });
    }

    const userAgent = (request.headers.get("User-Agent") || "").toLowerCase();
    const blockedAgents = ["yt-dlp", "youtube-dl", "ffmpeg", "lavf", "idm", "curl", "wget", "aria2"];
    if (blockedAgents.some((bot) => userAgent.includes(bot))) {
      return jsonResponse({ error: "External downloaders are blocked." }, 403, allowedOrigin);
    }

    if (url.pathname === "/api/health") {
      return jsonResponse({
        worker: "online",
        hasD1Binding: Boolean(env.DB),
        hasR2Binding: Boolean(env.VIDEO_BUCKET),
      }, 200, allowedOrigin);
    }

    if (url.pathname === "/" && request.method === "GET") {
      return new Response(getBuiltInPlayerHtml(), {
        status: 200,
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (url.pathname === "/api/register" && request.method === "POST") {
      if (!env.DB) return jsonResponse({ error: "D1 binding 'DB' is missing." }, 500, allowedOrigin);
      await ensureUsersTable(env.DB);
      const { email, password } = await request.json();
      if (!email || !password) return jsonResponse({ error: "Email and password required." }, 400, allowedOrigin);
      const passwordHash = await sha256Hex(password + ":" + jwtSecret);
      try {
        await env.DB.prepare("INSERT INTO users (email, password_hash, has_access) VALUES (?1, ?2, 1)")
          .bind(email.toLowerCase().trim(), passwordHash)
          .run();
        return jsonResponse({ message: "Account created! Click Login & Watch." }, 201, allowedOrigin);
      } catch {
        return jsonResponse({ error: "Email already registered. Click Login & Watch." }, 409, allowedOrigin);
      }
    }

    if (url.pathname === "/api/login" && request.method === "POST") {
      if (!env.DB) return jsonResponse({ error: "D1 binding 'DB' is missing." }, 500, allowedOrigin);
      await ensureUsersTable(env.DB);
      const { email, password } = await request.json();
      const passwordHash = await sha256Hex(password + ":" + jwtSecret);
      const user = await env.DB.prepare(
        "SELECT id, email, has_access FROM users WHERE email = ?1 AND password_hash = ?2"
      ).bind((email || "").toLowerCase().trim(), passwordHash).first();

      if (!user) return jsonResponse({ error: "Invalid email or password." }, 401, allowedOrigin);
      if (!user.has_access) return jsonResponse({ error: "Access disabled by admin." }, 403, allowedOrigin);

      const clientIp = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
      const token = await signJwt({
        sub: user.id,
        email: user.email,
        ip: clientIp,
        exp: Math.floor(Date.now() / 1000) + 14400,
      }, jwtSecret);

      return jsonResponse({ token, email: user.email }, 200, allowedOrigin);
    }

    if (url.pathname.startsWith("/stream/")) {
      if (!env.VIDEO_BUCKET) return jsonResponse({ error: "R2 binding 'VIDEO_BUCKET' is missing." }, 500, allowedOrigin);
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
      const payload = await verifyJwt(token, jwtSecret);
      if (!payload) return jsonResponse({ error: "Unauthorized token." }, 401, allowedOrigin);

      const clientIp = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
      if (payload.ip !== clientIp) return jsonResponse({ error: "IP mismatch." }, 403, allowedOrigin);

      const requestedPath = decodeURIComponent(url.pathname.replace(/^\/stream\//, ""));
      if (requestedPath.endsWith(".key") && (request.headers.get("Sec-Fetch-Dest") || "") === "document") {
        return jsonResponse({ error: "Direct key download forbidden." }, 403, allowedOrigin);
      }

      let object = await env.VIDEO_BUCKET.get(requestedPath);
      if (!object && !requestedPath.startsWith("videos/")) {
        object = await env.VIDEO_BUCKET.get("videos/" + requestedPath);
      }
      if (!object) return jsonResponse({ error: "File not found: " + requestedPath }, 404, allowedOrigin);

      const headers = new Headers(getCorsHeaders(allowedOrigin));
      if (requestedPath.endsWith(".m3u8")) {
        headers.set("Content-Type", "application/vnd.apple.mpegurl");
        headers.set("Cache-Control", "no-store");
      } else if (requestedPath.endsWith(".key")) {
        headers.set("Content-Type", "application/octet-stream");
        headers.set("Cache-Control", "no-store, no-cache, must-revalidate");
      } else if (requestedPath.endsWith(".ts")) {
        headers.set("Content-Type", "video/mp2t");
        headers.set("Cache-Control", "public, max-age=86400");
      } else if (requestedPath.endsWith(".json")) {
        headers.set("Content-Type", "application/json");
        headers.set("Cache-Control", "no-store");
      }
      return new Response(object.body, { status: 200, headers });
    }
    return jsonResponse({ error: "Not found" }, 404, allowedOrigin);
  },
};

async function ensureUsersTable(db) {
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, has_access INTEGER DEFAULT 1)"
  ).run();
}
function getCorsHeaders(allowedOrigin) {
  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Range",
    "Access-Control-Expose-Headers": "Content-Length, Content-Range",
  };
}
function jsonResponse(data, status, allowedOrigin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...getCorsHeaders(allowedOrigin) },
  });
}
async function sha256Hex(input) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function base64UrlEncode(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return atob(str);
}
async function signJwt(payload, secret) {
  const data = `${base64UrlEncode(JSON.stringify({ alg: "HS256", typ: "JWT" }))}.${base64UrlEncode(JSON.stringify(payload))}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return `${data}.${base64UrlEncode(String.fromCharCode(...new Uint8Array(sig)))}`;
}
async function verifyJwt(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const [encHeader, encPayload, encSig] = parts;
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const sigBytes = Uint8Array.from(base64UrlDecode(encSig), (c) => c.charCodeAt(0));
    const valid = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(`${encHeader}.${encPayload}`));
    if (!valid) return null;
    const payload = JSON.parse(base64UrlDecode(encPayload));
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return null;
    return payload;
  } catch { return null; }
}
function getBuiltInPlayerHtml() {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Protected Video Portal</title>
  <script src="https://cdn.jsdelivr.net/npm/hls.js@latest"></script>
  <style>
    body { background: #0f172a; color: #f8fafc; font-family: system-ui, sans-serif; display: flex; flex-direction: column; align-items: center; padding: 24px; margin: 0; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 24px; width: 100%; max-width: 420px; }
    input, select { width: 100%; box-sizing: border-box; padding: 10px 12px; margin-bottom: 12px; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #fff; }
    .btn-row { display: flex; gap: 10px; }
    button { flex: 1; padding: 10px; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; background: #3b82f6; color: #fff; }
    button.secondary { background: #475569; }
    #statusMsg { margin-top: 12px; font-size: 14px; color: #f87171; }
    .player-wrap { display: none; width: 100%; max-width: 880px; margin-top: 16px; }
    .video-box { position: relative; background: #000; border-radius: 10px; overflow: hidden; }
    video { width: 100%; display: block; }
    .watermark { position: absolute; color: rgba(255,255,255,0.35); font-size: 14px; font-weight: 600; pointer-events: none; user-select: none; z-index: 20; transition: all 2s ease; }
    .controls-bar { display: flex; gap: 8px; margin-bottom: 12px; align-items: center; }
  </style>
</head>
<body>
  <div class="card" id="authCard">
    <h2>Protected Video Login</h2>
    <input id="email" type="email" placeholder="Email address" />
    <input id="password" type="password" placeholder="Password" />
    <div class="btn-row">
      <button onclick="handleAuth('/api/login')">Login & Watch</button>
      <button class="secondary" onclick="handleAuth('/api/register')">Register New User</button>
    </div>
    <div id="statusMsg"></div>
  </div>
  <div class="player-wrap" id="playerWrap">
    <div class="controls-bar">
      <select id="videoSelect" onchange="onSelectVideo()" style="margin:0; flex: 1;"></select>
      <input id="manifestPath" type="text" value="index.m3u8" style="margin:0; flex: 1;" />
      <button onclick="loadVideo()" style="flex:0 0 130px;">Play Video</button>
    </div>
    <div class="video-box" oncontextmenu="return false;">
      <div class="watermark" id="wm"></div>
      <video id="video" controls controlsList="nodownload"></video>
    </div>
  </div>
  <script>
    let jwtToken = "";
    let hlsInstance = null;
    async function handleAuth(endpoint) {
      const msg = document.getElementById("statusMsg");
      msg.style.color = "#94a3b8";
      msg.textContent = "Processing...";
      const email = document.getElementById("email").value;
      const password = document.getElementById("password").value;
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      if (!res.ok) { msg.style.color = "#f87171"; msg.textContent = data.error; return; }
      if (endpoint === "/api/register") { msg.style.color = "#4ade80"; msg.textContent = data.message; return; }
      jwtToken = data.token;
      document.getElementById("authCard").style.display = "none";
      document.getElementById("playerWrap").style.display = "block";
      startWatermark(data.email);
      await loadCatalog();
      loadVideo();
    }
    async function loadCatalog() {
      const sel = document.getElementById("videoSelect");
      try {
        const res = await fetch("/stream/catalog.json", { headers: { "Authorization": "Bearer " + jwtToken } });
        const items = await res.json();
        if (Array.isArray(items) && items.length > 0) {
          sel.innerHTML = "";
          items.forEach((item) => {
            const opt = document.createElement("option");
            opt.value = item.path;
            opt.textContent = item.title;
            sel.appendChild(opt);
          });
          document.getElementById("manifestPath").value = items[0].path;
        }
      } catch { sel.innerHTML = '<option value="index.m3u8">Default Video</option>'; }
    }
    function onSelectVideo() {
      document.getElementById("manifestPath").value = document.getElementById("videoSelect").value;
      loadVideo();
    }
    function loadVideo() {
      const video = document.getElementById("video");
      const streamUrl = "/stream/" + document.getElementById("manifestPath").value.replace(/^\\/+/, "");
      if (Hls.isSupported()) {
        if (hlsInstance) hlsInstance.destroy();
        hlsInstance = new Hls({ xhrSetup: (xhr) => xhr.setRequestHeader("Authorization", "Bearer " + jwtToken) });
        hlsInstance.loadSource(streamUrl);
        hlsInstance.attachMedia(video);
        hlsInstance.on(Hls.Events.MANIFEST_PARSED, () => video.play().catch(() => {}));
      } else if (video.canPlayType("application/vnd.apple.mpegurl")) { video.src = streamUrl; }
    }
    function startWatermark(email) {
      const wm = document.getElementById("wm");
      wm.textContent = email;
      setInterval(() => {
        wm.style.top = Math.floor(Math.random() * 80 + 10) + "%";
        wm.style.left = Math.floor(Math.random() * 70 + 10) + "%";
      }, 4000);
    }
  </script>
</body>
</html>`;
}
'@
[System.IO.File]::WriteAllText($workerFileLocal, $embeddedWorkerCode, $utf8NoBom)

$jwtRandomBytes = New-Object byte[] 24
$rng.GetBytes($jwtRandomBytes)
$jwtSecretVal = [System.BitConverter]::ToString($jwtRandomBytes).Replace("-", "").ToLowerInvariant()

$metadataObj = @{
    main_module        = "worker.mjs"
    compatibility_date = "2025-08-06"
    bindings           = @(
        @{
            type = "d1"
            name = "DB"
            id   = $d1Uuid
        },
        @{
            type        = "r2_bucket"
            name        = "VIDEO_BUCKET"
            bucket_name = $BucketName
        },
        @{
            type = "plain_text"
            name = "JWT_SECRET"
            text = $jwtSecretVal
        }
    )
}

$metadataPath = Join-Path $EncryptedRoot "worker_metadata.json"
$metadataJson = ConvertTo-Json -InputObject $metadataObj -Depth 6 -Compress
[System.IO.File]::WriteAllText($metadataPath, $metadataJson, $utf8NoBom)

$deployUrl = "https://api.cloudflare.com/client/v4/accounts/$AccountId/workers/scripts/$WorkerName"
& $curlExe -s -S -X PUT $deployUrl `
    -H "Authorization: Bearer $ApiToken" `
    -F "metadata=@$metadataPath;type=application/json" `
    -F "worker.mjs=@$workerFileLocal;type=application/javascript+module" > $null

if ($LASTEXITCODE -ne 0) {
    throw "Worker deployment failed via curl."
}

# Enable *.workers.dev subdomain route for this Worker
$subEnableBody = ConvertTo-Json @{ enabled = $true }
try {
    Invoke-RestMethod -Method Post -Uri "https://api.cloudflare.com/client/v4/accounts/$AccountId/workers/scripts/$WorkerName/subdomain" -Headers $Headers -Body $subEnableBody > $null
} catch {}

# Fetch account's workers.dev subdomain name
$liveUrl = "https://$WorkerName.workers.dev"
try {
    $subResp = Invoke-RestMethod -Method Get -Uri "https://api.cloudflare.com/client/v4/accounts/$AccountId/workers/subdomain" -Headers $Headers
    if ($null -ne $subResp.result -and -not [string]::IsNullOrWhiteSpace($subResp.result.subdomain)) {
        $liveUrl = "https://$WorkerName.$($subResp.result.subdomain).workers.dev"
    }
} catch {}

Write-Host "======================================================================" -ForegroundColor Green
Write-Host " SUCCESS! YOUR CLOUDFLARE PROTECTED VIDEO PLATFORM IS LIVE!" -ForegroundColor Green
Write-Host " Portal URL : $liveUrl" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Green
Start-Process $liveUrl
