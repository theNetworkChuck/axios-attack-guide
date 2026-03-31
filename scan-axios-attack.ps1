# ============================================================================
# Axios Supply Chain Attack - Full PC Detection Script (Windows)
# ============================================================================
# Compromised versions: axios@1.14.1, axios@0.30.4
# Malicious dependency: plain-crypto-js
# RAT artifact: wt.exe in ProgramData
# C2 server: 142.11.206.73 / sfrclak.com
# ============================================================================
# Run in PowerShell: .\scan-axios-attack.ps1
# Optional: .\scan-axios-attack.ps1 -ScanRoot "D:\"
# ============================================================================

param(
    [string]$ScanRoot = "C:\"
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Axios Supply Chain Attack - Full PC Scan" -ForegroundColor Cyan
Write-Host "  Scan root: $ScanRoot" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$found = $false
$affectedFiles = @()

# ==========================================================================
# Check 1: Scan all package-lock.json files for compromised axios
# ==========================================================================
Write-Host "[1/5] Scanning all package-lock.json files..." -ForegroundColor Yellow
Write-Host "      (excluding node_modules, Windows, Program Files)" -ForegroundColor DarkGray

$lockfiles = Get-ChildItem -Path $ScanRoot -Recurse -Filter "package-lock.json" -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch "node_modules|\\Windows\\|\\Program Files|\\ProgramData\\|\\AppData\\Roaming\\npm"
    }

Write-Host "      Found $($lockfiles.Count) lockfile(s)" -ForegroundColor DarkGray

foreach ($f in $lockfiles) {
    $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { continue }

    # Check for malicious dependency (unambiguous - always a red flag)
    if ($content -match "plain-crypto-js") {
        Write-Host "  !! CRITICAL: plain-crypto-js found in $($f.FullName)" -ForegroundColor Red
        $affectedFiles += $f.FullName
        $found = $true
    }

    # Check axios version using package-name-anchored regex (prevents false positives)
    # Lockfile v2/v3 format: "node_modules/axios": { ... "version": "x.y.z" }
    $match = [regex]::Match($content, '"node_modules/axios":\s*\{[^}]*?"version":\s*"([^"]+)"')

    # Lockfile v1 format: "axios": { "version": "x.y.z" }
    if (-not $match.Success) {
        $match = [regex]::Match($content, '"axios":\s*\{\s*"version":\s*"([^"]+)"')
    }

    if ($match.Success) {
        $ver = $match.Groups[1].Value
        if ($ver -eq "1.14.1" -or $ver -eq "0.30.4") {
            Write-Host "  !! AFFECTED: axios@$ver in $($f.FullName)" -ForegroundColor Red
            $affectedFiles += $f.FullName
            $found = $true
        } else {
            Write-Host "  OK: axios@$ver in $($f.FullName)" -ForegroundColor Green
        }
    }
}

if ($lockfiles.Count -eq 0) {
    Write-Host "  SKIP: No package-lock.json files found" -ForegroundColor DarkGray
}

# ==========================================================================
# Check 2: Scan yarn.lock files
# ==========================================================================
Write-Host ""
Write-Host "[2/5] Scanning yarn.lock files..." -ForegroundColor Yellow

$yarnLocks = Get-ChildItem -Path $ScanRoot -Recurse -Filter "yarn.lock" -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -notmatch "node_modules|\\Windows\\|\\Program Files|\\ProgramData\\|\\AppData\\Roaming\\npm"
    }

Write-Host "      Found $($yarnLocks.Count) yarn.lock file(s)" -ForegroundColor DarkGray

foreach ($f in $yarnLocks) {
    $content = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
    if (-not $content) { continue }

    if ($content -match "plain-crypto-js") {
        Write-Host "  !! CRITICAL: plain-crypto-js found in $($f.FullName)" -ForegroundColor Red
        $affectedFiles += $f.FullName
        $found = $true
    }

    # yarn.lock format: axios@^x.y.z:\n  version "x.y.z"
    $yarnMatch = [regex]::Match($content, 'axios@[^:]+:\s*\n\s*version\s+"(1\.14\.1|0\.30\.4)"')
    if ($yarnMatch.Success) {
        $ver = $yarnMatch.Groups[1].Value
        Write-Host "  !! AFFECTED: axios@$ver in $($f.FullName)" -ForegroundColor Red
        $affectedFiles += $f.FullName
        $found = $true
    } elseif ($content -match 'axios@') {
        $safeMatch = [regex]::Match($content, 'axios@[^:]+:\s*\n\s*version\s+"([^"]+)"')
        if ($safeMatch.Success) {
            Write-Host "  OK: axios@$($safeMatch.Groups[1].Value) in $($f.FullName)" -ForegroundColor Green
        }
    }
}

if ($yarnLocks.Count -eq 0) {
    Write-Host "  SKIP: No yarn.lock files found" -ForegroundColor DarkGray
}

# ==========================================================================
# Check 3: Malicious package in node_modules
# ==========================================================================
Write-Host ""
Write-Host "[3/5] Checking for plain-crypto-js in node_modules..." -ForegroundColor Yellow

$maliciousDirs = Get-ChildItem -Path $ScanRoot -Recurse -Directory -Filter "plain-crypto-js" -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match "node_modules" }

if ($maliciousDirs) {
    foreach ($d in $maliciousDirs) {
        Write-Host "  !! CRITICAL: $($d.FullName)" -ForegroundColor Red
        $affectedFiles += $d.FullName
    }
    $found = $true
} else {
    Write-Host "  OK: plain-crypto-js not found in any node_modules" -ForegroundColor Green
    Write-Host "  (Note: Malware self-destructs - absence does NOT guarantee safety)" -ForegroundColor DarkGray
}

# ==========================================================================
# Check 4: RAT artifacts
# ==========================================================================
Write-Host ""
Write-Host "[4/5] Checking for RAT artifacts..." -ForegroundColor Yellow

# Windows RAT: wt.exe in ProgramData
$wtPath = "$env:PROGRAMDATA\wt.exe"
if (Test-Path $wtPath) {
    Write-Host "  !! CRITICAL: Windows RAT found at $wtPath" -ForegroundColor Red
    Get-Item $wtPath | Format-List Name, Length, LastWriteTime
    $found = $true
} else {
    Write-Host "  OK: wt.exe not found in ProgramData" -ForegroundColor Green
}

# Temp payload files
$vbsPath = "$env:TEMP\6202033.vbs"
$ps1Path = "$env:TEMP\6202033.ps1"
if ((Test-Path $vbsPath) -or (Test-Path $ps1Path)) {
    Write-Host "  !! WARNING: Temp payload files found" -ForegroundColor Red
    if (Test-Path $vbsPath) { Write-Host "     $vbsPath" -ForegroundColor Red }
    if (Test-Path $ps1Path) { Write-Host "     $ps1Path" -ForegroundColor Red }
    $found = $true
} else {
    Write-Host "  OK: No temp payload files (6202033.vbs / 6202033.ps1)" -ForegroundColor Green
}

# ==========================================================================
# Check 5: C2 connections
# ==========================================================================
Write-Host ""
Write-Host "[5/5] Checking for C2 connections..." -ForegroundColor Yellow

$c2Check = netstat -an 2>$null | Select-String "142.11.206.73"
if ($c2Check) {
    Write-Host "  !! CRITICAL: Active connection to C2 server (142.11.206.73)" -ForegroundColor Red
    $c2Check | ForEach-Object { Write-Host "     $_" -ForegroundColor Red }
    $found = $true
} else {
    Write-Host "  OK: No active C2 connections (142.11.206.73)" -ForegroundColor Green
}

# Also check DNS cache for the C2 domain
$dnsCheck = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match "sfrclak\.com" }
if ($dnsCheck) {
    Write-Host "  !! WARNING: sfrclak.com found in DNS cache" -ForegroundColor Red
    $found = $true
} else {
    Write-Host "  OK: sfrclak.com not in DNS cache" -ForegroundColor Green
}

# ==========================================================================
# Summary
# ==========================================================================
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
if ($found) {
    Write-Host "  !! POTENTIAL COMPROMISE DETECTED" -ForegroundColor Red
    Write-Host ""
    if ($affectedFiles.Count -gt 0) {
        Write-Host "  Affected files:" -ForegroundColor Red
        $affectedFiles | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
        Write-Host ""
    }
    Write-Host "  Remediation steps:" -ForegroundColor Yellow
    Write-Host "  1. Pin axios: npm install axios@1.14.0 --save-exact"
    Write-Host "  2. Clean reinstall: rm -r node_modules; npm ci"
    Write-Host "  3. Rotate ALL credentials (npm tokens, env vars, API keys)"
    Write-Host "  4. Block sfrclak.com and 142.11.206.73 at firewall"
    Write-Host "  5. If RAT (wt.exe) found: FULL SYSTEM REBUILD REQUIRED"
} else {
    Write-Host "  ALL CLEAR - No compromise indicators found" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Preventive measures:" -ForegroundColor DarkGray
    Write-Host "  - npm install axios@1.14.0 --save-exact" -ForegroundColor DarkGray
    Write-Host "  - npm config set min-release-age 3" -ForegroundColor DarkGray
}
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
