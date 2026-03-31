# ============================================================================
# Axios Supply Chain Attack — Detection Script (Windows)
# ============================================================================
# Run in PowerShell: .\check.ps1
# ============================================================================

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  Axios Supply Chain Attack - Detection" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$found = $false

# --- Check 1: Installed axios version ---
Write-Host "[1/5] Checking installed axios version..." -ForegroundColor Yellow
$axiosCheck = npm list axios 2>$null | Select-String "1\.14\.1|0\.30\.4"
if ($axiosCheck) {
    Write-Host "  !! AFFECTED: Compromised axios version found" -ForegroundColor Red
    Write-Host "  $axiosCheck"
    $found = $true
} else {
    Write-Host "  OK: No compromised axios version installed" -ForegroundColor Green
}

# --- Check 2: Lockfile ---
Write-Host ""
Write-Host "[2/5] Checking lockfile..." -ForegroundColor Yellow
if (Test-Path "package-lock.json") {
    $lockContent = Get-Content "package-lock.json" -Raw

    # Check for malicious dependency name
    $hasMaliciousDep = $lockContent -match "plain-crypto-js"

    # Check for axios specifically at compromised versions
    $hasCompromisedAxios = [regex]::IsMatch(
        $lockContent,
        '"node_modules/axios":\s*\{[^}]*?"version":\s*"(1\.14\.1|0\.30\.4)"'
    )

    # Also check lockfile v1 format
    if (-not $hasCompromisedAxios) {
        $hasCompromisedAxios = [regex]::IsMatch(
            $lockContent,
            '"axios":\s*\{\s*"version":\s*"(1\.14\.1|0\.30\.4)"'
        )
    }

    if ($hasMaliciousDep -or $hasCompromisedAxios) {
        if ($hasMaliciousDep) { Write-Host "  !! AFFECTED: plain-crypto-js in lockfile" -ForegroundColor Red }
        if ($hasCompromisedAxios) { Write-Host "  !! AFFECTED: Compromised axios version in lockfile" -ForegroundColor Red }
        $found = $true
    } else {
        Write-Host "  OK: Lockfile clean" -ForegroundColor Green
    }
} else {
    Write-Host "  SKIP: No package-lock.json found"
}

# --- Check 3: Malicious dependency ---
Write-Host ""
Write-Host "[3/5] Checking for malicious package..." -ForegroundColor Yellow
if (Test-Path "node_modules\plain-crypto-js") {
    Write-Host "  !! AFFECTED: node_modules\plain-crypto-js EXISTS" -ForegroundColor Red
    $found = $true
} else {
    Write-Host "  OK: plain-crypto-js not in node_modules" -ForegroundColor Green
    Write-Host "  (Note: Malware self-destructs - absence does NOT guarantee safety)"
}

# --- Check 4: RAT artifacts ---
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

# Temp files
$vbsPath = "$env:TEMP\6202033.vbs"
$ps1Path = "$env:TEMP\6202033.ps1"
if ((Test-Path $vbsPath) -or (Test-Path $ps1Path)) {
    Write-Host "  !! WARNING: Temp payload files found" -ForegroundColor Red
    $found = $true
} else {
    Write-Host "  OK: No temp payload files" -ForegroundColor Green
}

# --- Check 5: C2 connections ---
Write-Host ""
Write-Host "[5/5] Checking for C2 connections..." -ForegroundColor Yellow
$c2Check = netstat -an | Select-String "142.11.206.73"
if ($c2Check) {
    Write-Host "  !! CRITICAL: Active connection to C2 (142.11.206.73)" -ForegroundColor Red
    Write-Host "  $c2Check"
    $found = $true
} else {
    Write-Host "  OK: No active C2 connections" -ForegroundColor Green
}

# --- Summary ---
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
if ($found) {
    Write-Host "  !! POTENTIAL COMPROMISE DETECTED" -ForegroundColor Red
    Write-Host ""
    Write-Host "  1. Pin axios to 1.14.0: npm install axios@1.14.0 --save-exact"
    Write-Host "  2. Remove node_modules and reinstall: rm -r node_modules; npm ci"
    Write-Host "  3. Rotate ALL credentials"
    Write-Host "  4. Block sfrclak.com and 142.11.206.73"
    Write-Host "  5. If RAT found: FULL SYSTEM REBUILD"
} else {
    Write-Host "  ALL CLEAR" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Preventive: npm install axios@1.14.0 --save-exact"
    Write-Host "  Set: npm config set min-release-age 3"
}
Write-Host "============================================" -ForegroundColor Cyan
