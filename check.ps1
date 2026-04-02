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

# --- Check 1: Installed axios version in dependency tree ---
Write-Host "[1/5] Checking axios versions in dependency tree..." -ForegroundColor Yellow

if (Test-Path "yarn.lock") {
    if (Get-Command yarn -ErrorAction SilentlyContinue) {
        $treeOut = yarn why axios 2>$null
        $compromised = $treeOut | Select-String "1\.14\.1|0\.30\.4"
        if ($compromised) {
            Write-Host "  !! AFFECTED: Compromised axios in yarn dependency tree" -ForegroundColor Red
            $treeOut | ForEach-Object { Write-Host "    $_" }
            $found = $true
        } else {
            Write-Host "  OK: No compromised axios in yarn dependency tree" -ForegroundColor Green
        }
    } else {
        Write-Host "  SKIP: yarn not found" -ForegroundColor Yellow
    }
} elseif (Test-Path "pnpm-lock.yaml") {
    if (Get-Command pnpm -ErrorAction SilentlyContinue) {
        $treeOut = pnpm list axios --depth=Infinity 2>$null
        $compromised = $treeOut | Select-String "axios.*(1\.14\.1|0\.30\.4)"
        if ($compromised) {
            Write-Host "  !! AFFECTED: Compromised axios in pnpm dependency tree" -ForegroundColor Red
            $treeOut | ForEach-Object { Write-Host "    $_" }
            $found = $true
        } else {
            Write-Host "  OK: No compromised axios in pnpm dependency tree" -ForegroundColor Green
        }
    } else {
        Write-Host "  SKIP: pnpm not found" -ForegroundColor Yellow
    }
} elseif (Test-Path "bun.lockb") {
    if (Get-Command bun -ErrorAction SilentlyContinue) {
        $treeOut = bun pm ls --all 2>$null
        $compromised = $treeOut | Select-String "axios@.*(1\.14\.1|0\.30\.4)"
        if ($compromised) {
            Write-Host "  !! AFFECTED: Compromised axios in bun dependency tree" -ForegroundColor Red
            $compromised | ForEach-Object { Write-Host "    $_" }
            $found = $true
        } else {
            Write-Host "  OK: No compromised axios in bun dependency tree" -ForegroundColor Green
        }
    } else {
        Write-Host "  SKIP: bun not found" -ForegroundColor Yellow
    }
} else {
    $axiosTree = npm list axios --all 2>$null
    $axiosInstances = $axiosTree | Select-String "axios@"
    if ($axiosInstances) {
        $compromised = $axiosInstances | Select-String "axios@1\.14\.1|axios@0\.30\.4"
        if ($compromised) {
            Write-Host "  !! AFFECTED: Compromised axios in npm dependency tree" -ForegroundColor Red
            $axiosTree | ForEach-Object { Write-Host "    $_" }
            $found = $true
        } else {
            Write-Host "  OK: No compromised axios in npm dependency tree" -ForegroundColor Green
        }
    } else {
        Write-Host "  OK: axios not found in dependencies" -ForegroundColor Green
    }
}

# --- Check 2: Lockfile ---
Write-Host ""
Write-Host "[2/5] Checking lockfile..." -ForegroundColor Yellow
$lockfileFound = $false
$pkgManager = "npm"  # default; overridden below if another lockfile is found

# Helper: find compromised axios version in decoded yarn-style text
function Find-AxiosInYarnFormat($lines) {
    $inAxios = $false
    foreach ($line in $lines) {
        if ($line -match '^axios@') { $inAxios = $true; continue }
        if ($line -match '^[^ \t]') { $inAxios = $false }
        if ($inAxios -and $line -match 'version "(1\.14\.1|0\.30\.4)"') { return $line }
    }
    return $null
}

if (Test-Path "package-lock.json") {
    $lockfileFound = $true
    $lockHit = $null  # reset to avoid carry-over from a previous check
    # Scope to the axios entry specifically, not any package with that version number
    $content = Get-Content "package-lock.json"
    $axiosIdx = ($content | Select-String -Pattern '"node_modules/axios"').LineNumber
    if ($axiosIdx) {
        # LineNumber is 1-based; subtract 1 for 0-based array index
        $block = $content[($axiosIdx - 1)..([math]::Min($axiosIdx + 4, $content.Count - 1))]
        $lockHit = $block | Select-String -Pattern '"(1\.14\.1|0\.30\.4)"'
    }
    if ($lockHit) {
        Write-Host "  !! AFFECTED: Compromised axios version found in package-lock.json" -ForegroundColor Red
        $found = $true
    } else {
        Write-Host "  OK: package-lock.json clean" -ForegroundColor Green
    }
}

if (Test-Path "yarn.lock") {
    $lockfileFound = $true
    $pkgManager = "yarn"
    $lockHit = Find-AxiosInYarnFormat (Get-Content "yarn.lock")
    if ($lockHit) {
        Write-Host "  !! AFFECTED: Compromised axios version found in yarn.lock" -ForegroundColor Red
        $found = $true
    } else {
        Write-Host "  OK: yarn.lock clean" -ForegroundColor Green
    }
}

if (Test-Path "pnpm-lock.yaml") {
    $lockfileFound = $true
    $pkgManager = "pnpm"
    # pnpm entries are keyed as "/axios@VERSION:" or "axios@VERSION:"
    $lockHit = Select-String -Path "pnpm-lock.yaml" -Pattern "(^|/)axios@(1\.14\.1|0\.30\.4):"
    if ($lockHit) {
        Write-Host "  !! AFFECTED: Compromised axios version found in pnpm-lock.yaml" -ForegroundColor Red
        $found = $true
    } else {
        Write-Host "  OK: pnpm-lock.yaml clean" -ForegroundColor Green
    }
}

if (Test-Path "deno.lock") {
    $lockfileFound = $true
    $pkgManager = "deno"
    # deno.lock is JSON; npm entries are keyed as "axios@VERSION"
    $lockHit = Select-String -Path "deno.lock" -Pattern '"axios@(1\.14\.1|0\.30\.4)"'
    if ($lockHit) {
        Write-Host "  !! AFFECTED: Compromised axios version found in deno.lock" -ForegroundColor Red
        $found = $true
    } else {
        Write-Host "  OK: deno.lock clean" -ForegroundColor Green
    }
}

if (Test-Path "bun.lockb") {
    $lockfileFound = $true
    $pkgManager = "bun"
    $bunCmd = Get-Command bun -ErrorAction SilentlyContinue
    if ($bunCmd) {
        # bun.lockb is binary — decode to yarn-style text first, then scope to axios blocks
        $bunLines = & bun bun.lockb 2>$null
        $lockHit = Find-AxiosInYarnFormat $bunLines
        if ($lockHit) {
            Write-Host "  !! AFFECTED: Compromised axios version found in bun.lockb" -ForegroundColor Red
            $found = $true
        } else {
            Write-Host "  OK: bun.lockb clean" -ForegroundColor Green
        }
    } else {
        Write-Host "  WARN: bun.lockb found but 'bun' not installed — cannot decode binary lockfile, skipping" -ForegroundColor Yellow
    }
}

if (-not $lockfileFound) {
    Write-Host "  SKIP: No lockfile found"
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
    Write-Host "  1. Pin axios to 1.14.0 or 0.30.3"
    Write-Host "  2. Remove node_modules and reinstall cleanly:"
    switch ($pkgManager) {
        "yarn" { Write-Host "       Remove-Item -Recurse node_modules; yarn install --frozen-lockfile" }
        "pnpm" { Write-Host "       Remove-Item -Recurse node_modules; pnpm install --frozen-lockfile" }
        "bun"  { Write-Host "       Remove-Item -Recurse node_modules; bun install --frozen-lockfile" }
        "deno" { Write-Host "       deno install" }
        default { Write-Host "       Remove-Item -Recurse node_modules; npm ci" }
    }
    Write-Host "  3. Rotate ALL credentials"
    Write-Host "  4. Block sfrclak.com and 142.11.206.73"
    Write-Host "  5. If RAT found: FULL SYSTEM REBUILD"
} else {
    Write-Host "  ALL CLEAR" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Preventive steps:"
    Write-Host "  - Pin axios to a safe version:"
    switch ($pkgManager) {
        "yarn" {
            Write-Host "       yarn add axios@1.14.0 --exact"
            Write-Host "  - Use frozen installs in CI/CD: yarn install --frozen-lockfile"
            Write-Host "  - Set ignore-scripts: true in .yarnrc.yml"
        }
        "pnpm" {
            Write-Host "       pnpm add axios@1.14.0 --save-exact"
            Write-Host "  - Use frozen installs in CI/CD: pnpm install --frozen-lockfile"
            Write-Host "  - Set ignore-scripts=true in .npmrc"
        }
        "bun" {
            Write-Host "       bun add axios@1.14.0 --exact"
            Write-Host "  - Use frozen installs in CI/CD: bun install --frozen-lockfile"
        }
        "deno" {
            Write-Host "       deno add npm:axios@1.14.0"
        }
        default {
            Write-Host "       npm install axios@1.14.0 --save-exact"
            Write-Host "  - Use frozen installs in CI/CD: npm ci"
            Write-Host "  - Set ignore-scripts=true in .npmrc"
            Write-Host "  - Run: npm config set min-release-age 3"
        }
    }
}
Write-Host "============================================" -ForegroundColor Cyan
