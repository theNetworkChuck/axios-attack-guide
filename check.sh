#!/bin/bash
# ============================================================================
# Axios Supply Chain Attack — Detection Script (macOS/Linux)
# ============================================================================
# Checks if your system was affected by the axios@1.14.1 / axios@0.30.4
# supply chain attack that dropped a cross-platform RAT via plain-crypto-js.
#
# FIXED: Now checks axios versions across entire dependency tree
#
# Source: StepSecurity, Socket.dev, GitHub Issue #10604
# ============================================================================

echo "============================================"
echo "  Axios Supply Chain Attack — Detection"
echo "============================================"
echo ""

FOUND=0

# --- Check 1: Installed axios version in entire dependency tree ---
echo "[1/6] Checking axios versions in dependency tree..."

check_dep_tree_npm() {
  if ! command -v npm &> /dev/null; then echo "  SKIP: npm not found"; return; fi
  AXIOS_TREE=$(npm list axios --all 2>/dev/null)
  AXIOS_INSTANCES=$(echo "$AXIOS_TREE" | grep "axios@")
  if [ -z "$AXIOS_INSTANCES" ]; then echo "  OK: axios not found in npm dependencies"; return; fi
  COMPROMISED=$(echo "$AXIOS_INSTANCES" | grep -E "axios@1\.14\.1|axios@0\.30\.4")
  if [ -n "$COMPROMISED" ]; then
    echo "  !! AFFECTED: Compromised axios version found in npm dependency tree"
    echo "$AXIOS_TREE" | sed 's/^/    /'
    FOUND=1
  else
    echo "  OK: No compromised axios in npm dependency tree"
  fi
}

check_dep_tree_yarn() {
  if ! command -v yarn &> /dev/null; then return; fi
  if [ ! -f "yarn.lock" ]; then return; fi
  YARN_OUT=$(yarn why axios 2>/dev/null)
  COMPROMISED=$(echo "$YARN_OUT" | grep -E "1\.14\.1|0\.30\.4")
  if [ -n "$COMPROMISED" ]; then
    echo "  !! AFFECTED: Compromised axios version found in yarn dependency tree"
    echo "$YARN_OUT" | sed 's/^/    /'
    FOUND=1
  else
    echo "  OK: No compromised axios in yarn dependency tree"
  fi
}

check_dep_tree_pnpm() {
  if ! command -v pnpm &> /dev/null; then return; fi
  if [ ! -f "pnpm-lock.yaml" ]; then return; fi
  PNPM_OUT=$(pnpm list axios --depth=Infinity 2>/dev/null)
  COMPROMISED=$(echo "$PNPM_OUT" | grep -E "axios.*(1\.14\.1|0\.30\.4)")
  if [ -n "$COMPROMISED" ]; then
    echo "  !! AFFECTED: Compromised axios version found in pnpm dependency tree"
    echo "$PNPM_OUT" | sed 's/^/    /'
    FOUND=1
  else
    echo "  OK: No compromised axios in pnpm dependency tree"
  fi
}

check_dep_tree_bun() {
  if ! command -v bun &> /dev/null; then return; fi
  if [ ! -f "bun.lockb" ]; then return; fi
  BUN_OUT=$(bun pm ls --all 2>/dev/null)
  COMPROMISED=$(echo "$BUN_OUT" | grep -E "axios@.*(1\.14\.1|0\.30\.4)")
  if [ -n "$COMPROMISED" ]; then
    echo "  !! AFFECTED: Compromised axios version found in bun dependency tree"
    echo "$BUN_OUT" | grep -i axios | sed 's/^/    /'
    FOUND=1
  else
    echo "  OK: No compromised axios in bun dependency tree"
  fi
}

# Run the dep tree check for whichever package manager is available
if [ -f "yarn.lock" ]; then
  check_dep_tree_yarn
elif [ -f "pnpm-lock.yaml" ]; then
  check_dep_tree_pnpm
elif [ -f "bun.lockb" ]; then
  check_dep_tree_bun
else
  check_dep_tree_npm
fi

# --- Check 2: Parse lockfiles for axios specifically ---
echo ""
echo "[2/6] Checking lockfiles for axios-specific entries..."
LOCKFILE_FOUND=0
PKG_MANAGER="npm"  # default; overridden below if another lockfile is found

# Helper: check decoded yarn-style content for axios specifically
# Finds blocks whose header starts with "axios@" and checks the resolved version
check_axios_yarn_format() {
  awk '/^axios@/{p=1} p && /  version "(1\.14\.1|0\.30\.4)"/{print; p=0} /^[^ \t]/{p=0}' "$1"
}

if [ -f "package-lock.json" ]; then
  LOCKFILE_FOUND=1
  # Scope to the axios entry in node_modules, not any package with that version number
  LOCK_HIT=$(grep -A 5 '"node_modules/axios"' package-lock.json | grep -E '"(1\.14\.1|0\.30\.4)"' | head -3)
  if [ -n "$LOCK_HIT" ]; then
    echo "  !! AFFECTED: Compromised axios version found in package-lock.json"
    echo "  $LOCK_HIT"
    FOUND=1
  else
    echo "  OK: package-lock.json clean"
  fi
fi

if [ -f "yarn.lock" ]; then
  LOCKFILE_FOUND=1
  PKG_MANAGER="yarn"
  LOCK_HIT=$(check_axios_yarn_format yarn.lock)
  if [ -n "$LOCK_HIT" ]; then
    echo "  !! AFFECTED: Compromised axios version found in yarn.lock"
    echo "  $LOCK_HIT"
    FOUND=1
  else
    echo "  OK: yarn.lock clean"
  fi
fi

if [ -f "pnpm-lock.yaml" ]; then
  LOCKFILE_FOUND=1
  PKG_MANAGER="pnpm"
  # pnpm entries are keyed as "/axios@VERSION:" or "axios@VERSION:"
  LOCK_HIT=$(grep -E "(^|/)(axios)@(1\.14\.1|0\.30\.4):" pnpm-lock.yaml | head -3)
  if [ -n "$LOCK_HIT" ]; then
    echo "  !! AFFECTED: Compromised axios version found in pnpm-lock.yaml"
    echo "  $LOCK_HIT"
    FOUND=1
  else
    echo "  OK: pnpm-lock.yaml clean"
  fi
fi

if [ -f "deno.lock" ]; then
  LOCKFILE_FOUND=1
  PKG_MANAGER="deno"
  # deno.lock is JSON; npm entries are keyed as "axios@VERSION"
  LOCK_HIT=$(grep -E '"axios@(1\.14\.1|0\.30\.4)"' deno.lock | head -3)
  if [ -n "$LOCK_HIT" ]; then
    echo "  !! AFFECTED: Compromised axios version found in deno.lock"
    echo "  $LOCK_HIT"
    FOUND=1
  else
    echo "  OK: deno.lock clean"
  fi
fi

if [ -f "bun.lockb" ]; then
  LOCKFILE_FOUND=1
  PKG_MANAGER="bun"
  if command -v bun &> /dev/null; then
    # bun.lockb is binary — decode to yarn-style text first, then scope to axios blocks
    LOCK_HIT=$(bun bun.lockb 2>/dev/null | check_axios_yarn_format /dev/stdin)
    if [ -n "$LOCK_HIT" ]; then
      echo "  !! AFFECTED: Compromised axios version found in bun.lockb"
      echo "  $LOCK_HIT"
      FOUND=1
    else
      echo "  OK: No compromised axios in bun.lockb"
    fi
  else
    echo "  WARN: bun.lockb found but 'bun' not installed — cannot decode binary lockfile, skipping"
  fi
fi

if [ $LOCKFILE_FOUND -eq 0 ]; then
  echo "  SKIP: No lockfile found in current directory"
fi

# --- Check 3: Lockfile git history ---
echo ""
echo "[3/6] Checking lockfile git history (forensic source of truth)..."
if [ -d ".git" ]; then
  GIT_HIT=$(git log -p -- package-lock.json yarn.lock bun.lockb pnpm-lock.yaml deno.lock 2>/dev/null | grep -E "plain-crypto-js" | head -3)
  if [ -n "$GIT_HIT" ]; then
    echo "  !! WARNING: plain-crypto-js appeared in lockfile history"
    echo "  $GIT_HIT"
    echo "  (Your system MAY have been compromised even if node_modules is clean now)"
    FOUND=1
  else
    echo "  OK: No trace in git history"
  fi
else
  echo "  SKIP: Not a git repository"
fi

# --- Check 4: Malicious dependency in node_modules ---
echo ""
echo "[4/6] Checking for malicious package in node_modules..."
if [ -d "node_modules/plain-crypto-js" ]; then
  echo "  !! AFFECTED: node_modules/plain-crypto-js/ EXISTS"
  FOUND=1
else
  echo "  OK: plain-crypto-js not in node_modules"
  echo "  (Note: The malware self-destructs — absence does NOT guarantee safety)"
fi

# --- Check 5: RAT artifacts on disk ---
echo ""
echo "[5/6] Checking for RAT artifacts..."

# macOS
if [ "$(uname)" = "Darwin" ]; then
  if [ -f "/Library/Caches/com.apple.act.mond" ]; then
    echo "  !! CRITICAL: macOS RAT found at /Library/Caches/com.apple.act.mond"
    ls -la "/Library/Caches/com.apple.act.mond"
    FOUND=1
  else
    echo "  OK: macOS RAT artifact not found"
  fi
fi

# Linux
if [ -f "/tmp/ld.py" ]; then
  echo "  !! CRITICAL: Linux RAT found at /tmp/ld.py"
  ls -la "/tmp/ld.py"
  FOUND=1
else
  echo "  OK: Linux RAT artifact not found"
fi

# --- Check 6: Network connections to C2 ---
echo ""
echo "[6/6] Checking for C2 connections..."
C2_CHECK=$(netstat -an 2>/dev/null | grep "142.11.206.73" || ss -tn 2>/dev/null | grep "142.11.206.73")
if [ -n "$C2_CHECK" ]; then
  echo "  !! CRITICAL: Active connection to C2 server (142.11.206.73)"
  echo "  $C2_CHECK"
  FOUND=1
else
  echo "  OK: No active C2 connections detected"
fi

# DNS check
DNS_CHECK=$(grep -r "sfrclak.com" /var/log/ 2>/dev/null | head -3)
if [ -n "$DNS_CHECK" ]; then
  echo "  !! WARNING: DNS queries to sfrclak.com found in logs"
  FOUND=1
fi

# --- Summary ---
echo ""
echo "============================================"
if [ $FOUND -eq 1 ]; then
  echo "  !! POTENTIAL COMPROMISE DETECTED"
  echo ""
  echo "  Immediate actions:"
  echo "  1. Pin axios to 1.14.0 or 0.30.3"
  echo "  2. Remove node_modules and reinstall cleanly:"
  case "$PKG_MANAGER" in
    yarn) echo "       yarn install --frozen-lockfile" ;;
    pnpm) echo "       pnpm install --frozen-lockfile" ;;
    bun)  echo "       bun install --frozen-lockfile" ;;
    deno) echo "       deno install" ;;
    *)    echo "       rm -rf node_modules && npm ci" ;;
  esac
  echo "  3. Rotate ALL credentials (npm tokens, AWS, SSH, API keys)"
  echo "  4. Block sfrclak.com and 142.11.206.73 at firewall"
  echo "  5. If RAT artifacts found: FULL SYSTEM REBUILD"
  echo ""
  echo "  Ref: https://github.com/axios/axios/issues/10604"
else
  echo "  ALL CLEAR — No indicators of compromise found"
  echo ""
  echo "  Preventive steps:"
  echo "  - Pin axios to a safe version:"
  case "$PKG_MANAGER" in
    yarn) echo "       yarn add axios@1.14.0 --exact"
          echo "  - Use frozen installs in CI/CD: yarn install --frozen-lockfile"
          echo "  - Set ignore-scripts: true in .yarnrc.yml" ;;
    pnpm) echo "       pnpm add axios@1.14.0 --save-exact"
          echo "  - Use frozen installs in CI/CD: pnpm install --frozen-lockfile"
          echo "  - Set ignore-scripts=true in .npmrc" ;;
    bun)  echo "       bun add axios@1.14.0 --exact"
          echo "  - Use frozen installs in CI/CD: bun install --frozen-lockfile" ;;
    deno) echo "       deno add npm:axios@1.14.0" ;;
    *)    echo "       npm install axios@1.14.0 --save-exact"
          echo "  - Use frozen installs in CI/CD: npm ci"
          echo "  - Set ignore-scripts=true in .npmrc"
          echo "  - Run: npm config set min-release-age 3" ;;
  esac
fi
echo "============================================"
