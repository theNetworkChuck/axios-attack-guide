#!/bin/bash
# ============================================================================
# Axios Supply Chain Attack — Detection Script (macOS/Linux)
# ============================================================================
# Checks if your system was affected by the axios@1.14.1 / axios@0.30.4
# supply chain attack that dropped a cross-platform RAT via plain-crypto-js.
#
# Source: StepSecurity, Socket.dev, GitHub Issue #10604
# ============================================================================

echo "============================================"
echo "  Axios Supply Chain Attack — Detection"
echo "============================================"
echo ""

FOUND=0

# --- Check 1: Installed axios version ---
echo "[1/6] Checking installed axios version..."
if command -v npm &> /dev/null; then
  AXIOS_VER=$(npm list axios 2>/dev/null | grep -oE "1\.14\.1|0\.30\.4")
  if [ -n "$AXIOS_VER" ]; then
    echo "  !! AFFECTED: axios@${AXIOS_VER} found in node_modules"
    FOUND=1
  else
    echo "  OK: No compromised axios version installed"
  fi
else
  echo "  SKIP: npm not found"
fi

# --- Check 2: Lockfile contains compromised version ---
echo ""
echo "[2/6] Checking lockfile for compromised versions..."
LOCKFILE_FOUND=0
for LOCKFILE in package-lock.json yarn.lock pnpm-lock.yaml deno.lock; do
  if [ -f "$LOCKFILE" ]; then
    LOCKFILE_FOUND=1
    LOCK_HIT=$(grep -E "1\.14\.1|0\.30\.4" "$LOCKFILE" | head -3)
    if [ -n "$LOCK_HIT" ]; then
      echo "  !! AFFECTED: Compromised version found in $LOCKFILE"
      echo "  $LOCK_HIT"
      FOUND=1
    else
      echo "  OK: $LOCKFILE clean"
    fi
  fi
done
if [ -f "bun.lockb" ]; then
  LOCKFILE_FOUND=1
  if command -v bun &> /dev/null; then
    LOCK_HIT=$(bun bun.lockb 2>/dev/null | grep -E "1\.14\.1|0\.30\.4" | head -3)
    if [ -n "$LOCK_HIT" ]; then
      echo "  !! AFFECTED: Compromised version found in bun.lockb"
      echo "  $LOCK_HIT"
      FOUND=1
    else
      echo "  OK: bun.lockb clean"
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
  echo "  2. rm -rf node_modules && npm ci"
  echo "  3. Rotate ALL credentials (npm tokens, AWS, SSH, API keys)"
  echo "  4. Block sfrclak.com and 142.11.206.73 at firewall"
  echo "  5. If RAT artifacts found: FULL SYSTEM REBUILD"
  echo ""
  echo "  Ref: https://github.com/axios/axios/issues/10604"
else
  echo "  ALL CLEAR — No indicators of compromise found"
  echo ""
  echo "  Preventive steps:"
  echo "  - Pin axios: npm install axios@1.14.0 --save-exact"
  echo "  - Use npm ci (not npm install) in CI/CD"
  echo "  - Set ignore-scripts=true in .npmrc"
  echo "  - Run: npm config set min-release-age 3"
fi
echo "============================================"
