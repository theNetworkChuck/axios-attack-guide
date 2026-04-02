#!/bin/bash
# ============================================================================
# Axios Supply Chain Attack — Recursive Detection Script (macOS/Linux)
# ============================================================================
# Checks if your system was affected by the axios@1.14.1 / axios@0.30.4
# supply chain attack that dropped a cross-platform RAT via plain-crypto-js.
#
# Walks a directory tree (default: $HOME) finding all JS projects and
# checking each one, then runs system-global checks once at the end.
#
# Usage:
#   ./check-recursive.sh              # scans $HOME
#   ./check-recursive.sh /srv/apps    # scans a specific root
#
# Source: StepSecurity, Socket.dev, GitHub Issue #10604
# ============================================================================

SCAN_ROOT="${1:-$(pwd)}"
FOUND=0
AFFECTED_PROJECTS=()

# ============================================================================
# Helpers
# ============================================================================

check_axios_yarn_format() {
  awk '/^axios@/{p=1} p && /  version "(1\.14\.1|0\.30\.4)"/{print; p=0} /^[^ \t]/{p=0}' "$1"
}

section() { echo ""; echo "--- $* ---"; }
hit()     { echo "  !! $*"; FOUND=1; }
ok()      { echo "  OK: $*"; }
skip()    { echo "  SKIP: $*"; }
warn()    { echo "  WARN: $*"; }

# ============================================================================
# Per-project checks (called once per discovered project root)
# ============================================================================

check_project() {
  local dir="$1"
  local project_found=0

  # --- Dependency tree check ---
  local pkg_manager="npm"
  if [ -f "$dir/yarn.lock" ]; then pkg_manager="yarn"
  elif [ -f "$dir/pnpm-lock.yaml" ]; then pkg_manager="pnpm"
  elif [ -f "$dir/bun.lockb" ]; then pkg_manager="bun"
  elif [ -f "$dir/deno.lock" ]; then pkg_manager="deno"
  fi

  case "$pkg_manager" in
    yarn)
      if command -v yarn &> /dev/null; then
        local tree_hit
        tree_hit=$(cd "$dir" && yarn why axios 2>/dev/null | grep -E "1\.14\.1|0\.30\.4")
        if [ -n "$tree_hit" ]; then
          hit "Compromised axios in yarn dependency tree: $tree_hit"
          project_found=1
        fi
      fi
      ;;
    pnpm)
      if command -v pnpm &> /dev/null; then
        local tree_hit
        tree_hit=$(cd "$dir" && pnpm list axios --depth=Infinity 2>/dev/null | grep -E "axios.*(1\.14\.1|0\.30\.4)")
        if [ -n "$tree_hit" ]; then
          hit "Compromised axios in pnpm dependency tree: $tree_hit"
          project_found=1
        fi
      fi
      ;;
    bun)
      if command -v bun &> /dev/null; then
        local tree_hit
        tree_hit=$(cd "$dir" && bun pm ls --all 2>/dev/null | grep -E "axios@.*(1\.14\.1|0\.30\.4)")
        if [ -n "$tree_hit" ]; then
          hit "Compromised axios in bun dependency tree: $tree_hit"
          project_found=1
        fi
      fi
      ;;
    *)
      if command -v npm &> /dev/null; then
        local tree_hit
        tree_hit=$(cd "$dir" && npm list axios --all 2>/dev/null | grep -E "axios@1\.14\.1|axios@0\.30\.4")
        if [ -n "$tree_hit" ]; then
          hit "Compromised axios in npm dependency tree: $tree_hit"
          project_found=1
        fi
      fi
      ;;
  esac

  # --- Lockfile checks ---
  local lockfile_found=0

  if [ -f "$dir/package-lock.json" ]; then
    lockfile_found=1
    local lock_hit
    lock_hit=$(grep -A 5 '"node_modules/axios"' "$dir/package-lock.json" | grep -E '"(1\.14\.1|0\.30\.4)"' | head -3)
    if [ -n "$lock_hit" ]; then
      hit "package-lock.json contains compromised axios: $lock_hit"
      project_found=1
    fi
  fi

  if [ -f "$dir/yarn.lock" ]; then
    lockfile_found=1
    local lock_hit
    lock_hit=$(check_axios_yarn_format "$dir/yarn.lock")
    if [ -n "$lock_hit" ]; then
      hit "yarn.lock contains compromised axios: $lock_hit"
      project_found=1
    fi
  fi

  if [ -f "$dir/pnpm-lock.yaml" ]; then
    lockfile_found=1
    local lock_hit
    lock_hit=$(grep -E "(^|/)(axios)@(1\.14\.1|0\.30\.4):" "$dir/pnpm-lock.yaml" | head -3)
    if [ -n "$lock_hit" ]; then
      hit "pnpm-lock.yaml contains compromised axios: $lock_hit"
      project_found=1
    fi
  fi

  if [ -f "$dir/deno.lock" ]; then
    lockfile_found=1
    local lock_hit
    lock_hit=$(grep -E '"axios@(1\.14\.1|0\.30\.4)"' "$dir/deno.lock" | head -3)
    if [ -n "$lock_hit" ]; then
      hit "deno.lock contains compromised axios: $lock_hit"
      project_found=1
    fi
  fi

  if [ -f "$dir/bun.lockb" ]; then
    lockfile_found=1
    if command -v bun &> /dev/null; then
      local lock_hit
      lock_hit=$(bun "$dir/bun.lockb" 2>/dev/null | check_axios_yarn_format /dev/stdin)
      if [ -n "$lock_hit" ]; then
        hit "bun.lockb contains compromised axios: $lock_hit"
        project_found=1
      fi
    else
      warn "bun.lockb found but 'bun' not installed — skipping binary lockfile"
    fi
  fi

  # --- node_modules check ---
  if [ -d "$dir/node_modules/plain-crypto-js" ]; then
    hit "node_modules/plain-crypto-js EXISTS"
    project_found=1
  fi

  # --- Git history check ---
  if [ -d "$dir/.git" ]; then
    local git_hit
    git_hit=$(git -C "$dir" log -p -- package-lock.json yarn.lock bun.lockb pnpm-lock.yaml deno.lock 2>/dev/null | grep -E "plain-crypto-js" | head -3)
    if [ -n "$git_hit" ]; then
      hit "plain-crypto-js found in git history (system may have been compromised even if node_modules is clean)"
      project_found=1
    fi
  fi

  if [ $project_found -eq 1 ]; then
    AFFECTED_PROJECTS+=("$dir")
    FOUND=1

    echo ""
    echo "  Remediation for this project:"
    echo "  1. Pin axios to a safe version:"
    case "$pkg_manager" in
      yarn) echo "       yarn add axios@1.14.0 --exact" ;;
      pnpm) echo "       pnpm add axios@1.14.0 --save-exact" ;;
      bun)  echo "       bun add axios@1.14.0 --exact" ;;
      deno) echo "       deno add npm:axios@1.14.0" ;;
      *)    echo "       npm install axios@1.14.0 --save-exact" ;;
    esac
    echo "  2. Remove node_modules and reinstall:"
    case "$pkg_manager" in
      yarn) echo "       rm -rf node_modules && yarn install --frozen-lockfile" ;;
      pnpm) echo "       rm -rf node_modules && pnpm install --frozen-lockfile" ;;
      bun)  echo "       rm -rf node_modules && bun install --frozen-lockfile" ;;
      deno) echo "       deno install" ;;
      *)    echo "       rm -rf node_modules && npm ci" ;;
    esac
  fi
}

# ============================================================================
# System-global checks (run once, not per-project)
# ============================================================================

check_system() {
  section "System-Global Checks"

  # RAT artifacts
  echo ""
  echo "[SYS-1] RAT artifacts..."
  if [ "$(uname)" = "Darwin" ]; then
    if [ -f "/Library/Caches/com.apple.act.mond" ]; then
      hit "macOS RAT found at /Library/Caches/com.apple.act.mond"
      ls -la "/Library/Caches/com.apple.act.mond"
    else
      ok "macOS RAT artifact not found"
    fi
  fi
  if [ -f "/tmp/ld.py" ]; then
    hit "Linux RAT found at /tmp/ld.py"
    ls -la "/tmp/ld.py"
  else
    ok "Linux RAT artifact not found"
  fi

  # C2 connections
  echo ""
  echo "[SYS-2] Active C2 connections..."
  local c2_check
  c2_check=$(netstat -an 2>/dev/null | grep "142.11.206.73" || ss -tn 2>/dev/null | grep "142.11.206.73")
  if [ -n "$c2_check" ]; then
    hit "Active connection to C2 server (142.11.206.73): $c2_check"
  else
    ok "No active C2 connections detected"
  fi

  # DNS log check
  echo ""
  echo "[SYS-3] DNS logs for C2 domain..."
  local dns_check
  dns_check=$(grep -r "sfrclak.com" /var/log/ 2>/dev/null | head -3)
  if [ -n "$dns_check" ]; then
    hit "DNS queries to sfrclak.com found in logs"
    echo "  $dns_check"
  else
    ok "No sfrclak.com DNS entries in /var/log"
  fi
}

# ============================================================================
# Main
# ============================================================================

echo "============================================"
echo "  Axios Supply Chain Attack — Detection"
echo "  Recursive Mode: $SCAN_ROOT"
echo "============================================"

# System-global checks first
check_system

# Walk the tree — find every directory containing a package.json,
# skipping node_modules and .git internals to avoid false positives
# and redundant scanning.
section "Project Scan"
echo "Searching for JS projects under $SCAN_ROOT ..."
echo "(This may take a moment.)"
echo ""

TMPFILE=$(mktemp)
find "$SCAN_ROOT" \
  -name "package.json" \
  -not -path "*/node_modules/*" \
  -not -path "*/.git/*" \
  -not -path "*/.bun/*" \
  -not -path "*/.yarn/*" \
  -not -path "*/.pnpm/*" \
  -not -path "*/.pnpm-store/*" \
  -not -path "*/.npm/*" \
  -not -path "*/.cache/*" \
  -not -path "*/Cache/*" \
  -not -path "*/Caches/*" \
  2>/dev/null \
  > "$TMPFILE" &
FIND_PID=$!

SPINNER='|/-\'
i=0
while kill -0 "$FIND_PID" 2>/dev/null; do
  i=$(( (i + 1) % 4 ))
  printf "\r  Scanning... %s" "$(echo "$SPINNER" | cut -c$((i+1)))"
  sleep 0.2
done
wait "$FIND_PID"
printf "\r%-40s\n" ""  # clear the spinner line

PROJECT_DIRS=()
while IFS= read -r pjson; do
  dir=$(dirname "$pjson")
  # Deduplicate without associative arrays (bash 3.2 compat)
  case " ${PROJECT_DIRS[*]} " in
    *" $dir "*) continue ;;
  esac
  PROJECT_DIRS+=("$dir")
done < "$TMPFILE"
rm -f "$TMPFILE"

if [ ${#PROJECT_DIRS[@]} -eq 0 ]; then
  echo "No JS projects found under $SCAN_ROOT"
else
  echo "Found ${#PROJECT_DIRS[@]} project(s). Checking each..."
  for dir in "${PROJECT_DIRS[@]}"; do
    echo ""
    echo ">> $dir"
    check_project "$dir"
    # Print OK only if no hits were found for this project
    if ! printf '%s\n' "${AFFECTED_PROJECTS[@]}" | grep -qx "$dir"; then
      ok "Clean"
    fi
  done
fi

# ============================================================================
# Summary
# ============================================================================

echo ""
echo "============================================"
if [ $FOUND -eq 1 ]; then
  echo "  !! POTENTIAL COMPROMISE DETECTED"
  echo ""
  if [ ${#AFFECTED_PROJECTS[@]} -gt 0 ]; then
    echo "  Affected projects:"
    for p in "${AFFECTED_PROJECTS[@]}"; do
      echo "    - $p"
    done
    echo ""
  fi
  echo "  System-wide actions:"
  echo "  1. Rotate ALL credentials (npm tokens, AWS, SSH, API keys)"
  echo "  2. Block sfrclak.com and 142.11.206.73 at firewall"
  echo "  3. If RAT artifacts found: FULL SYSTEM REBUILD"
  echo ""
  echo "  Ref: https://github.com/axios/axios/issues/10604"
else
  echo "  ALL CLEAR — No indicators of compromise found"
  echo "  Scanned ${#PROJECT_DIRS[@]} project(s) under $SCAN_ROOT"
fi
echo "============================================"
