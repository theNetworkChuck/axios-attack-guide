# Axios npm Supply Chain Attack — Detection & Protection Guide

On March 31, 2026, the npm package **axios** (100M+ weekly downloads) was compromised in a sophisticated supply chain attack. A hacker took over the lead maintainer's account, injected a phantom dependency that deploys a cross-platform RAT in 1.1 seconds, and the malware self-destructs to erase all evidence.

This repo has everything you need to check if you're affected and protect yourself.

Watch the full breakdown: [NetworkChuck Video](https://youtube.com/networkchuck)

---

## Am I Affected?

**Bad versions:** `axios@1.14.1` and `axios@0.30.4`

**Safe versions:** `axios@1.14.0` and `axios@0.30.3`

### Quick Check

```bash
npm list axios
npm list -g axios
```

### Run the Full Detection Script

**Mac/Linux:**
```bash
curl -sL https://raw.githubusercontent.com/thenetworkchuck/axios-attack-guide/main/check.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/thenetworkchuck/axios-attack-guide/main/check.ps1 | iex
```

Or clone and run locally:
```bash
git clone https://github.com/thenetworkchuck/axios-attack-guide.git
cd axios-attack-guide
./check.sh        # Mac/Linux
.\check.ps1       # Windows PowerShell
```

The scripts check all 6 indicators: axios version, lockfile, git history, malicious dependency, RAT artifacts, and C2 connections.

### Scan Multiple Projects (Recursive)

The default scripts only check the directory you run them from. The recursive variant walks a directory tree, checks every JS project it finds, and runs system-global checks (RAT artifacts, C2 connections) once at the end.

> **Note:** `check-revursive.sh` scans the **current working directory** by default. Pass a path to scan somewhere else.

**Mac/Linux — scan current directory:**
```bash
curl -sL https://raw.githubusercontent.com/thenetworkchuck/axios-attack-guide/main/check-revursive.sh | bash
```

**Mac/Linux — scan a specific directory:**
```bash
curl -sL https://raw.githubusercontent.com/thenetworkchuck/axios-attack-guide/main/check-revursive.sh | bash -s /path/to/projects
```

Or clone and run locally:
```bash
git clone https://github.com/thenetworkchuck/axios-attack-guide.git
cd axios-attack-guide
chmod +x check-revursive.sh
./check-revursive.sh              # scans current directory
./check-revursive.sh /srv/apps    # scans a specific directory
```

---

## Manual Detection Commands

### Step 1 — Scan Your Entire System for Axios

**Mac/Linux:**
```bash
find / -path "*/node_modules/axios/package.json" 2>/dev/null | while read f; do
  version=$(grep '"version"' "$f" | head -1)
  echo "$f -> $version"
done
```

**Windows (PowerShell):**
```powershell
Get-ChildItem -Path C:\ -Recurse -Filter "package.json" -ErrorAction SilentlyContinue |
  Where-Object { $_.DirectoryName -like "*node_modules\axios" } |
  ForEach-Object {
    $version = (Get-Content $_.FullName | Select-String '"version"').Line
    Write-Output "$($_.FullName) -> $version"
  }
```

If any result shows version **1.14.1** or **0.30.4**, you are affected.

### Step 2 — Check Your Lockfile History

```bash
git log -p -- package-lock.json | grep "plain-crypto-js"
```

If `plain-crypto-js` shows up anywhere in your lockfile history, investigate immediately. Legitimate axios has exactly **3 dependencies**: `follow-redirects`, `form-data`, `proxy-from-env`. Anything else is a red flag.

### Step 3 — Check for RAT Artifacts

The malware drops platform-specific payloads disguised as system files:

**macOS:**
```bash
ls -la /Library/Caches/com.apple.act.mond 2>/dev/null
```

**Linux:**
```bash
ls -la /tmp/ld.py 2>/dev/null
```

**Windows (PowerShell):**
```powershell
Test-Path "$env:PROGRAMDATA\wt.exe"
```

### Step 4 — Check for C2 Communication

```bash
netstat -an | grep "142.11.206.73"
```

---

## If You're Compromised

If you found ANY indicators above, treat your machine as **fully compromised**:

1. **STOP** — do not just delete files
2. **Rotate ALL credentials** — npm tokens, SSH keys, API keys, cloud credentials
3. **Rotate all database passwords**
4. **Check CI/CD pipelines** for affected installs
5. **Block C2 traffic** — `sfrclak.com` and `142.11.206.73` at your firewall
6. **Rebuild from a clean image** if possible
7. **Audit git history** for unauthorized changes

---

## Protect Yourself Going Forward

### 1. Refuse newly published packages
```bash
npm config set min-release-age 3
```
This tells npm to refuse any package published less than 3 days ago. **This one command would have blocked this attack.**

### 2. Disable postinstall scripts
Add to your `.npmrc`:
```
ignore-scripts=true
```
The entire attack depended on a postinstall script running automatically. No scripts = no attack.

### 3. Pin exact versions
Add to your `.npmrc`:
```
save-exact=true
```
The `^` in your version ranges is what let npm auto-upgrade to the compromised version.

### 4. Use npm ci in CI/CD
```bash
npm ci  # NOT npm install
```
Installs exactly what's in your lockfile. No surprises.

### 5. Consider pnpm or bun
Both package managers do **NOT** run lifecycle scripts by default. This attack would have completely failed on pnpm or bun.

---

## What Happened — The Full Attack Chain

| Step | What Happened |
|------|--------------|
| 1 | Attacker obtained lead maintainer's (`jasonsaayman`) long-lived npm classic access token |
| 2 | Account email changed to `ifstap@proton.me` |
| 3 | One line added to package.json: `"plain-crypto-js": "^4.2.1"` — never imported anywhere |
| 4 | Clean decoy version published 18 hours before the malicious one |
| 5 | Published via npm CLI, bypassing GitHub Actions OIDC Trusted Publishing |
| 6 | Both `axios@1.14.1` and `axios@0.30.4` poisoned within 39 minutes |
| 7 | Postinstall dropper auto-executes — XOR + base64 obfuscation (key: `OrDeR_7077`) |
| 8 | Platform-specific RAT downloaded from C2 in 1.1 seconds |
| 9 | Malware self-destructs — deletes dropper, replaces package.json with clean decoy |

---

## IOCs (Indicators of Compromise)

| Type | Value |
|------|-------|
| C2 Domain | `sfrclak.com` |
| C2 IP | `142.11.206.73` |
| C2 Port | `8000` |
| C2 Path | `/6202033` |
| XOR Key | `OrDeR_7077` |
| axios@1.14.1 SHA-1 | `2553649f2322049666871cea80a5d0d6adc700ca` |
| axios@0.30.4 SHA-1 | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| plain-crypto-js@4.2.1 SHA-1 | `07d889e2dadce6f3910dcbc253317d28ca61c766` |
| Attacker emails | `ifstap@proton.me`, `nrwise@proton.me` |

**RAT File Paths:**
| OS | Path | Disguised As |
|----|------|-------------|
| macOS | `/Library/Caches/com.apple.act.mond` | Apple system cache |
| Windows | `%PROGRAMDATA%\wt.exe` | Windows Terminal |
| Linux | `/tmp/ld.py` | Generic temp file |

---

## Resources

- [Socket.dev Analysis](https://socket.dev/blog/axios-npm-package-compromised) — First automated detection (6 minutes)
- [StepSecurity Deep Dive](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan) — Runtime telemetry
- [GitHub Issue #10604](https://github.com/axios/axios/issues/10604) — Maintainer confirms compromise
- [Huntress Blog](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package) — 100+ confirmed compromised hosts
- [John Hammond Video](https://youtu.be/A58cV17avpM)
- [John Hammond Livestream](https://www.youtube.com/watch?v=A-KpP-6Dt8E)

---

Made with coffee by [NetworkChuck](https://youtube.com/networkchuck)
