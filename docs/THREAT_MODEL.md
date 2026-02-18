# IronClaw Threat Model (STRIDE)

## Overview

This document analyzes threats to IronClaw using the STRIDE framework:
- **S**poofing
- **T**ampering
- **R**epudiation
- **I**nformation Disclosure
- **D**enial of Service
- **E**levation of Privilege

## System Components

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│   User   │────>│  Agent   │────>│   LLM    │
│ (Human)  │     │  Engine  │     │ Provider │
└──────────┘     └────┬─────┘     └──────────┘
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐
    │  Tools   │ │  Memory  │ │  Skills  │
    │ (Sandbox)│ │ (Encrypt)│ │ (Signed) │
    └──────────┘ └──────────┘ └──────────┘
```

## Trust Boundaries

1. **User <-> Agent**: Semi-trusted (user may be manipulated by prompt injection)
2. **Agent <-> LLM Provider**: Untrusted network, trusted API
3. **Agent <-> Tools**: Untrusted (tools execute in sandbox)
4. **Agent <-> Memory**: Trusted but encrypted
5. **Agent <-> Skills**: Untrusted until signature verified
6. **Agent <-> Filesystem**: Untrusted (RBAC enforced)

---

## STRIDE Analysis

### S — Spoofing

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Impersonation of LLM provider | HIGH | TLS certificate validation via rustls | Implemented |
| Spoofed skill publisher | HIGH | Ed25519 signature verification | Implemented |
| Forged audit log entries | MEDIUM | Append-only log with 0600 permissions | Implemented |
| Spoofed user identity | LOW | Single-user CLI model | N/A |

### T — Tampering

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Modified skill content | CRITICAL | SHA-256 hash + Ed25519 signature | Implemented |
| Tampered memory entries | HIGH | AES-256-GCM authenticated encryption | Implemented |
| Modified configuration | MEDIUM | Config validation on load | Implemented |
| Altered tool outputs | MEDIUM | Sandbox isolation prevents host modification | Implemented |
| Poisoned LLM responses | HIGH | Response validation + output sanitization | Partial |

### R — Repudiation

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Deny executing a dangerous command | HIGH | Audit log with timestamps | Implemented |
| Deny approving an action | MEDIUM | Approval events logged | Implemented |
| Deny policy changes | MEDIUM | Config change audit | Planned |

### I — Information Disclosure

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| API key leakage in logs | CRITICAL | PII redaction + credential scrubbing | Implemented |
| Memory content exposure | HIGH | AES-256-GCM encryption at rest | Implemented |
| Sensitive file read | HIGH | RBAC filesystem deny list | Implemented |
| Environment variable leakage | HIGH | Sandbox env filtering | Implemented |
| Cloud metadata access (SSRF) | CRITICAL | Metadata endpoint blocking | Implemented |
| Cross-context memory access | MEDIUM | Context isolation | Implemented |

### D — Denial of Service

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Resource exhaustion (CPU/memory) | HIGH | Sandbox resource limits | Implemented |
| Output flooding | MEDIUM | Output truncation (1MB limit) | Implemented |
| Rate limit exhaustion | MEDIUM | Per-tool rate limiting | Implemented |
| Fork bomb in sandbox | HIGH | PID limits in Docker | Implemented |
| Disk filling via tool output | MEDIUM | Sandbox tmpfs with size limit | Implemented |

### E — Elevation of Privilege

| Threat | Risk | Mitigation | Status |
|--------|------|------------|--------|
| Shell command injection | CRITICAL | Command Guardian + sandbox isolation | Implemented |
| Container escape | HIGH | CAP_DROP ALL + no-new-privileges + seccomp | Implemented |
| Path traversal to sensitive files | HIGH | Canonicalization + deny list | Implemented |
| Privilege escalation via sudo | CRITICAL | sudo/su blocked by Guardian | Implemented |
| RBAC bypass | HIGH | Deny-first policy, deny rules take precedence | Implemented |
| Prompt injection to bypass controls | HIGH | Input sanitization + approval workflow | Partial |

---

## Attack Scenarios

### Scenario 1: Prompt Injection via Untrusted Content
**Attack**: LLM reads a file containing hidden instructions that attempt to bypass security.
**Mitigations**:
- Command Guardian validates all commands regardless of origin
- RBAC enforces permissions regardless of LLM intent
- High-risk operations require human approval
- Sandbox isolates execution environment

### Scenario 2: Supply Chain Attack via Malicious Skill
**Attack**: Attacker publishes a skill with a legitimate name but malicious code.
**Mitigations**:
- Ed25519 signature verification with trusted keys
- SHA-256 content hash prevents post-signature modification
- Path traversal detection prevents skill from accessing outside its directory

### Scenario 3: Data Exfiltration via Network
**Attack**: LLM attempts to send sensitive data to an external server.
**Mitigations**:
- Sandbox network policy (deny by default)
- Network domain allowlist
- Cloud metadata endpoint blocking
- Credential scrubbing in all outputs

### Scenario 4: Persistent Backdoor via Scheduled Task
**Attack**: LLM creates a cron job that maintains access.
**Mitigations**:
- Shell execution disabled by default
- Sandbox isolation prevents host cron access
- Audit logging captures all tool executions
- Rate limiting prevents rapid action sequences

---

## Residual Risks

1. **Zero-day in Docker/container runtime** — Mitigated by defense-in-depth layers
2. **Compromise of trusted Ed25519 key** — Requires key rotation procedure
3. **Sophisticated prompt injection** — ML-based detection planned for v0.6
4. **Side-channel attacks** — Not addressed at application level
5. **Physical access to host** — Out of scope

## Review Schedule

This threat model should be reviewed:
- After every major version release
- When new tools or providers are added
- After any security incident
- Quarterly at minimum
