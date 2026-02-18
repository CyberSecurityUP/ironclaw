# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in IronClaw, please report it responsibly:

1. **Do NOT open a public GitHub issue** for security vulnerabilities.
2. Email security findings to: `security@ironclaw-project.org`
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Security Architecture

### Defense-in-Depth Layers

```
Layer 1: Input Validation (Command Guardian)
  ├── Blocklist pattern matching
  ├── Heuristic risk classification
  ├── Subshell/pipe/redirect blocking
  └── Null byte and encoding attack prevention

Layer 2: Access Control (RBAC)
  ├── Role-based tool permissions
  ├── Filesystem path policies (allow/deny)
  ├── Network domain policies
  ├── Per-tool rate limiting
  └── Deny-first policy enforcement

Layer 3: Execution Isolation (Sandbox)
  ├── Docker rootless containers
  ├── Read-only root filesystem
  ├── Dropped capabilities (CAP_DROP ALL)
  ├── No-new-privileges flag
  ├── Seccomp system call filtering
  ├── Resource limits (CPU, memory, time)
  └── Network isolation (deny by default)

Layer 4: Data Protection
  ├── AES-256-GCM encrypted memory
  ├── Context-segregated storage
  ├── Input sanitization (null bytes, control chars)
  ├── Credential scrubbing in outputs
  └── PII redaction in logs

Layer 5: Verification
  ├── Ed25519 skill signatures
  ├── SHA-256 content hashing
  ├── Trusted key registry
  └── Path traversal prevention

Layer 6: Observability
  ├── Structured audit logging
  ├── Security event classification
  ├── SIEM export capability
  └── Tamper-resistant log storage (0600 permissions)
```

### Threat Model

See [THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full STRIDE analysis.

### Known Limitations

1. **Native sandbox** provides reduced isolation compared to Docker. Use Docker in production.
2. **Memory encryption key** is currently derived from local data. HSM integration is planned.
3. **Prompt injection detection** uses heuristic patterns, not ML. False negatives are possible.
4. **WASM sandbox** is planned but not yet implemented.

### Security Configuration Checklist

For production deployments:

- [ ] Use Docker sandbox backend (`sandbox.backend: "docker"`)
- [ ] Enable sandbox enforcement (`sandbox.enforce: true`)
- [ ] Set network policy to deny (`sandbox.network_policy: "deny"`)
- [ ] Disable shell execution (`permissions.system.allow_shell: false`)
- [ ] Enable memory encryption (`memory.encrypt_at_rest: true`)
- [ ] Require skill signatures (`skills.require_signatures: true`)
- [ ] Enable audit logging (`audit.enabled: true`)
- [ ] Enable PII redaction (`observability.redact_pii: true`)
- [ ] Block cloud metadata endpoints (default)
- [ ] Configure filesystem deny list (default includes sensitive paths)
- [ ] Set rate limits on all tools
- [ ] Enable human approval for high-risk operations
