# IronClaw

<p align="center">
  <strong>Secure-by-default AI Agent Framework with Zero Trust Architecture</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#architecture">Architecture</a> &bull;
  <a href="#security-layers">Security Layers</a> &bull;
  <a href="#providers">Providers</a> &bull;
  <a href="#channels">Channels</a> &bull;
  <a href="#differentials">Differentials</a> &bull;
  <a href="#contributing">Contributing</a>
</p>

---

IronClaw is a production-grade AI agent framework written in **Rust**, engineered from the ground up with **security as its primary concern**. Every tool execution is validated, sandboxed, and audited. No implicit trust — every action requires explicit permission.

**25+ LLM providers** | **20+ communication channels** | **13-step security pipeline** | **432+ tests** | **~25,000 lines of Rust**

---

## Quick Start

### Prerequisites

- **Rust 1.75+** — `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **SQLite3** (bundled in the build)
- **Docker** (optional, for container sandbox)
- **Ollama** (optional, for local models with no API key)

### Build & Run

```bash
# Clone and build
git clone https://github.com/CyberSecurityUP/ironclaw.git
cd ironclaw
cargo build --release

# Run the onboarding wizard (easiest way to get started)
./target/release/ironclaw onboard

# Or run directly with a provider
./target/release/ironclaw run --provider ollama --model llama3.3

# Run with the Web UI
./target/release/ironclaw run --provider anthropic --ui

# Check your security posture
./target/release/ironclaw doctor
```

### Provider Presets

Use preset aliases for quick selection:

| Preset | Provider | Model | Use Case |
|--------|----------|-------|----------|
| `fast` | Groq | llama-3.3-70b-versatile | Ultra-low latency |
| `smart` | Anthropic | claude-sonnet-4-5 | Highest quality |
| `cheap` | DeepSeek | deepseek-chat | Lowest cost |
| `local` | Ollama | llama3.3 | No API key needed |
| `vision` | Google | gemini-2.5-flash | Multimodal |
| `code` | Anthropic | claude-sonnet-4-5 | Code generation |

```bash
ironclaw run --provider fast    # Groq ultra-fast
ironclaw run --provider local   # Ollama local
ironclaw run --provider smart   # Claude best quality
```

### Provider Setup Examples

```bash
# Ollama (free, local)
ollama serve && ollama pull llama3.3
ironclaw run --provider ollama

# Anthropic (Claude)
export ANTHROPIC_API_KEY="sk-ant-api03-..."
ironclaw run --provider anthropic

# OpenAI (GPT)
export OPENAI_API_KEY="sk-..."
ironclaw run --provider openai

# Google (Gemini)
export GOOGLE_API_KEY="AIza..."
ironclaw run --provider google

# OpenRouter (100+ models, single API key)
export OPENROUTER_API_KEY="sk-or-..."
ironclaw run --provider openrouter --model google/gemini-2.5-pro
```

See [QUICKSTART.md](QUICKSTART.md) for detailed setup instructions for all 25 providers.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     CLI / Web UI / Channels                   │
├──────────────────────────────────────────────────────────────┤
│                        Core Engine                            │
│  ┌────────────┬────────────┬────────────┬──────────────────┐ │
│  │  Provider   │    Tool    │   Memory   │     Workflow     │ │
│  │  Router     │  Registry  │   Store    │     Engine       │ │
│  ├────────────┼────────────┼────────────┼──────────────────┤ │
│  │  Skill      │   Cost     │  Context   │   Agent          │ │
│  │  Verifier   │  Tracker   │  Chunking  │  Orchestrator    │ │
│  └────────────┴────────────┴────────────┴──────────────────┘ │
├──────────────────────────────────────────────────────────────┤
│                    Security Pipeline (13 steps)               │
│  ┌──────────┬──────────┬──────────┬──────────┬───────────┐  │
│  │ Command  │   RBAC   │ Sandbox  │  Audit   │   DLP     │  │
│  │ Guardian │  Policy  │ Enforcer │   Log    │  Engine   │  │
│  ├──────────┼──────────┼──────────┼──────────┼───────────┤  │
│  │  Anti-   │   SSRF   │  Skill   │Community │ Session   │  │
│  │ Stealer  │  Guard   │ Scanner  │ Scanner  │   Auth    │  │
│  └──────────┴──────────┴──────────┴──────────┴───────────┘  │
├──────────────────────────────────────────────────────────────┤
│         Sandbox (Docker / Bubblewrap / Native)                │
│  ┌──────────────────────────────────────────────────────┐    │
│  │ Multi-Level Profiles: Minimal → Standard → Elevated  │    │
│  └──────────────────────────────────────────────────────┘    │
├──────────────────────────────────────────────────────────────┤
│      Communication Channels (20+) & Gateway (JWT/OAuth2)      │
└──────────────────────────────────────────────────────────────┘
```

### Core Modules

| Module | Description | Lines |
|--------|-------------|-------|
| `core/` | Engine, config, types, tools, cost tracker, chunking, cache, history, scheduler, multimodal | ~4,500 |
| `providers/` | 25 LLM provider integrations + presets + catalog | ~1,850 |
| `channels/` | 20 communication channels with security pipeline | ~1,475 |
| `security/` | Credential scanning, network/system policy | ~2,530 |
| `gateway/` | API gateway with JWT, OAuth2, session auth, rate limiting | ~1,150 |
| `workflow/` | DAG-based workflow engine with 10 action types | ~1,230 |
| `agents/` | Multi-agent orchestration with 5 coordination patterns | ~1,010 |
| `observability/` | Structured logging, audit trail, SIEM export, metrics | ~1,190 |
| `memory/` | Encrypted stores (SQLite, file, Redis, Postgres) | ~1,060 |
| `skills/` | Skill loader, registry, scanner (27 rules), community scanner | ~1,750 |
| `sandbox/` | Docker, Bubblewrap, Native backends + multi-level profiles | ~980 |
| `guardian/` | Command validation with 45+ blocked patterns | ~650 |
| `dlp/` | Data Loss Prevention with 22+ detection rules | ~520 |
| `antitheft/` | Anti-stealer credential harvesting detection | ~470 |
| `network/` | SSRF protection + URL validation | ~450 |
| `auth/` | LLM session authentication (HMAC-SHA256 tokens) | ~300 |
| `cli/` | Doctor (20 checks), onboard wizard, policy, audit, skills | ~1,200 |
| `ui/` | Web UI (Axum + WebSocket + embedded assets) | ~550 |

---

## Security Layers

IronClaw follows **Zero Trust** principles with **13 overlapping security layers**:

### 1. Command Guardian
Every shell command is validated against **45+ blocklist patterns** and heuristic rules. Blocks reverse shells, privilege escalation, data exfiltration, credential access, and injection attacks.

### 2. Role-Based Access Control (RBAC)
Full role-based permission model for filesystem, network, and system access. **Deny rules always take precedence**. Rate limiting per role.

### 3. Sandbox Isolation
All tool execution runs in isolated environments (Docker rootless, Bubblewrap, or Native) with seccomp profiles, no host access by default, and explicit network policies.

### 4. Multi-Level Sandbox Profiles
Per-skill isolation levels — **Minimal, Standard, Elevated, Unrestricted, Custom** — with fine-grained control over filesystem access, network access, resource limits, and environment variables.

### 5. Skill Signature Verification
All skills must be cryptographically signed (**Ed25519**) with SHA-256 content hashing. Only skills signed by trusted keys can execute.

### 6. Skill Static Analyzer
Scans skill/plugin source code for **27 dangerous patterns** (eval, exec, crypto mining, exfiltration, env harvesting, obfuscated code, privilege escalation, persistence mechanisms) with CWE mapping.

### 7. Community Skill Security Scanner
**Typosquatting detection** via Levenshtein distance against known packages (npm, PyPI, crates.io), **reputation database**, **dependency analysis**, and **quarantine** for untrusted packages.

### 8. Memory Protection
All memory encrypted at rest (**AES-256-GCM**), segregated by context, sanitized against injection attacks. Multiple backends: SQLite, file, Redis, Postgres.

### 9. Anti-Stealer Detection
Dedicated module detecting credential harvesting, sensitive file access (SSH keys, cloud creds, crypto wallets, browser profiles, keychains), multi-step exfiltration correlation, and stealer-like command patterns.

### 10. SSRF Protection
Blocks private/reserved IP ranges (RFC 1918, CGNAT, link-local), cloud metadata endpoints (AWS/GCP/Azure), DNS rebinding, IP obfuscation (decimal, hex, octal), and dangerous URL schemes.

### 11. Data Loss Prevention (DLP)
Scans all tool outputs for sensitive data (private keys, AWS/GCP/Azure credentials, database URIs, JWT tokens, API keys, /etc/shadow) with configurable actions: **block, redact, warn**.

### 12. Observability & Audit
Structured JSON logging with automatic **PII redaction**, security audit trail, and **SIEM export** capability. OpenTelemetry integration for metrics and tracing.

### 13. LLM Session Authentication
Active LLM session as proof of identity — **HMAC-SHA256** signed tokens with configurable TTL, provider health-check validation, rate-limited session creation.

---

## Providers

IronClaw supports **25+ LLM providers** out of the box:

| Provider | Models | API Key Env Var |
|----------|--------|-----------------|
| Anthropic | Claude 4.5 Sonnet, Haiku | `ANTHROPIC_API_KEY` |
| OpenAI | GPT-4.1, GPT-4.1-mini, o3, o4-mini | `OPENAI_API_KEY` |
| Google | Gemini 2.5 Flash, Pro | `GOOGLE_API_KEY` |
| Groq | Llama 3.3, Mixtral | `GROQ_API_KEY` |
| DeepSeek | DeepSeek Chat, Coder | `DEEPSEEK_API_KEY` |
| Mistral | Mistral Large, Small | `MISTRAL_API_KEY` |
| Cohere | Command R+ | `COHERE_API_KEY` |
| xAI | Grok-3 | `XAI_API_KEY` |
| Together | Llama, Mixtral, Code Llama | `TOGETHER_API_KEY` |
| Fireworks | Llama, Mixtral | `FIREWORKS_API_KEY` |
| Perplexity | pplx-7b, pplx-70b | `PERPLEXITY_API_KEY` |
| Replicate | Llama, Stable Diffusion | `REPLICATE_API_TOKEN` |
| AI21 | Jamba 1.5 | `AI21_API_KEY` |
| OpenRouter | 100+ models | `OPENROUTER_API_KEY` |
| Ollama | Any local model | (local, no key) |
| LM Studio | Any local model | (local, no key) |
| Cerebras | Llama 3.3 | `CEREBRAS_API_KEY` |
| SambaNova | Llama, Mixtral | `SAMBANOVA_API_KEY` |
| AWS Bedrock | Claude, Llama | AWS credentials |
| Google Vertex AI | Gemini, PaLM | GCP credentials |
| Azure OpenAI | GPT-4, GPT-3.5 | `AZURE_OPENAI_API_KEY` |
| Cloudflare Workers AI | Llama, Mistral | `CF_API_TOKEN` |
| Lepton | Llama | `LEPTON_API_KEY` |
| Hugging Face | Various | `HF_API_TOKEN` |
| Jan | Local models | (local, no key) |

```bash
# List all providers and models
ironclaw models

# Show only providers with available API keys
ironclaw models --available
```

---

## Channels

IronClaw supports **20 communication channels**, each with rate limiting, sender validation, input sanitization, and credential redaction:

| Channel | Type | Rate Limit |
|---------|------|------------|
| CLI | Interactive terminal | 120/burst, 10/s |
| Slack | Events API + Web API | 50/burst, 1/s |
| Discord | Gateway WebSocket + REST | 50/burst, 2/s |
| Telegram | Bot API (long-poll/webhook) | 30/burst, 1/s |
| WhatsApp | Business API | 20/burst, 0.5/s |
| Matrix | Client-server API (/sync) | 60/burst, 2/s |
| IRC | Persistent TCP | 30/burst, 1/s |
| Teams | Bot Framework | 40/burst, 1.5/s |
| Google Chat | Workspace API | 40/burst, 1.5/s |
| Signal | Signal CLI / REST bridge | 20/burst, 0.5/s |
| iMessage | AppleScript (macOS) | 20/burst, 0.5/s |
| BlueBubbles | iMessage bridge | 20/burst, 0.5/s |
| Zalo | Official Account API | 30/burst, 1/s |
| Zalo Personal | Personal API | 20/burst, 0.5/s |
| Web UI | HTTP + WebSocket | 100/burst, 5/s |
| REST API | JSON POST /v1/messages | 200/burst, 20/s |
| WebSocket | Bidirectional streaming | 100/burst, 10/s |
| gRPC | Unary + streaming RPCs | 200/burst, 20/s |
| Email | SMTP (out) + IMAP (in) | 10/burst, 0.2/s |
| LINE | Messaging API | 30/burst, 1/s |

### Channel Security Pipeline

All messages pass through a security pipeline:

**Inbound:** Rate limiting → Sender validation → Input sanitization (null bytes, ANSI escapes, role injection)

**Outbound:** Credential redaction (API keys, AWS keys, tokens) → PII redaction (emails, card numbers) → Internal URL / SSRF detection

---

## Workflow Engine

DAG-based automation engine with **10 action types**:

- **LlmCall** — Send prompts to any provider
- **ToolExec** — Execute registered tools
- **ChannelSend** — Send messages to any channel
- **WaitForEvent** — Pause until an external trigger
- **Transform** — Map/filter data with templates
- **Branch** — Conditional branching with 8 operators
- **SubWorkflow** — Nest workflows
- **HttpRequest** — External API calls
- **Delay** — Time-based delays
- **Log** — Structured logging

Features: `{{variable}}` template resolution, cycle detection via topological sort, conditional execution, retry policies with exponential backoff, 6 trigger types (manual, scheduled, webhook, channel_message, event, on_completion).

---

## Collaborative Agents

Multi-agent orchestration with **6 built-in roles** and **5 coordination patterns**:

### Roles
| Role | Capabilities |
|------|-------------|
| Researcher | Web search, file read, analysis |
| Coder | Code generation, file write, tool execution |
| Reviewer | Code review, analysis |
| Planner | Planning, task decomposition |
| Tester | Test execution, analysis |
| Security Auditor | Security scanning, analysis |

### Coordination Patterns
- **Sequential** — Agents execute one after another, passing results forward
- **Parallel** — All agents work simultaneously, results aggregated
- **Debate** — Agents propose, critique, and refine answers
- **Hierarchical** — Lead agent delegates tasks to sub-agents
- **Pipeline** — Each agent transforms and passes data to the next

---

## Native Multimodal Support

Process images, audio, video, and files natively:

- **Images**: JPEG, PNG, GIF, WebP (max 10 MB)
- **Audio**: MP3, WAV, OGG, FLAC, M4A (max 25 MB)
- **Video**: MP4, WebM, MOV (max 100 MB)
- **Files**: PDF, TXT, CSV, JSON, XML

Automatic MIME detection, base64 encoding, format conversion for Anthropic/OpenAI APIs.

---

## Differentials vs. Related Projects

IronClaw was inspired by and extends concepts from [ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) and [OpenClaw](https://github.com/openclaw/openclaw), but is a ground-up rewrite focused on defense-in-depth security.

| Feature | ZeroClaw | OpenClaw | **IronClaw** |
|---------|----------|----------|-------------|
| **Language** | Rust | TypeScript | **Rust** |
| **Security Layers** | 3 (RBAC, Guardian, Sandbox) | 4 (Sandbox, SSRF, Gateway, Scanner) | **13 overlapping layers** |
| **LLM Providers** | 8 | 12 | **25+** |
| **Communication Channels** | 5 (CLI, Slack, Discord, Telegram, Web) | 8 | **20** |
| **RBAC** | Flat autonomy levels | None | **Full role-based model with deny precedence** |
| **Sandbox** | Optional Docker/Bubblewrap | Docker only | **Mandatory, multi-backend + multi-level profiles** |
| **Memory Encryption** | Secrets only | None | **All memory (AES-256-GCM)** |
| **Skill Verification** | None | None | **Ed25519 cryptographic signatures** |
| **Command Validation** | Pattern-based (~20 patterns) | Sandbox-level only | **Guardian + sandbox (45+ patterns)** |
| **Audit Logging** | Basic file log | Basic | **Structured JSON + SIEM export + PII redaction** |
| **Anti-Stealer** | None | None | **Dedicated detection module** |
| **SSRF Protection** | None | Gateway-level | **Full IP/DNS/scheme/metadata validation** |
| **DLP** | None | None | **22+ rules, output scanning + redaction** |
| **Skill Scanning** | None | Heuristic (basic) | **27-rule static analysis + community scanner** |
| **Typosquatting Detection** | None | None | **Levenshtein distance vs. known packages** |
| **Workflow Engine** | None | None | **DAG-based with 10 action types** |
| **Multi-Agent** | None | None | **5 coordination patterns, 6 built-in roles** |
| **Multimodal** | Text only | Text + images | **Images, audio, video, files** |
| **Cost Tracking** | None | Basic | **SQLite-backed with daily/monthly budgets** |
| **Session Auth** | None | None | **HMAC-SHA256 LLM session tokens** |
| **Web UI** | None | React app | **Embedded Axum + WebSocket (no separate build)** |
| **Onboarding** | Manual config | Manual config | **Interactive TUI wizard** |
| **Test Coverage** | ~80 tests | ~150 tests | **432+ tests (336 unit + 96 integration)** |
| **Prompt Injection Defense** | None | None | **Input sanitization layer** |

### Key Architectural Differences

1. **Defense in Depth**: IronClaw chains 13 security layers in a pipeline — even if one layer is bypassed, others catch the threat. ZeroClaw and OpenClaw use isolated security checks that don't overlap.

2. **Rust Performance**: IronClaw compiles to a single static binary with `lto = true` and `panic = abort` — no runtime, no garbage collector, no dependency on Node.js or Python.

3. **Mandatory Sandboxing**: In IronClaw, sandboxing is enforced by default. ZeroClaw makes it optional; OpenClaw requires Docker but allows host network access.

4. **Credential Security**: IronClaw's Anti-Stealer module actively monitors for credential harvesting patterns (SSH key enumeration, cloud credential access, multi-step exfiltration chains). Neither ZeroClaw nor OpenClaw has an equivalent.

5. **Community Trust**: IronClaw's Community Scanner checks skills against typosquatting databases, reputation scores, and dependency graphs before allowing installation. Neither predecessor does this.

---

## Configuration

IronClaw uses YAML configuration (`ironclaw.yaml`):

```yaml
agent:
  system_prompt: "You are a secure AI assistant powered by IronClaw."
  default_provider: "anthropic"
  default_model: "claude-sonnet-4-5-20250514"
  max_turns: 100
  tool_timeout_secs: 30
  max_daily_cost_cents: 500  # $5.00/day

permissions:
  filesystem:
    read: ["./src/**", "./docs/**"]
    write: ["./output/**"]
    deny: ["/etc/shadow", "**/.ssh/id_*", "**/.env"]
  network:
    allow_domains: ["api.anthropic.com", "api.openai.com"]
    block_domains: ["169.254.169.254"]
    block_private: true
  system:
    allow_shell: false
    require_approval: true

sandbox:
  backend: "docker"     # "docker", "bubblewrap", or "native"
  enforce: true

memory:
  backend: "sqlite"
  encrypt_at_rest: true

antitheft:
  enforce: true

dlp:
  enabled: true

ui:
  enabled: false
  port: 3000
  theme: "dark"
```

See `config/ironclaw.yaml` for a complete example.

---

## CLI Commands

```bash
ironclaw run       # Start interactive agent
ironclaw run --ui  # Start with Web UI
ironclaw ui        # Start Web UI server only
ironclaw models    # List all providers and models
ironclaw doctor    # Run 20 security diagnostic checks
ironclaw policy    # Show active security policy
ironclaw audit     # View audit log
ironclaw onboard   # Interactive setup wizard
ironclaw skill list      # List installed skills
ironclaw skill verify    # Verify skill signatures
ironclaw skill scan      # Static analysis on skill source
ironclaw skill install   # Install from trusted registry
```

---

## Project Structure

```
ironclaw/
├── src/
│   ├── main.rs              # CLI entry point (clap)
│   ├── core/                # Engine, config, types, tools, cost, cache, history, multimodal
│   ├── providers/           # 25 LLM provider integrations
│   ├── channels/            # 20 communication channels + security pipeline
│   ├── gateway/             # API gateway (JWT, OAuth2, session auth, rate limiting)
│   ├── workflow/            # DAG-based workflow engine
│   ├── agents/              # Multi-agent orchestration
│   ├── sandbox/             # Docker, Bubblewrap, Native backends + profiles
│   ├── guardian/            # Command validation (45+ patterns)
│   ├── rbac/                # Role-based access control
│   ├── memory/              # Encrypted memory stores
│   ├── security/            # Credential scanning, network/system policy
│   ├── antitheft/           # Anti-stealer detection
│   ├── network/             # SSRF protection
│   ├── dlp/                 # Data Loss Prevention
│   ├── skills/              # Skill loader, scanner, community scanner
│   ├── plugins/             # Plugin system (lifecycle, sandbox, permissions)
│   ├── auth/                # LLM session authentication
│   ├── observability/       # Logging, audit trail, SIEM, metrics
│   ├── cli/                 # Doctor, onboard, policy, audit, skills, models
│   ├── ui/                  # Web UI (Axum + WebSocket)
│   └── tunnel/              # Encrypted tunnel pool
├── config/                  # Example configuration
├── docs/                    # Threat model, security audit
├── tests/                   # Integration & security tests (1,700+ lines)
├── ui/static/               # Web UI static assets
├── Cargo.toml
├── QUICKSTART.md
├── SECURITY.md
├── CONTRIBUTING.md
└── CODE_OF_CONDUCT.md
```

---

## Testing

```bash
# Run all tests (432+)
cargo test

# Run by module
cargo test guardian           # Command Guardian
cargo test rbac               # RBAC
cargo test dlp                # Data Loss Prevention
cargo test antitheft          # Anti-Stealer
cargo test ssrf               # SSRF Protection
cargo test memory             # Encrypted Memory
cargo test scanner            # Skill Scanner
cargo test providers          # Provider tests
cargo test channels           # Channel pipeline
cargo test auth               # Session Authentication
cargo test workflow           # Workflow Engine
cargo test agents             # Collaborative Agents
cargo test multimodal         # Multimodal support
cargo test channel_security   # Channel security integration
```

---

## Roadmap

- [x] **v0.1** — Core framework with 10 security layers, 25 providers
- [x] **v0.2** — 20 channels, workflow engine, collaborative agents, multimodal
- [ ] **v0.3** — Skill marketplace with trusted registry
- [ ] **v0.4** — WASM sandbox backend
- [ ] **v0.5** — Prompt injection ML detection layer
- [ ] **v0.6** — Hardware security module (HSM) integration
- [ ] **v1.0** — Production-ready with SOC 2 compliance documentation

---

## Credits & Inspiration

IronClaw draws architectural insights from two open-source projects:

- **[ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw)** — A fast, minimal AI assistant in Rust with tool support, multi-channel integration, and policy-based security. Informed IronClaw's command validation, provider abstraction, and memory management design.

- **[OpenClaw](https://github.com/openclaw/openclaw)** — A feature-rich AI agent platform in TypeScript with Docker sandboxing, SSRF protection, and gateway authentication. Influenced IronClaw's sandbox architecture and network security guards.

IronClaw is an independent project that restructures and extends concepts from both with a focus on **defense-in-depth security**, **formal RBAC**, and **cryptographic verification**.

---

## Legal Notice

IronClaw is an independent open-source project. It is inspired by and builds upon concepts from ZeroClaw (Apache-2.0) and OpenClaw (MIT), but contains original code with a restructured architecture focused on security. All original source projects are credited above.

This software is provided "as-is" without warranty. The security measures implemented reduce risk but cannot guarantee absolute protection. Users are responsible for their own security posture and compliance requirements.

## License

Apache-2.0

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. See [SECURITY.md](SECURITY.md) for vulnerability reporting.
