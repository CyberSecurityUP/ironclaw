# IronClaw — Quickstart Guide

## Prerequisites

- **Rust 1.75+** (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **SQLite3** (included in most systems, bundled in build)
- **Docker** (optional, for container sandbox)
- **Ollama** (optional, for testing with local models without an API key)

---

## 1. Build

```bash
cd ironclaw
cargo build --release
export PATH="$PATH:$(pwd)/target/release"
```

## 2. Run Tests

```bash
cargo test
```

Expected: **432+ tests passing** (336 unit + 96 integration).

---

## 3. List Providers and Models

```bash
ironclaw models
```

Shows all 25 providers with default model, cost, and description.

To see only providers with API keys configured:
```bash
ironclaw models --available
```

### Quick Presets

Use presets instead of provider names:

| Preset | Provider | Model | Use Case |
|--------|----------|-------|----------|
| `fast` | Groq | llama-3.3-70b-versatile | Ultra-fast |
| `smart` | Anthropic | claude-sonnet-4-5-20250514 | Highest quality |
| `cheap` | DeepSeek | deepseek-chat | Lowest cost |
| `local` | Ollama | llama3.3 | No API key needed |
| `vision` | Google | gemini-2.5-flash | Multimodal |
| `code` | Anthropic | claude-sonnet-4-5-20250514 | Programming |

```bash
ironclaw run --provider fast
ironclaw run --provider local
ironclaw run --provider smart
```

---

## 4. Provider Setup

### 4.1 Ollama (Local, Free)

The easiest way to test. No API key required.

```bash
# Install Ollama (if not already installed)
curl -fsSL https://ollama.com/install.sh | sh

# Start the server
ollama serve

# Pull a model
ollama pull llama3.3

# Run IronClaw
ironclaw run --provider ollama --model llama3.3
```

**Verification:** Type "Hello" at the prompt and confirm you receive a response.

### 4.2 Anthropic (Claude)

```bash
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# Default model: claude-sonnet-4-5-20250514
ironclaw run --provider anthropic

# Or specify a model
ironclaw run --provider anthropic --model claude-haiku-4-5-20251001
```

### 4.3 OpenAI (GPT)

```bash
export OPENAI_API_KEY="sk-..."

# Default model: gpt-4.1
ironclaw run --provider openai

# Cheaper model
ironclaw run --provider openai --model gpt-4.1-mini

# Most capable
ironclaw run --provider openai --model gpt-4.1
```

### 4.4 Google (Gemini)

```bash
export GOOGLE_API_KEY="AIza..."

# Default model: gemini-2.5-flash
ironclaw run --provider google

# Most capable
ironclaw run --provider google --model gemini-2.5-pro
```

### 4.5 Groq (Ultra-Fast)

```bash
export GROQ_API_KEY="gsk_..."

# Default model: llama-3.3-70b-versatile
ironclaw run --provider groq

# Or via preset
ironclaw run --provider fast
```

### 4.6 DeepSeek (Lowest Cost)

```bash
export DEEPSEEK_API_KEY="sk-..."

ironclaw run --provider deepseek

# Or via preset
ironclaw run --provider cheap
```

### 4.7 Mistral

```bash
export MISTRAL_API_KEY="..."

ironclaw run --provider mistral
```

### 4.8 OpenRouter (Meta-Provider)

Access 100+ models from all providers with a single API key.

```bash
export OPENROUTER_API_KEY="sk-or-..."

# Default: claude-sonnet-4-5
ironclaw run --provider openrouter

# Use any available model
ironclaw run --provider openrouter --model google/gemini-2.5-pro
ironclaw run --provider openrouter --model openai/gpt-4.1
ironclaw run --provider openrouter --model meta-llama/llama-3.3-70b-instruct
```

### 4.9 LM Studio (Local GUI)

```bash
# 1. Open LM Studio
# 2. Download a model (e.g., Llama 3)
# 3. Start the API server (port 1234)

ironclaw run --provider lmstudio
```

### 4.10 xAI (Grok)

```bash
export XAI_API_KEY="..."

ironclaw run --provider xai --model grok-3
```

---

## 5. Web UI

IronClaw includes a web interface with real-time chat via WebSocket.

### Start with the interactive agent

```bash
# Add --ui to launch the web interface alongside the terminal
ironclaw run --provider ollama --model llama3.3 --ui
```

Open: **http://127.0.0.1:3000**

### Start as a dedicated server

```bash
# Dedicated UI subcommand
ironclaw ui --provider anthropic

# Custom port
ironclaw ui --provider ollama --port 8080
```

### Configure UI in the config file

```yaml
ui:
  enabled: true           # Auto-start UI with `ironclaw run`
  bind_address: "0.0.0.0" # Accept external connections (use with caution!)
  port: 3000
  theme: "dark"
```

### UI Features

- Real-time chat with WebSocket
- Dark theme by default
- Markdown rendering (code, bold, italic, links)
- Automatic reconnection (3s timeout)
- Status bar: provider, model, session ID
- "Secured by IronClaw" badge

---

## 6. Onboarding Wizard

The easiest way to configure IronClaw for the first time:

```bash
ironclaw onboard
```

The interactive wizard guides you through:

1. **Provider selection** — Choose from 8 cloud providers + 2 local, tests connection
2. **Channel setup** — Enable communication channels (WhatsApp, Telegram, Slack, Discord, etc.)
3. **Security level** — Choose a security preset (strict / moderate / permissive)
4. **Session auth** — Configure authentication based on active LLM session
5. **Web UI** — Enable the web interface with custom port
6. **Generate config** — Saves `ironclaw.yaml` with all selections

---

## 7. Communication Channels (20 channels)

IronClaw supports 20 communication channels, each with rate limiting, sender validation, input sanitization, and credential redaction on output.

### Supported Channels

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

### Configure channels in config

```yaml
channels:
  - channel_type: "slack"
    enabled: true
    credentials:
      bot_token: "xoxb-..."
      signing_secret: "..."

  - channel_type: "telegram"
    enabled: true
    credentials:
      bot_token: "123456:ABC..."
```

### Security pipeline for channels

All messages pass through a security pipeline:

**Inbound (receiving):**
- Rate limiting per channel
- Sender validation (blocks reserved names: system, admin, root)
- Input sanitization (removes null bytes, ANSI escapes, role injection tags)

**Outbound (sending):**
- Credential redaction (API keys, AWS keys, GitHub tokens, Slack tokens)
- PII redaction (emails, credit card numbers)
- Internal URL / SSRF detection

---

## 8. LLM Session Authentication

IronClaw uses the active LLM session as proof of identity. If a user has an LLM session responding, it proves they have valid credentials.

### How it works

1. User proves access to an LLM provider (valid API key + health check)
2. IronClaw issues a `SessionToken` — blob signed with HMAC-SHA256
3. Subsequent requests carry the token in the `X-IronClaw-Session` header
4. `SessionAuthenticator` verifies HMAC signature + expiry window

### Configuration

```yaml
session_auth:
  enabled: true
  ttl_secs: 3600           # Token valid for 1 hour
  secret: "my-hmac-secret" # Optional, generates random if omitted
```

---

## 9. Full Configuration Example

Create `ironclaw.yaml` in the project root:

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
    read: ["./src/**", "./docs/**", "./*.md", "./*.toml"]
    write: ["./output/**", "/tmp/ironclaw/**"]
    deny:
      - "/etc/shadow"
      - "/etc/passwd"
      - "/root/.ssh/**"
      - "**/.ssh/id_*"
      - "**/.env"
      - "**/.aws/credentials"
      - "**/.kube/config"
  network:
    allow_domains: ["api.anthropic.com", "api.openai.com", "api.groq.com"]
    block_domains: ["169.254.169.254", "metadata.google.internal"]
    block_private: true
    max_requests_per_hour: 100
  system:
    allow_shell: false
    require_approval: true
    max_concurrent: 4

guardian:
  block_pipes: true
  block_redirects: true
  block_subshells: true

sandbox:
  backend: "native"    # "docker", "bubblewrap", or "native"
  enforce: true

memory:
  backend: "sqlite"
  path: "~/.ironclaw/memory.db"
  encrypt_at_rest: true
  max_entries: 10000

antitheft:
  enforce: true

dlp:
  enabled: true
  scan_tool_outputs: true
  scan_llm_responses: true

audit:
  enabled: true
  path: "~/.ironclaw/audit.log"

observability:
  log_level: "info"
  structured_logs: true
  redact_pii: true

ui:
  enabled: false
  bind_address: "127.0.0.1"
  port: 3000
  theme: "dark"
```

---

## 10. Security Verification

```bash
# Full diagnostic (20 checks: sandbox, DLP, SSRF, channels, session auth)
ironclaw doctor

# View active security policy
ironclaw policy

# View audit logs
ironclaw audit --count 50

# Manage skills
ironclaw skill list
ironclaw skill verify ./skills/my-skill
ironclaw skill scan ./skills/my-skill/main.py
```

---

## 11. Troubleshooting

| Symptom | Cause | Solution |
|---------|-------|---------|
| `ANTHROPIC_API_KEY not set` | Missing env variable | `export ANTHROPIC_API_KEY="sk-ant-..."` |
| `Config file not found` | No ironclaw.yaml | Uses secure defaults, or create the file |
| `Path '/etc/shadow' is denied` | Deny list blocking | Expected! Security working correctly |
| Ollama: `connection refused` | Ollama server not running | `ollama serve` |
| Ollama: `model not found` | Model not downloaded | `ollama pull llama3.3` |
| `Session expired after 100 turns` | Reached max_turns | Increase `agent.max_turns` |
| `Tool rate limit exceeded` | Too many calls/hour | Increase rate_limit in config |
| UI won't open | UI disabled | Use `--ui` flag or set `ui.enabled: true` |
| UI won't connect | Wrong port | Check `ui.port` in config |
| `Session token expired` | Token TTL expired | Increase `session_auth.ttl_secs` |
| `Channel not connected` | Channel not started | Check credentials in config |
| `[REDACTED] in output` | DLP redacted credentials | Expected! Security pipeline working |

---

## 12. Running Tests by Module

```bash
cargo test guardian           # Command Guardian
cargo test rbac               # RBAC
cargo test dlp                # Data Loss Prevention
cargo test antitheft          # Anti-Stealer
cargo test ssrf               # SSRF Protection
cargo test memory             # Encrypted Memory
cargo test scanner            # Skill Scanner
cargo test providers          # Provider tests
cargo test channels           # Channel pipeline (20 channels)
cargo test auth               # Session Authentication
cargo test workflow           # Workflow Engine
cargo test agents             # Collaborative Agents
cargo test multimodal         # Multimodal support
cargo test channel_security   # Channel security integration
```

---

## 13. Next Steps

1. **Onboarding:** `ironclaw onboard` — interactive wizard configures everything
2. **Test locally:** `ollama serve` + `ironclaw run --provider local --ui`
3. **Test with API:** Set up a key and use `ironclaw run --provider smart`
4. **Explore presets:** `ironclaw run --provider fast` for Groq ultra-fast
5. **Web UI:** `ironclaw run --provider anthropic --ui` and open http://127.0.0.1:3000
6. **Security check:** `ironclaw doctor` (20 checks)
7. **List providers:** `ironclaw models --available`
