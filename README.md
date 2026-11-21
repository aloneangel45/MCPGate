<div align="center">
  <img src="assets/banner.png" alt="MCPGate — Zero-Trust Local Firewall, Sandbox & DLP Proxy for MCP Servers" width="100%" />

  <h1>MCPGate</h1>
  <p><strong>Zero-Trust Local Firewall, OS Sandbox &amp; Live DLP Proxy for Model Context Protocol (MCP) Servers</strong></p>

  <p>
    <a href="https://github.com/aloneangel45/MCPGate/actions/workflows/ci.yml"><img src="https://github.com/aloneangel45/MCPGate/actions/workflows/ci.yml/badge.svg" alt="CI Status" /></a>
    <a href="https://github.com/aloneangel45/MCPGate/releases/latest"><img src="https://img.shields.io/github/v/release/aloneangel45/MCPGate?color=00d4ff" alt="Latest Release" /></a>
    <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.24%2B%20(CGO__ENABLED%3D0)-00ADD8?logo=go" alt="Pure Go 1.24+" /></a>
    <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-Stdio%20%2B%20Egress%20Firewall-ff8c00" alt="MCP Stdio + Egress Firewall" /></a>
    <a href="#owasp-mcp-top-10-coverage"><img src="https://img.shields.io/badge/OWASP-MCP%20Top%2010-7c3aed" alt="OWASP MCP Top 10" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License" /></a>
  </p>
</div>

---

## Why MCPGate?

Every time your AI coding IDE launches an MCP server with raw `npx -y ...` or `uvx ...`, that child process inherits your **entire host environment** (`AWS_*`, `GITHUB_TOKEN`, `OPENAI_API_KEY`), unrestricted **filesystem read/write access** (`~/.ssh`, `~/.aws`, `.env`), and **unrestricted outbound networking** (including cloud metadata `169.254.169.254` and arbitrary exfiltration webhooks).

Static scanners can flag misconfigurations after the fact, but they cannot stop a **live tool-poisoning injection**, a **mid-session rug-pull schema mutation**, or an **outbound HTTP POST leaking your `.env` secrets**.

**MCPGate** wraps any local stdio MCP server as a **single zero-dependency static binary (`CGO_ENABLED=0`)**—enforcing live MCP JSON-RPC security, SHA-256 tool schema lockfiles, real-time secret/PII DLP, DNS-pinned SSRF & egress firewalling, and OS-native process sandboxing with sub-millisecond overhead.

| Capability | Raw `npx` / `uvx` | Static Scanners | **MCPGate** |
| :--- | :---: | :---: | :---: |
| **Live Tool Poisoning & Prompt-Injection Quarantine** | None | Offline only | **Real-time JSON-RPC inspection** |
| **SHA-256 Tool Schema Lockfile (Rug-Pull Defense)** | None | Snapshot only | **Live per-session + `mcpgate.lock` enforce** |
| **Live Secret & `.env` Fingerprint DLP** | None | Static regex only | **Blocks / redacts in args & HTTP egress** |
| **DNS-Pinned SSRF & Egress Domain Firewall** | Unrestricted | None | **Local HTTP/CONNECT proxy + IMDS/RFC1918 block** |
| **Sensitive Path & Traversal Confinement (`~/.ssh`, `.env`)** | Unrestricted | Config args only | **Argument + symlink + OS sandbox enforcement** |
| **OS Process & Environment Isolation (`--clean-env`)** | Full host env | None | **Linux Landlock / macOS Seatbelt / Win32 Job** |
| **Runaway Agent Circuit Breaker** | None | None | **Rate, consecutive-error & identical-call caps** |
| **IDE Config Audit (`SARIF 2.1.0` + Dark HTML Report)** | None | Partial | **All 6 major IDEs (`--all-ides`)** |
| **Zero-Touch IDE Auto-Wrapper (`preset --write`)** | Manual | None | **Atomic, idempotent wrap & unwrap** |
| **Read-Only Self-MCP Server (`mcpgate mcp`)** | None | None | **Built-in stdio MCP tools for agents** |

---

## Zero-Trust 4-Tool AI Infrastructure Stack

**MCPGate** is designed to compose seamlessly with **ToolPrune**, **TracePort**, and **AgentFixture**—giving AI engineering teams end-to-end runtime security, token compaction, flight-recorder observability, and \$0 deterministic offline CI replay:

```text
  +-----------------------------------------------------------------------------+
  |             AI IDE / Agent Host (Claude, Cursor, VS Code, Windsurf, Zed)    |
  +--------------------------------------+--------------------------------------+
                                         | MCP JSON-RPC (stdio)
                                         v
  +-----------------------------------------------------------------------------+
  |  1. MCPGate  (Zero-Trust Sandbox + Egress DLP Firewall)                     |
  |     - Tool poisoning quarantine & SHA-256 rug-pull lockfile (mcpgate.lock)  |
  |     - Live DLP secret / .env scanner + sensitive path confinement           |
  |     - DNS-pinned SSRF / IMDS blocker + allowlisted HTTP(S) egress proxy     |
  |     - Clean-env OS sandbox (Landlock / Seatbelt / Win32 Job Objects)        |
  +--------------------------------------+--------------------------------------+
                                         | Clean, Authorized MCP Frames
                                         v
  +-----------------------------------------------------------------------------+
  |  2. ToolPrune  (Schema & Output Token Compaction)                           |
  |     - Compresses verbose tool schemas & noisy JSON responses (40-80% saved) |
  |     - Shares unified JSONL SecurityEvent telemetry with MCPGate             |
  +--------------------------------------+--------------------------------------+
                                         | Compacted Live Traffic
                                         v
  +-----------------------------------------------------------------------------+
  |  3. TracePort  (Flight Recorder & Time-Travel Debugger)                     |
  |     - Captures deterministic timelines of tool calls, latency & diffs       |
  |     - Replays incidents step-by-step across agent runs                      |
  +--------------------------------------+--------------------------------------+
                                         | Exported Golden Cassettes
                                         v
  +-----------------------------------------------------------------------------+
  |  4. AgentFixture  ($0 Offline CI Replay & Regression Harness)               |
  |     - Replays recorded MCP/LLM sessions in CI with zero API spend           |
  |     - Verifies policy, schema lockfiles & agent behavior on every PR        |
  +-----------------------------------------------------------------------------+
```

---

## Installation

### Linux & macOS (SHA-256 Verified, Pure POSIX `sh`)
```sh
curl -fsSL https://raw.githubusercontent.com/aloneangel45/MCPGate/main/install.sh | sh
```

### Windows PowerShell (Pure `.NET`, Zero Cmdlets, SHA-256 Verified)
```powershell
irm https://raw.githubusercontent.com/aloneangel45/MCPGate/main/install.ps1 | iex
```

### From Source (`Go 1.24+`, Pure Go `CGO_ENABLED=0`)
```bash
CGO_ENABLED=0 go install github.com/aloneangel45/mcpgate/cmd/mcpgate@latest
```

### Docker (Multi-Stage Distroless Non-Root)
```bash
docker build -t mcpgate .
docker run --rm -v "$PWD:/work:ro" mcpgate audit /work/mcp.json
```

---

## Quickstart

### 1. Wrap Any MCP Server with Zero-Trust Protection (`mcpgate run`)
```bash
# Run with a built-in zero-trust preset (balanced | strict | readonly | airgapped)
mcpgate run --preset strict -- npx -y @modelcontextprotocol/server-filesystem@2025.3.28 .

# Run with an explicit mcpgate.yaml policy, lockfile enforcement, and JSONL audit log
mcpgate run --policy examples/mcpgate.strict.yaml -- npx -y @modelcontextprotocol/server-github@2025.3.28
```

### 2. Audit All Local IDE MCP Configs (`mcpgate audit`)
Scan Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, and Zed for OWASP MCP Top 10 risks (unpinned `npx`/`uvx` packages, plaintext secrets, unencrypted HTTP endpoints, broad filesystem roots, shell indirection, and weakened policies):

```bash
# Console table across every installed IDE on your machine
mcpgate audit --all-ides

# Export a self-contained dark-mode interactive HTML security report (zero external CDNs)
mcpgate audit --all-ides --format html --out mcpgate-audit.html

# Export OASIS SARIF 2.1.0 for GitHub Code Scanning / CI gates (fail on high or critical)
mcpgate audit --all-ides --format sarif --out mcpgate-audit.sarif --fail-on high
```

### 3. Pin & Verify Tool Schemas Against Rug-Pull Attacks (`mcpgate lock`)
```bash
# Probe a live MCP server and pin canonical SHA-256 hashes into mcpgate.lock
mcpgate lock init --server filesystem -- npx -y @modelcontextprotocol/server-filesystem@2025.3.28 .

# Verify the server's live tool definitions match mcpgate.lock (fails non-zero on drift)
mcpgate lock verify --server filesystem -- npx -y @modelcontextprotocol/server-filesystem@2025.3.28 .
```

### 4. Dry-Run Policy Decisions (`mcpgate test-policy`)
Test tools, filesystem paths, outbound URLs/SSRF targets, and DLP payloads against your policy before deploying:

```bash
# Validate policy decisions interactively or in CI
mcpgate test-policy --policy examples/mcpgate.strict.yaml \
  --tool write_file \
  --path ~/.ssh/id_rsa \
  --url http://169.254.169.254/latest/meta-data/ \
  --payload "AKIAIOSFODNN7EXAMPLE"
```

### 5. Inspect Security Event Logs (`mcpgate inspect`)
Analyze JSONL security events emitted by live `mcpgate run` sessions (compatible with ToolPrune security event logs) and render an interactive dark-mode dashboard or SARIF report:

```bash
# Terminal summary of blocked targets, rules, and severity breakdown
mcpgate inspect .mcpgate/security-events.jsonl

# Generate a self-contained interactive HTML incident report & SARIF export
mcpgate inspect .mcpgate/security-events.jsonl --html mcpgate-events.html --sarif mcpgate-events.sarif
```

### 6. One-Command IDE Integration (`mcpgate preset`)
Atomically wrap (or unwrap) existing stdio MCP servers in Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, or Zed while preserving all unrelated JSON/JSONC settings and comments:

```bash
# Preview changes (dry-run by default)
mcpgate preset claude --preset balanced

# Atomically wrap all eligible stdio MCP servers in Claude Desktop config
mcpgate preset claude --preset strict --write

# Revert back to original unwrapped commands at any time
mcpgate preset claude --unwrap --write
```

### 7. Diagnose Host Sandbox & IDE Readiness (`mcpgate doctor`)
```bash
# Probe OS sandbox capabilities (Landlock / Seatbelt / Win32 Job Objects) & discover IDE configs
mcpgate doctor
```

### 8. Run MCPGate's Built-In Read-Only MCP Server (`mcpgate mcp`)
Expose MCPGate's policy evaluator, DLP scanner, static config auditor, and host capability diagnostics directly to AI agents over stdio:

```bash
mcpgate mcp
```

---

## OWASP MCP Top 10 Coverage

MCPGate combines **pre-execution static auditing (`mcpgate audit`)** with **live runtime enforcement (`mcpgate run`)** across `OWASP-MCP01` through `OWASP-MCP08`:

| OWASP ID | Threat Vector | Static Audit (`mcpgate audit`) | Live Runtime Guard (`mcpgate run`) |
| :--- | :--- | :--- | :--- |
| **MCP01** | **Supply-Chain & Tool Poisoning** | Flags unpinned `npx`/`uvx`/`docker` packages (`OWASP-MCP01`) | Live prompt-injection, Unicode spoofing, exfil & shell-smuggling quarantine (`MCP01-TOOL-POISONING`) |
| **MCP02** | **Plaintext Secrets & Rug-Pull Drift** | Flags hardcoded tokens, keys & headers in IDE configs (`OWASP-MCP02`) | Canonical SHA-256 `mcpgate.lock` verification & mid-session schema mutation blocking |
| **MCP03** | **Secret Exfiltration & Insecure Transport** | Flags non-loopback `http://` MCP endpoints (`OWASP-MCP03`) | Live DLP scanner (AWS, GitHub, OpenAI, Anthropic, Stripe, PEM, JWT, `.env` fingerprints + URL/Base64 decode) |
| **MCP04** | **Unwrapped High-Risk Servers & SSRF** | Flags unwrapped shell/DB/FS/cloud MCP servers (`OWASP-MCP04`) | DNS-pinned egress firewall blocking `169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal` & RFC1918 IPs |
| **MCP05** | **Broad Filesystem Roots & Path Traversal** | Flags `/`, `~`, `C:\`, broad container mounts (`OWASP-MCP05`) | Path traversal & symlink confinement + built-in blocks for `~/.ssh`, `~/.aws`, `~/.gnupg`, `.env`, keychains |
| **MCP06** | **Shell Indirection & Egress Abuse** | Flags `sh -c`, `bash -c`, `cmd /c`, `powershell -enc` (`OWASP-MCP06`) | Egress domain allowlist/denylist, port allowlist & airgapped mode (`network.enabled: false`) |
| **MCP07** | **Weak Policy & Unauthorized Tool Execution** | Audits `mcpgate.yaml` for disabled DLP, SSRF, lockfile, or clean-env (`OWASP-MCP07`) | Deny > Prompt > Allow glob precedence (`default_tool_action: deny`) & human approval gates |
| **MCP08** | **Runaway Agent Loops & Resource Exhaustion** | — | Circuit breaker (`max_calls_per_minute`, `max_consecutive_errors`, `max_identical_calls`) + OS memory/process/timeout limits |

---

## Policy Configuration (`mcpgate.yaml`)

MCPGate ships with four built-in presets (`balanced`, `strict`, `readonly`, `airgapped`) and supports full declarative customization via `mcpgate/v1` YAML. See ready-to-use templates in [`examples/mcpgate.strict.yaml`](examples/mcpgate.strict.yaml) and [`examples/mcpgate.balanced.yaml`](examples/mcpgate.balanced.yaml).

```yaml
version: mcpgate/v1
name: production-strict
preset: strict                     # Seeds defaults: balanced | strict | readonly | airgapped

filesystem:
  allow_paths: ["."]               # Confine all tool path arguments (symlink-safe)
  deny_paths: ["~/.ssh", "~/.aws", "**/.env*"]
  read_only: false
  block_sensitive_defaults: true   # Always guard SSH/AWS/GPG/kube/keychain/.env paths

network:
  enabled: true                    # Set false for fully airgapped mode
  allow_domains: ["api.github.com", "registry.npmjs.org"]
  deny_domains: ["*.ngrok.io", "webhook.site"]
  allow_ports: [443]
  block_private_ips: true          # Blocks RFC1918, loopback, link-local, CGNAT, ULA
  block_cloud_metadata: true       # Blocks 169.254.169.254, fd00:ec2::254, metadata.google.internal
  inspect_tls: false               # Optional ephemeral local CA MITM inspection

dlp:
  enabled: true
  action: block                    # block | redact | warn
  load_dotenv: true                # Fingerprint local .env values (never stores raw secrets)
  dotenv_paths: [".env", ".env.local"]
  custom_patterns:
    - id: "MCP03-CUSTOM-CORP"
      name: "Corporate Token"
      pattern: '\bCORP_[A-Z0-9]{24,}\b'
      severity: critical

mcp:
  default_tool_action: deny        # allow | deny | prompt
  allow_tools: ["read_*", "list_*", "get_*", "search_*"]
  deny_tools: ["*exec*", "*shell*", "*delete_all*"]
  prompt_tools: ["write_*", "edit_*"]
  block_poisoning: true            # Detect prompt injection, Unicode spoofing & stealth directives
  quarantine_poisoned: true        # Strip poisoned tools from tools/list & block invocation
  lockfile_path: "mcpgate.lock"
  lock_mode: enforce               # off | warn | enforce | update
  max_calls_per_minute: 60
  max_consecutive_errors: 6
  max_identical_calls: 5

sandbox:
  clean_env: true                  # Strip host secrets (AWS_*, GITHUB_TOKEN, OPENAI_API_KEY, ...)
  pass_env: ["PATH", "HOME", "USER", "USERPROFILE", "TEMP", "TMP", "SYSTEMROOT", "COMSPEC"]
  work_dir: "."
  max_memory_mb: 512
  max_processes: 32
  use_landlock: true               # Linux Landlock LSM (best-effort on supported kernels)
  use_seatbelt: true               # macOS Seatbelt sandbox-exec profile
  timeout_seconds: 300

audit:
  log_path: ".mcpgate/security-events.jsonl"
  log_allowed: false
```

---

## OS Sandbox & Supported IDEs

| Platform | Process & Tree Containment | Environment Scrubbing | Filesystem / Resource Enforcement |
| :--- | :--- | :--- | :--- |
| **Linux** (`amd64` / `arm64`) | Process group (`Setpgid`) + `Pdeathsig` | `--clean-env` allowlist | Landlock LSM + `RLIMIT_AS` / `RLIMIT_NPROC` + path policy |
| **macOS** (`amd64` / `arm64`) | Process group (`Setpgid`) | `--clean-env` allowlist | Seatbelt (`sandbox-exec`) profile + `RLIMIT` + path policy |
| **Windows** (`amd64` / `arm64`) | Win32 Job Objects (`KILL_ON_JOB_CLOSE`) | `--clean-env` (case-insensitive) | Job memory/process caps + symlink-resolved path policy |

**Supported IDE Config Targets (`mcpgate audit --all-ides` & `mcpgate preset`):**
`claude` (Claude Desktop) · `claude-code` (Claude Code) · `cursor` (Cursor) · `vscode` (VS Code) · `windsurf` (Windsurf) · `zed` (Zed)

---

## Contributing & Security

- See [CONTRIBUTING.md](CONTRIBUTING.md) for pure-Go build/test guidelines (`CGO_ENABLED=0`, `go vet ./...`, `go test -race -count=1 ./...`).
- See [SECURITY.md](SECURITY.md) to report vulnerabilities responsibly.
- Released under the [MIT License](LICENSE).
