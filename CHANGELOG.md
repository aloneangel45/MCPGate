# Changelog

All notable changes to **MCPGate** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-11-21

### Security & Hardening
- **MCP JSON-RPC 2.0 Batch Inspection (`pkg/mcpproxy`)**:
  - Closed a critical bypass where JSON-RPC 2.0 batch arrays (`[...]`) passed through `processClientMessage` and `processServerMessage` uninspected; batches are now recursively enforced across circuit breaker, tool quarantine, tool policy, path guard, DLP, poisoning quarantine, and schema lockfiles, including mixed allow/block client batches.
- **Protocol, Path & Tool-Poisoning Hardening (`pkg/mcpproxy`, `pkg/policy`)**:
  - Tracked explicit `"id": null` requests (with FIFO pending queues and canonical JSON ID normalization) so `"id": null` responses cannot bypass `tools/list` quarantine or `tools/call` DLP.
  - Hardened `readFrame` / `readJSONRPCFrame` against conflicting duplicate `Content-Length` smuggling, unbounded NDJSON lines, header floods, malformed headers, UTF-8 BOM prefixes, and arbitrary non-canonical MIME headers.
  - Extended `tools/call` DLP inspection/redaction to cover JSON-RPC `error` payloads, JSON map keys, and structured key-value objects (e.g. `structuredContent` containing contextual secrets like `aws_secret_access_key`).
  - Added iterative lenient percent-decoding (`%2e%2e%2f`, `%252e%252e%252f`, stray `%zz`), NUL-byte rejection, rooted POSIX path confinement on Windows, and case-insensitive `file://localhost/...` URI normalization in `policy.EvaluatePath` and `mcpproxy.ExtractPaths`.
  - Fixed `policy.EvaluateDomain` order of operations so trailing dots before `:port` (e.g. `EVIL.COM.:443`) and multiple trailing dots cannot bypass `DenyDomains`.
  - Hardened `ScanToolPoisoning` against HTML-entity encoded tags (`&#x3c;IMPORTANT&#x3e;`, `&#60; important &#62;`, `&lt;OVERRIDE&gt;`), XML tag attributes, and invisible Unicode word splitters (`U+00AD`, `U+061C`, `U+2060`, `U+FEFF`).
- **Egress & SSRF Firewall Hardening (`pkg/egress`)**:
  - Blocked IPv6-embedded IPv4 SSRF vectors (`64:ff9b::/96` NAT64, `::ffff:0:0:0/96`, `::/96`, `2002::/16` 6to4), IPv6 zone IDs (`fe80::1%eth0`, `%25eth0`), reserved IP ranges, and multiple trailing dots.
  - Blocked HTTP and TLS MITM `Host`-header domain fronting when `Host` differs from target host, rejected non-HTTP(S) schemes, capped `EphemeralCA` certificate cache size, added `IdleTimeout`/`MaxHeaderBytes`/MITM read deadlines, and eliminated a `CONNECT` connection leak race during `Proxy.Close()`.
- **DLP & `.env` Fixes (`pkg/dlp`)**:
  - Fixed `.env` parsing for UTF-8 BOM, `export\tKEY=...`, backtick quotes, and earliest whitespace+`#` inline comment stripping.
  - Merged overlapping DLP spans in `resolveOverlaps` so `Redact` never leaks unredacted secret tails on partial overlaps, and updated `MCP03-AWS-SECRET-KEY` to match JSON-quoted keys.
- **OS Sandbox Hardening (`pkg/sandbox`)**:
  - Hardened macOS Seatbelt profile generation against SBPL injection via quotes/backslashes/newlines/NUL bytes in `WorkDir`.
  - Made Windows case-insensitive `BuildCleanEnv` deduplication 100% deterministic (preferring canonical uppercase keys).
  - Added graceful fallback in Win32 Job Object setup/assignment when `AssignProcessToJobObject` returns `ERROR_ACCESS_DENIED` inside restricted nested-job containers.
- **Audit, SARIF & Self-MCP Hardening (`pkg/audit`, `cmd/mcpgate`)**:
  - Skipped symlinks/symlink loops and enforced pre-read size caps (`2 MiB` JSON / `512 KiB` YAML / `10 MiB` `AuditFiles`) during directory audits to prevent OOM and symlink hangs.
  - Fixed SARIF 2.1.0 `artifactLocation.uri` RFC 3986 escaping for Windows drive paths (`file:///C:/...`), UNC paths, and special characters/spaces.
  - Added JSON-RPC 2.0 batch support and strict method/version/params validation to `mcpgate mcp`.

## [1.0.0] - 2026-11-21

### Added
- **Zero-Trust Policy Engine (`pkg/policy`, `mcpgate/v1`)**:
  - Declarative YAML/JSON schema supporting `filesystem`, `network`, `dlp`, `mcp`, `sandbox`, and `audit` controls.
  - Four hardened built-in presets: `balanced`, `strict`, `readonly`, and `airgapped`.
  - Symlink-resolving filesystem confinement with built-in sensitive path blocks (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `.env*`, keychains, `/etc/shadow`).
  - Precedence-ordered tool authorization (`DenyTools > PromptTools > AllowTools > DefaultToolAction`).
- **Live DLP Secret & PII Scanner (`pkg/dlp`)**:
  - Real-time detection and optional redaction/blocking of cloud keys, VCS tokens, LLM API keys, payment keys, PEM private keys, JWTs, and user-defined custom regex rules.
  - Automatic `.env` value fingerprinting (stores only hashed fingerprints, never raw secrets) with Base64 and URL-encoded evasion decoding.
- **DNS-Pinned Egress Firewall & SSRF Defense (`pkg/egress`)**:
  - Local HTTP and HTTPS `CONNECT` egress proxy enforcing domain allowlists/denylists, port allowlists, and airgapped mode.
  - Pre-dial DNS resolution and IP pinning blocking AWS/GCP/Azure/Alibaba IMDS (`169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `fd00:ec2::254`, `metadata.google.internal`), IPv4-mapped IPv6 bypasses, loopback, link-local, CGNAT, and RFC1918 ranges.
  - Optional ephemeral local CA support for TLS payload inspection (`inspect_tls`).
- **Live MCP JSON-RPC Security Proxy (`pkg/mcpproxy`)**:
  - Real-time tool-poisoning detection and quarantine for embedded prompt-injection tags, stealth directives, Unicode spoofing, exfiltration instructions, and shell smuggling.
  - Canonical SHA-256 tool schema lockfile (`mcpgate.lock`) with `off`, `warn`, `enforce`, and `update` modes to prevent mid-session and upstream rug-pull attacks.
  - Runaway agent circuit breaker enforcing per-minute call rates, consecutive error limits, and identical-call loop caps.
- **OS-Native Process & Environment Sandbox (`pkg/sandbox`)**:
  - Clean environment scrubbing (`clean_env` + `pass_env` allowlist) stripping host credentials before launching child MCP servers.
  - Cross-platform containment: Linux Landlock + process groups + `RLIMIT`, macOS Seatbelt (`sandbox-exec`), and Windows Win32 Job Objects with `KILL_ON_JOB_CLOSE`.
- **OWASP MCP Top 10 Static Auditor & Telemetry (`pkg/audit`)**:
  - Static config and policy auditing covering `OWASP-MCP01` through `OWASP-MCP07` with A–F grading and 0–100 risk scoring.
  - Output formats: console table, JSON, OASIS SARIF 2.1.0 (for GitHub Code Scanning), and self-contained zero-CDN dark-mode interactive HTML reports.
  - Structured JSONL `SecurityEvent` audit logging compatible with ToolPrune security event logs.
- **IDE Preset Auto-Wrapper & Unwrapper (`pkg/preset`)**:
  - JSON/JSONC-safe, atomic, idempotent wrapping and unwrapping for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, and Zed.
- **CLI & Read-Only Self-MCP Server (`cmd/mcpgate`)**:
  - Full command suite: `run`, `audit`, `lock` (`init`/`verify`), `test-policy`, `inspect`, `preset`, `doctor`, `mcp`, and `version`.
- **Packaging, Installers & Hardened CI/Release Pipelines**:
  - Pure-Go (`CGO_ENABLED=0`) multi-arch release binaries (`linux`/`darwin`/`windows` x `amd64`/`arm64`) with SHA-256 `checksums.txt`.
  - POSIX `install.sh` (strict LF, atomic `.tmp.$$` install, GitHub API latest lookup with `v1.0.0` fallback) and zero-cmdlet pure-`.NET` `install.ps1`.
  - Multi-stage distroless non-root `Dockerfile` (`golang:1.24-alpine` -> `gcr.io/distroless/static-debian12:nonroot`).
  - GitHub Actions CI & Release workflows hardened for Node 24 with least-privilege permissions.
