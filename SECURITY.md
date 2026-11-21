# Security Policy

## Reporting a Vulnerability

MCPGate is a zero-trust runtime security gateway for Model Context Protocol (MCP) servers and AI agents. We take security vulnerabilities seriously.

Please report suspected security issues via GitHub Private Vulnerability Reporting or by opening a minimal advisory issue without publishing live exploit payloads targeting third-party services.

### Scope of Security Guarantees
- **OS Process & Environment Isolation:** Enforces process group/Win32 Job containment, clean environment allowlisting (`--clean-env`), and OS-native filesystem restrictions where supported (Linux Landlock, macOS Seatbelt, Windows Job Objects + path policy).
- **Egress Firewall & SSRF Defense:** Validates outbound proxy targets against domain allowlists, blocks cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`) and private RFC1918/loopback ranges by resolving and pinning IPs prior to dialing.
- **MCP JSON-RPC Policy & DLP:** Inspects live tool schemas for prompt-injection/tool-poisoning and SHA-256 rug-pull drift, blocks sensitive path traversal arguments, and scans payloads for leaked secrets and `.env` fingerprints.

