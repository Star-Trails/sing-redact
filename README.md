# sing-redact

`sing-redact` is a cross-platform CLI (Linux, macOS, Windows) that performs deterministic, structure-aware, local redaction of sing-box JSON configurations. It produces clean, sanitized JSON suitable for sharing with ChatGPT, Claude, Gemini, GitHub issues, technical forums, or colleagues for troubleshooting.

**sing-redact is an independent community tool and is not affiliated with or endorsed by SagerNet or the sing-box project.**

---

## What it does

```bash
# Linux / macOS
sing-redact config.json

# Windows
sing-redact.exe config.json
```

This creates, without modifying the original configuration:

```text
config.redacted.json
```

The executable:

- **100% Offline & Private**: Runs entirely locally and transmits no configuration content over the network.
- **Zero Telemetry**: No tracking, phone-home, or analytics.
- **Embedded jq Engine**: Embeds its redaction policy with [`github.com/itchyny/gojq`](https://github.com/itchyny/gojq); no system `jq` installation required.
- **Extended JSON Support**: Accepts JSONC comments (`//`, `/* */`), hash comments (`#`), and trailing commas used by sing-box.
- **Structure & Graph Preservation**: Preserves object key ordering, array ordering, value types, ports, tags, ALPN, multiplexing, and routing graph references.
- **Deterministic Placeholder Mapping**: Replaces endpoints and identities with stable, RFC-reserved documentation values (`redacted.example`, `192.0.2.1`, etc.).
- **Atomic File Writing**: Writes via a synced temporary file with platform-native atomic replacement (`MoveFileExW` on Windows, POSIX `os.Rename` on macOS/Linux).
- **Defense-in-Depth Audit**: Performs a second-stage residual secret scan before writing to ensure nothing was missed.

---

## Supported Platforms & Pre-built Binaries

Pre-compiled standalone binaries are available on the [GitHub Releases](https://github.com/Star-Trails/sing-redact/releases) page for:

| Platform | Architecture | Binary Package |
|---|---|---|
| **Linux** | `amd64` (x86_64) | `sing-redact-v*-linux-amd64.tar.gz` |
| **Linux** | `arm64` (aarch64) | `sing-redact-v*-linux-arm64.tar.gz` |
| **macOS** | `arm64` (Apple Silicon) | `sing-redact-v*-darwin-arm64.tar.gz` |
| **macOS** | `amd64` (Intel x86_64) | `sing-redact-v*-darwin-amd64.tar.gz` |
| **Windows** | `amd64` (x86_64) | `sing-redact-v*-windows-amd64.zip` |
| **Windows** | `arm64` (ARM64) | `sing-redact-v*-windows-arm64.zip` |

No Python, Node.js, Bash, WSL, MSYS2, or external libraries required at runtime. Each release is a single standalone executable.

---

## Installation

### Linux & macOS

Download the latest release for your architecture and place it in your `PATH`:

```bash
# Example for Linux (x86_64)
curl -sL https://github.com/Star-Trails/sing-redact/releases/latest/download/sing-redact-v0.1.0-linux-amd64.tar.gz | tar -xz
sudo mv sing-redact /usr/local/bin/

# Example for macOS (Apple Silicon)
curl -sL https://github.com/Star-Trails/sing-redact/releases/latest/download/sing-redact-v0.1.0-darwin-arm64.tar.gz | tar -xz
sudo mv sing-redact /usr/local/bin/
```

### Windows

1. Download `sing-redact-v*-windows-amd64.zip` from [Releases](https://github.com/Star-Trails/sing-redact/releases).
2. Extract `sing-redact.exe` to any folder (e.g. `C:\Tools\`).
3. Add that folder to your User `PATH` or run it directly.

**Windows Explorer Drag-and-Drop**: You can also drag and drop any `config.json` file onto `sing-redact.exe` in Windows Explorer to automatically generate `config.redacted.json` in the same folder.

---

## Disclosure Modes

### 1. `share` (Default)

Designed for sharing configurations with an AI, technical support person, or troubleshooting community.

- **Redacted**: Passwords, tokens, private keys, PSKs, UUIDs, session cookies, authorization headers, real proxy/VPN server endpoints, non-Reality TLS `server_name`, `certificate_providers[].domain`, `tls.ech.config`, `reality.public_key`, WARP `reserved` bytes, user/host/device identities, local filesystem paths, interface identities, Wi-Fi SSID/BSSID, MAC addresses, and private source LAN CIDRs.
- **Preserved**: Protocol types, inbound/outbound tags, ports, Reality camouflage SNI (e.g. `itunes.apple.com`), WARP peer public keys, TUN virtual interface stack (`tun.address`, `tun.dns_address`), public rule-set download URLs, transport paths, ALPN, multiplexing, congestion control, and routing actions.

```bash
sing-redact config.json
sing-redact config.json --mode share
```

### 2. `credentials`

Designed for trusted internal debugging or local AI models when you only want to strip direct authentication secrets while keeping network topology visible.

- **Redacted**: Passwords, passphrases, UUID authentication identities, tokens, session cookies, authorization headers, API credentials, private keys, PSKs, Reality short IDs, embedded URL credentials, obvious JWTs, and private-key PEM.
- **Preserved**: Server endpoints, TLS SNIs, public keys, local paths, and rule literals.

```bash
sing-redact config.json --mode credentials
```

### 3. `strict`

Designed for posting to public GitHub issues, public forums, or open chat groups.

- **Redacted**: Everything in `share`, plus TLS SNIs (including Reality camouflage SNIs), public peer keys, peer/certificate fingerprints, certificate content, route/DNS literal domains, IP rules, process names/paths, package names, user IDs, custom URLs, DNS hosts object keys, and ShadowTLS SNI mapping object keys (deterministically rewritten with collision detection).

```bash
sing-redact config.json --mode strict
```

---

## What Remains Visible

| Field / Category | `credentials` | `share` (default) | `strict` |
|---|:---:|:---:|:---:|
| **Password / token / cookie / private key / PSK / UUID / auth headers** | 🔒 Hidden | 🔒 Hidden | 🔒 Hidden |
| **Proxy / VPN / DNS / NTP remote server endpoint** | 👁️ Visible | 🔒 Hidden | 🔒 Hidden |
| **Authentication username / device identity** | 🔒 Hidden | 🔒 Hidden | 🔒 Hidden |
| **TUN inbound address & virtual stack (`address`, `dns_address`, etc.)** | 👁️ Visible | 👁️ Visible | 🔒 Hidden |
| **Reality camouflage SNI / WARP public keys / public rule-set URLs** | 👁️ Visible | 👁️ Visible | 🔒 Hidden |
| **Non-Reality TLS `server_name` / `certificate_providers[].domain`** | 👁️ Visible | 🔒 Hidden | 🔒 Hidden |
| **`tls.ech.config` / `reality.public_key` / `reserved`** | 👁️ Visible | 🔒 Hidden | 🔒 Hidden |
| **Local filesystem paths / interfaces / private networks** | 👁️ Visible | 🔒 Hidden | 🔒 Hidden |
| **Route / DNS literal domains & IP CIDR rules** | 👁️ Visible | 👁️ Visible | 🔒 Hidden |
| **Process & package rule names** | 👁️ Visible | 👁️ Visible | 🔒 Hidden |
| **Tags, detours, selectors, rule-set & DNS references** | 👁️ Visible | 👁️ Visible | 👁️ Visible |
| **Ports, protocol, transport, ALPN, multiplex, rule order, numbers, booleans** | 👁️ Visible | 👁️ Visible | 👁️ Visible |

---

## CLI Examples

### Basic Usage

```bash
# Default neighboring output (config.redacted.json)
sing-redact config.json

# Explicit output file
sing-redact config.json -o safe.json

# Print sanitized JSON directly to stdout
sing-redact config.json --stdout > safe.json

# Read from stdin
cat config.json | sing-redact --stdin > safe.json
# Windows PowerShell:
Get-Content -Raw config.json | sing-redact.exe --stdin > safe.json
```

### Reporting & Analysis

```bash
# Print a safe category and JSON-path report to stderr while saving output
sing-redact config.json --report

# Analyze only (exit code 1 if sensitive data found; no file created)
sing-redact config.json --check
```

### Overwriting Existing Files

```bash
# Explicitly replace an existing target file
sing-redact config.json -o safe.json --force
```

### Optional Gitleaks Audit

If [`gitleaks`](https://github.com/gitleaks/gitleaks) is installed on your machine and available in `PATH`:

```bash
sing-redact config.json --gitleaks
```

---

## CLI Flags

```text
-o, --output PATH       Write to PATH (default: <name>.redacted.json)
    --stdout            Write only sanitized JSON to stdout
    --stdin             Read configuration from stdin
    --mode MODE         credentials, share (default), or strict
    --report            Print redacted categories and JSON paths to stderr
    --check             Analyze only; do not create an output file
    --force             Atomically replace an existing output file
    --allow-suspicious  Write despite safe-path-only audit findings
    --gitleaks          Run optional local Gitleaks audit when installed
-h, --help              Show this help
    --version           Show tool and policy snapshot versions
```

---

## Output Naming & Exit Codes

- `config.json` becomes `config.redacted.json`.
- `home-router.json` becomes `home-router.redacted.json`.
- `--stdin` writes to stdout unless `-o` is specified.
- The input path itself is rejected as an output path to prevent accidental overwrites.

### Exit Codes

| Code | Meaning |
|---:|---|
| `0` | Success, or `--check` found no sensitive data |
| `1` | `--check` detected sensitive or suspicious data |
| `2` | CLI flag error, input read failure, parse error, or runtime error |
| `3` | Sanitized-output defense audit detected unredacted secrets (output blocked) |

---

## Supported sing-box Version Snapshot

Policy research target:

- **Target Line**: sing-box `1.14.0 testing`
- **Branch**: `testing`
- **Commit**: [`df34f5068b961fe3390a61eb3e773ad9bf4d98e2`](https://github.com/SagerNet/sing-box/commit/df34f5068b961fe3390a61eb3e773ad9bf4d98e2)
- **Policy Snapshot Date**: `2026-08-31`
- **Official Schema**: [`docs/schema.json`](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/docs/schema.json)
- **Documentation**: <https://sing-box.sagernet.org/configuration/>

Check your compiled binary's snapshot:

```bash
sing-redact --version
```

---

## Building from Source

Requires Go 1.27 or newer.

```bash
# Clone the repository
git clone https://github.com/Star-Trails/sing-redact.git
cd sing-redact

# Run test suite and vet checks
go test -count=1 ./...
go vet ./...

# Build binary for your current platform
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/sing-redact ./cmd/sing-redact
```

### Cross-Compiling

```bash
# Windows (x86_64)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/sing-redact.exe ./cmd/sing-redact

# macOS (Apple Silicon)
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/sing-redact-darwin-arm64 ./cmd/sing-redact

# macOS (Intel x86_64)
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/sing-redact-darwin-amd64 ./cmd/sing-redact

# Linux (x86_64)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/sing-redact-linux-amd64 ./cmd/sing-redact

# Linux (ARM64)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/sing-redact-linux-arm64 ./cmd/sing-redact
```

---

## Security & Privacy Design

- **Read-Only Input**: The input file is opened read-only and is never written to.
- **No Network Activity**: The binary contains no HTTP client or networking code; nothing leaves your machine.
- **Zero Secret Echoing**: Error messages, logs, and `--report` outputs display JSON paths and categories only, never value excerpts, prefixes, suffixes, or hashes.
- **Safe Documentation Ranges**: Placeholders strictly use RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 (`2001:db8::/32`), and RFC 2606 (`.example`) ranges.
- **Atomic Commits**: Output is written to a temporary file in the target directory, synced to disk, and committed atomically (`MoveFileExW` on Windows, POSIX `os.Rename` on Linux/macOS).

---

## License

[MIT License](LICENSE) © 2026 Star-Trails
