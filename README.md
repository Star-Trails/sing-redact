# sing-box-redact

`sing-box-redact` is a Windows-native CLI that performs deterministic, structure-aware, local redaction of sing-box JSON configurations. It produces readable sanitized JSON for ChatGPT, Claude, Gemini, GitHub issues, technical forums, or another person helping with troubleshooting.

**sing-box-redact is an independent community tool and is not affiliated with or endorsed by SagerNet or the sing-box project.**

## What it does

```powershell
sing-box-redact.exe C:\path\to\config.json
```

This creates, without changing the original file:

```text
C:\path\to\config.redacted.json
```

The executable:

- runs locally and does not upload configuration data;
- has no telemetry;
- embeds its jq policy and uses [`github.com/itchyny/gojq`](https://github.com/itchyny/gojq), so system `jq` is not required;
- accepts the JSONC comments and trailing commas used by sing-box;
- preserves object key order, array order, value types, ports, tags, and internal references;
- writes UTF-8 JSON with two-space indentation and a newline at EOF;
- writes through a synced temporary file and atomically commits or replaces the target;
- adds a second pure-Go residual-secret audit before file output.

No Python, Node.js, Bash, MSYS2, WSL, or external jq installation is required at runtime. The release artifact is one Windows `.exe`.

## Threat model

The tool reduces accidental disclosure of:

- authentication credentials and sessions;
- private cryptographic material;
- account and device identities;
- private proxy, VPN, DNS, NTP, and control endpoints;
- local filesystem and network details;
- public configuration fingerprints in strict mode.

It assumes the local Windows host and the resulting output location are trusted. It does not protect an input file already exposed through backups, shell history, malware, another process, or an unsafe destination. Review sanitized output before publishing it. Unknown future sing-box fields receive generic secret-key and content checks, but no finite policy can prove that arbitrary user-defined metadata is non-sensitive.

## Why schema-aware redaction

Fields such as `server`, `key`, `path`, `name`, and `user` are ambiguous:

- `outbounds[].server` is normally a remote endpoint;
- `route.rules[].server` can be a DNS-server tag and must remain intact;
- TLS `key` is private material;
- `public_key` is intentionally visible in credentials/share and hidden in strict;
- a transport or DoH `path` is diagnostic protocol structure;
- `private_key_path` and a local rule-set `path` identify local files.

The embedded jq program recursively classifies fields using JSON path, root section, parent object, parent `type`, field name, container name, and value type. Go then applies type-preserving deterministic replacements. The policy is readable at [`internal/redact/rules/redact.jq`](internal/redact/rules/redact.jq); the researched field inventory is in [`docs/redaction-policy.md`](docs/redaction-policy.md).

## Supported sing-box version/schema snapshot

Policy research target:

- sing-box release line: **1.14.0 testing**
- branch: `testing`
- commit: [`df34f5068b961fe3390a61eb3e773ad9bf4d98e2`](https://github.com/SagerNet/sing-box/commit/df34f5068b961fe3390a61eb3e773ad9bf4d98e2)
- policy/schema date: **2026-08-31**
- schema: [`docs/schema.json` at that commit](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/docs/schema.json)
- official configuration docs: <https://sing-box.sagernet.org/configuration/>

The testing source uses `github.com/sagernet/sing/common/json` from sing `v0.9.0-beta.4`. Its decoder accepts JSONC comments and trailing commas. This tool uses the pure-Go `hujson` parser from that same testing dependency graph, plus a string-aware hash-comment pass, before ordered generic decoding.

Check the compiled snapshot:

```powershell
sing-box-redact.exe --version
```

## Modes

### `credentials`

Use when only direct authentication material should be hidden, for example trusted internal troubleshooting or a local AI.

It hides passwords, passphrases, UUID authentication identities, tokens, cookies, authorization headers, API credentials, private keys, PSKs, Reality short IDs, embedded URL credentials, obvious JWTs, private-key PEM, and paths that directly point to secret material. It mostly keeps endpoints, TLS SNI, public keys, ordinary usernames/hostnames, local paths, and route literals.

```powershell
sing-box-redact.exe config.json --mode credentials
```

### `share` (default)

Use when sending a configuration to an AI, friend, or technical support person.

It includes credentials-mode protection and also hides real remote endpoints, authentication usernames, account/device/host identities, local filesystem paths, local interface and network identities, Wi-Fi/MAC data, and private source networks. It intentionally keeps protocol types, ports, TLS/Reality enablement, transport and DoH paths, network/multiplex/congestion settings, route/DNS ordering, rule actions, literal route domains/process names/packages, tags, and internal reference relationships.

```powershell
sing-box-redact.exe config.json
sing-box-redact.exe config.json --mode share
```

### `strict`

Use before posting to a public GitHub issue, forum, or chat group.

It includes share-mode protection and additionally anonymizes TLS SNI, outbound ECH configuration, Reality/WireGuard/SSH public peer material, certificate and peer fingerprints, certificate content, route/DNS literal domains and IPs, process fields, package fields, user IDs, interface maps, DNS hosts, and custom/remote URLs. Sensitive object keys such as ShadowTLS SNI maps and DNS hosts maps are deterministically rewritten with collision checks.

```powershell
sing-box-redact.exe config.json --mode strict
```

## What remains visible

| Data | credentials | share | strict |
|---|---:|---:|---:|
| Password/token/cookie/private key/PSK/UUID/auth headers | hidden | hidden | hidden |
| Proxy/VPN/DNS/NTP endpoint | visible | hidden | hidden |
| Authentication username/device identity | hidden where used for auth | hidden | hidden |
| TUN inbound address / virtual stack (`address`, `dns_address`, etc.) | visible | visible | hidden |
| Local paths/interfaces/private networks | mostly visible, except secret paths | hidden | hidden |
| Reality camouflage SNI / WireGuard public keys / public rule-set URLs | visible | visible | hidden |
| Non-Reality TLS `server_name` / `certificate_providers[].domain` | visible | hidden | hidden |
| `tls.ech.config` / `reality.public_key` / `reserved` | visible | hidden | hidden |
| Route/DNS literal domains and IPs | visible | visible, except local identity | hidden |
| Process/package rule literals | visible | visible, except process paths | hidden |
| Tags, detours, selectors, rule-set and DNS references | visible | visible | visible |
| Ports, protocol, transport, rule order, booleans, numbers | visible | visible | visible |

## Examples

Default neighboring output:

```powershell
sing-box-redact.exe config.json
```

Explicit output:

```powershell
sing-box-redact.exe config.json -o safe.json
```

JSON only on stdout; reports and diagnostics stay on stderr:

```powershell
sing-box-redact.exe config.json --stdout > safe.json
```

Read from stdin; stdin defaults to sanitized stdout when `-o` is absent:

```powershell
Get-Content -Raw config.json | sing-box-redact.exe --stdin > safe.json
```

Create a safe path-only report while also writing the sanitized file:

```powershell
sing-box-redact.exe config.json --report
```

Analyze without writing:

```powershell
sing-box-redact.exe config.json --check
```

Replace an existing target explicitly:

```powershell
sing-box-redact.exe config.json -o safe.json --force
```

Optional local Gitleaks pass, when `gitleaks` is already in `PATH`:

```powershell
sing-box-redact.exe config.json --gitleaks
```

Gitleaks is never required for core redaction. Its stdout/stderr are discarded; only rule category and sanitized-file line number are reported. The temporary sanitized scan file and machine-readable report are deleted afterward.

## Windows installation

1. Copy `sing-box-redact.exe` to a local directory, for example `C:\Tools\sing-box-redact\`.
2. Run it by full path, or add that directory to the user `PATH`.
3. Keep the original configuration in a trusted location. The tool never modifies it.

PowerShell may require unblocking an executable downloaded from a browser:

```powershell
Unblock-File .\sing-box-redact.exe
```

## Drag-and-drop usage

Drag one `config.json` file from Windows Explorer onto `sing-box-redact.exe`. Explorer passes the file path as the sole positional argument. The tool creates `config.redacted.json` beside the source. If that target already exists, no file is overwritten; use a terminal with `--force` when replacement is intentional.

## CLI flags

```text
-o, --output PATH       Write to PATH (default: <name>.redacted.json)
    --stdout            Write only sanitized JSON to stdout
    --stdin             Read configuration from stdin
    --mode MODE         credentials, share (default), or strict
    --report            Print redacted categories and JSON paths to stderr
    --check             Analyze only; do not create a file
    --force             Atomically replace an existing output file
    --allow-suspicious  Write despite safe-path-only audit findings
    --gitleaks          Run an optional local Gitleaks audit
-h, --help              Show help
    --version           Show tool and policy versions
```

Flags can appear before or after the input path, matching the documented Windows examples.

## Output naming

- `config.json` becomes `config.redacted.json`.
- `home-router.json` becomes `home-router.redacted.json`.
- An extensionless input becomes `<name>.redacted.json`.
- `--stdin` writes to stdout unless `-o` is supplied.
- `--check` never writes a file.
- `--force` is required to replace an existing destination.
- The input path itself is rejected as an output path, even with `--force`.

## Report mode

`--report` prints only category and JSON path to stderr:

```text
Redacted 4 values:
ENDPOINT         $.outbounds[0].server
CREDENTIAL       $.outbounds[0].uuid
PRIVATE_KEY      $.endpoints[0].private_key
PATH             $.experimental.cache_file.path
```

It never prints an original value, fragment, prefix, suffix, or hash. With `--stdout`, stdout remains JSON-only.

## Check mode

`--check` analyzes the selected disclosure mode without producing sanitized output:

```text
Credentials:   7
Private keys:  2
Endpoints:     4
Identifiers:   3
Paths:         2
Suspicious:    0
```

Use it in scripts:

```powershell
sing-box-redact.exe config.json --mode strict --check
if ($LASTEXITCODE -eq 1) { Write-Host "Sensitive data detected" }
```

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Success, or `--check` found nothing selected by the mode/audit |
| `1` | `--check` found sensitive or suspicious data |
| `2` | CLI, input, parse, policy, I/O, or optional Gitleaks runtime error |
| `3` | Sanitized-output audit found residual/suspicious content and output was blocked |

`--allow-suspicious` permits code-3 audit findings to be written after a warning. It does not change redaction policy.

## Defense-in-depth audit

After jq classification and Go replacement, the tool scans the sanitized tree for:

- private-key PEM;
- obvious JWTs;
- Bearer/Basic authorization material;
- URI userinfo and credential-like query parameters;
- non-placeholder values under known credential fields;
- common credential prefixes;
- token-like high-entropy strings.

The audit emits only category and JSON path. Known public cryptographic fields intentionally retained by `credentials`/`share`—including Reality/WireGuard public keys and outbound ECH config—are excluded from the generic high-entropy warning. Unknown high-entropy strings remain unchanged but block output by default; `--allow-suspicious` is explicit risk acceptance.

## Updating the redaction policy

For a new sing-box testing snapshot:

1. Record the testing commit, release line, and schema date in `internal/app/app.go`, this README, and `docs/redaction-policy.md`.
2. Diff official `docs/schema.json` and JSON struct tags under `option/`.
3. Review inbound, outbound, endpoint, shared TLS/transport/HTTP, certificate providers, DNS, route/rule-set, services, and experimental options.
4. Add every new credential, identity, private endpoint, local path/network, or strict fingerprint field to the policy table and jq context rules.
5. Extend `testdata/all-sensitive.json` and the planted-secret lists.
6. Run the complete verification commands below and inspect the built executable's report.

Do not update metadata without reviewing the exact commit's schema and source.

## Cross-platform and building from source

The project is written in 100% pure Go with `CGO_ENABLED=0` and is fully cross-platform for **Windows**, **macOS** (Intel & Apple Silicon), and **Linux** (amd64, arm64, etc.).

Requirements: Go 1.25 or newer.

### Windows (PowerShell)

```powershell
go test -count=1 ./...
go vet ./...

New-Item -ItemType Directory -Force dist | Out-Null
$env:CGO_ENABLED="0"
$env:GOOS="windows"
$env:GOARCH="amd64"

go build `
  -trimpath `
  -ldflags="-s -w" `
  -o dist\sing-box-redact.exe `
  .\cmd\sing-box-redact
```

### macOS / Linux (Bash / Zsh)

```bash
go test -count=1 ./...
go vet ./...

mkdir -p dist

# Native build for current OS & Arch:
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/sing-box-redact ./cmd/sing-box-redact

# Cross-compile for macOS (Apple Silicon M1/M2/M3/M4):
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/sing-box-redact-darwin-arm64 ./cmd/sing-box-redact

# Cross-compile for macOS (Intel x86_64):
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/sing-box-redact-darwin-amd64 ./cmd/sing-box-redact

# Cross-compile for Linux (amd64):
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/sing-box-redact-linux-amd64 ./cmd/sing-box-redact

# Cross-compile for Linux (arm64 / Raspberry Pi):
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/sing-box-redact-linux-arm64 ./cmd/sing-box-redact
```
## Security considerations

- Original input is opened read-only and is never selected as a valid destination.
- The program contains no network client and sends no configuration content over the network.
- Session-local placeholder mappings are never persisted or reported.
- Parser/runtime diagnostics do not include input excerpts.
- Reports contain paths and categories only.
- Existing output is not touched until parsing, redaction, audit, and serialization succeed.
- `--force` uses Windows `MoveFileExW` with replace-existing and write-through flags after syncing the temporary file.
- Non-force output uses an atomic same-volume hard-link commit, which cannot silently overwrite an existing name.
- `--gitleaks` is optional and local; subprocess output is suppressed to prevent accidental secret echoing.
- Reserved documentation address ranges and `.example` names are used, never arbitrary third-party addresses.

## Known limitations

- Output is normalized to two-space JSON. Original whitespace and comments are not retained; object and array ordering are retained.
- Duplicate object keys are rejected instead of guessing which duplicate sing-box would use.
- The generic parser checks redaction safety but does not perform full sing-box schema validation or validate protocol-specific option combinations.
- Unknown future fields are covered by normalized secret-key and content fallbacks, but ambiguous future fields still require a policy update.
- Unknown high-entropy values can trigger the conservative output audit; inspect the path and use `--allow-suspicious` only when the field is intentionally public.
- Strict URL replacement preserves only the documented sing-box documentation host allowlist. Credentials embedded in that allowlisted URL are still removed.
- Tags are preserved. Global `--anonymize-tags` mapping is not implemented because incomplete tag/reference rewriting would be more dangerous than leaving the internal graph intact.
- Input is limited to 64 MiB to bound memory use.
- The optional Gitleaks integration targets the common Gitleaks v8 `detect --no-git` CLI contract; incompatible future CLI versions return exit code 2 without exposing subprocess output.
