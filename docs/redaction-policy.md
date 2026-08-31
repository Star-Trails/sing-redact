# Redaction policy

This policy was researched before implementation against the sing-box **testing** branch on 2026-08-31.

- Target release line: sing-box 1.14.0 testing
- Commit: [`df34f5068b961fe3390a61eb3e773ad9bf4d98e2`](https://github.com/SagerNet/sing-box/commit/df34f5068b961fe3390a61eb3e773ad9bf4d98e2)
- Schema snapshot: [`docs/schema.json`](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/docs/schema.json)
- Configuration documentation: <https://sing-box.sagernet.org/configuration/>
- Option structs: [`option/`](https://github.com/SagerNet/sing-box/tree/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option)
- Extended JSON behavior: sing `v0.9.0-beta.4`, commit [`3f8f790b7a2968307bbf900544fc8030791c715e`](https://github.com/SagerNet/sing/commit/3f8f790b7a2968307bbf900544fc8030791c715e), whose JSON decoder accepts JSONC comments and trailing commas.

The jq policy classifies values using the complete JSON path, root section, parent object, parent `type`, key, and value type. Go applies type-preserving replacements, deterministic mappings, URL parsing, ordered serialization, and a second audit. `tag`, `outbound`, `inbound`, `detour`, DNS-server references, rule-set references, HTTP-client references, certificate-provider references, and network-namespace references remain unchanged by default.

## Disclosure modes

| Category | credentials | share | strict |
|---|---:|---:|---:|
| Password, secret, token, cookie, UUID, private key, PSK, auth header | redact | redact | redact |
| Remote proxy/VPN/DNS/NTP endpoint | keep | redact | redact |
| User, account, device, host identity | mostly keep; redact authentication identities | redact | redact |
| Local filesystem path and interface identity | keep, except paths to secret material | redact | redact |
| TLS SNI and public peer fingerprints | keep | keep | redact |
| Route/DNS literal domains, IPs, processes, packages | keep | keep except local identity | redact/anonymize |
| Ports, protocol, transport, routing graph, tags | keep | keep | keep |

## Field and context inventory

`replacement` names are logical actions. Arrays retain their length; objects are traversed rather than replaced; numbers remain numbers, booleans remain booleans, and null remains null.

| JSON path / context | Field | Risk category | Modes | Replacement | Official source |
|---|---|---|---|---|---|
| Any scalar leaf; allowlist excludes public/fingerprint metadata | `password`, `passwd`, `passphrase`, `private_key_passphrase`, `client_key_password`, `mca_key_password` and normalized equivalents | credential | all | `<REDACTED:PASSWORD>` | [schema](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/docs/schema.json), [OpenConnect](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/openconnect.go) |
| `inbounds[]`, `outbounds[]`, `endpoints[]`, nested `users[]` | `uuid` | authentication identity | all | `00000000-0000-4000-8000-000000000000` | [VLESS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/vless.go), [VMess](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/vmess.go), [TUIC](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tuic.go) |
| `**.reality` | `short_id` | authentication identity | all | valid zero hex, preserving list length | [TLS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tls.go) |
| WireGuard endpoint | `private_key`, `peers[].pre_shared_key` | private key / PSK | all | `<REDACTED:PRIVATE_KEY>` / `<REDACTED:PSK>` | [WireGuard](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/wireguard.go) |
| SSH outbound | `private_key`, `private_key_path`, `private_key_passphrase` | private key / secret path | all | private-key/path/password placeholders | [SSH](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/ssh.go) |
| TLS server, client and ECH | `key`, `key_path`, `client_key`, `client_key_path`, `ech.key`, `ech.key_path` | private key / secret path | all | private-key/path placeholders | [TLS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tls.go) |
| Outbound TLS ECH | `ech.config`, `ech.config_path` | public configuration fingerprint / local path | config path: share/strict; config content: share/strict | path/fingerprint placeholders | [TLS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tls.go) |
| OpenVPN endpoint | `static_key`, `static_key_path`, `tls.client_key`, `tls.client_key_path`, `tls.client_key_password` | PSK / private key | all | PSK/private-key/path/password placeholders | [OpenVPN](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/openvpn.go) |
| OpenConnect TLS | `client_key`, `client_key_path`, `client_key_password`, `mca_key`, `mca_key_path`, `mca_key_password` | private key | all | private-key/path/password placeholders | [OpenConnect](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/openconnect.go) |
| Snell inbound/outbound/users | `psk`, `userkey` | PSK / authentication credential | all | `<REDACTED:PSK>` / `<REDACTED:CREDENTIAL>` | [Snell](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/snell.go) |
| Tailscale DERP | `mesh_psk`, `mesh_psk_file` | PSK / secret path | all | PSK/path placeholders | [Tailscale](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tailscale.go) |
| ACME provider | `account_key`, `external_account.key_id`, `external_account.mac_key`, `domain` | account credential / identifier / domain | domain: share/strict; keys/identifiers: all | key/identifier/domain placeholders | [ACME](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/acme.go) |
| ACME DNS01 `alidns` | `access_key_id`, `access_key_secret`, `security_token` | API credential | all | credential/secret/token placeholders | [ACME DNS01](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tls_acme.go) |
| ACME DNS01 `cloudflare` | `api_token`, `zone_token` | API credential | all | `<REDACTED:TOKEN>` | [ACME DNS01](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tls_acme.go) |
| Cloudflare Origin CA provider | `api_token`, `origin_ca_key` | API credential / private key | all | token/private-key placeholders | [Origin CA](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/origin_ca.go) |
| ACME DNS01 `acmedns` | `username`, `password`, `subdomain`, `server_url` | credential / identity / endpoint | credentials: username/password; share/strict: all | credential/password/identity/URL placeholders | [ACME DNS01](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tls_acme.go) |
| `experimental.clash_api` and API service | `secret` | API credential | all | `<REDACTED:SECRET>` | [experimental](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/experimental.go), [API](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/api.go) |
| Cloudflared inbound | `token` | tunnel credential | all | `<REDACTED:TOKEN>` | [Cloudflared](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/cloudflared.go) |
| CCM/OCM inbound | `credential_path`, `users[].token`, `usages_path` | credential / local path | token and credential path: all; usages path: share/strict | credential/path placeholders | [CCM](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/ccm.go), [OCM](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/ocm.go) |
| Hysteria2 realm | `token` | service credential | all | `<REDACTED:TOKEN>` | [Hysteria2](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/hysteria2.go) |
| OpenConnect endpoint | `username`, `password`, `cookie` | authentication/session credential | all | credential/password/cookie placeholders | [OpenConnect](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/openconnect.go) |
| OpenConnect `token` object | `secret`, `secret_path`, `pin`, `password`, `device_id` | OTP/OIDC/session credential and device identity | credentials: secret/path/PIN/password/device auth ID; share/strict: all | credential/path/identity placeholders | [OpenConnect](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/openconnect.go) |
| OpenConnect forms | `submission_key` | authentication form key | all | `<REDACTED:CREDENTIAL>` | [OpenConnect](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/openconnect.go) |
| OpenVPN endpoint/users | `username`, `password` | authentication credential | all | credential/password placeholders | [OpenVPN](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/openvpn.go) |
| Any `headers` or `extra_headers` object, case-insensitive | `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, API-key/token/secret/password-like names | header credential | all | authorization/cookie/secret placeholder | [HTTP client](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/http.go), [transport](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/v2ray_transport.go) |
| Any URL-valued string | URL userinfo and sensitive query keys | embedded credential | all | parsed with `net/url`; credential components replaced | schema and all URL fields below |
| Any scalar string | private-key PEM or obvious JWT | embedded credential | all | private-key/token placeholder | content fallback |
| Any normalized scalar key not allowlisted | password/secret/token/cookie/private-key/PSK/API-key/PIN pattern | unknown future credential | all | type-preserving credential placeholder | forward-compatible fallback |
| `outbounds[]` direct server field | `server` | private endpoint | share/strict | reserved IP/domain placeholder; port kept | [outbound `ServerOptions`](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/outbound.go) |
| `endpoints[]` OpenConnect and other direct remote server | `server` | private endpoint | share/strict | endpoint placeholder | [OpenConnect](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/openconnect.go) |
| OpenVPN endpoint | `servers[].server` | private endpoint | share/strict | endpoint placeholder; `server_port` kept | [OpenVPN](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/openvpn.go) |
| WireGuard endpoint | `peers[].address` | private endpoint | share/strict | endpoint placeholder; `port` kept | [WireGuard](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/wireguard.go) |
| Reality/ShadowTLS handshake | `handshake.server` | private endpoint | share/strict | endpoint placeholder | [ShadowTLS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/shadowtls.go), [TLS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tls.go) |
| DNS `servers[]` remote address options | `server` | resolver endpoint | share/strict | endpoint placeholder | [DNS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/dns.go) |
| NTP remote options | `server` | remote endpoint | share/strict | endpoint placeholder | [NTP](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/ntp.go) |
| Tailscale endpoint | `control_url`, `exit_node`, `relay_server_static_endpoints` | private endpoint/network | share/strict | URL/endpoint placeholders | [Tailscale](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tailscale.go) |
| Hysteria2 realm | `server_url`, `stun_servers` | private endpoint | share/strict | URL/endpoint placeholders | [Hysteria2](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/hysteria2.go) |
| Route/DNS action/resolve objects | `server` with `reference:"dns_server"` | internal reference | none | unchanged | [rule actions](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/rule_action.go) |
| Authentication objects and local rules | `username`, `user`, `auth_user`, `users[].name`, `email` | account identity | share/strict; direct authentication username also credentials | deterministic user/email placeholder | schema option structs |
| Host/device contexts | `hostname`, `local_hostname`, `source_hostname`, `device_id`, `device_unique_id` | device identity | share/strict; auth device ID also credentials | identity placeholder | [OpenConnect](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/openconnect.go), [rules](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/rule.go) |
| Tailscale endpoint | `auth_key`, `hostname`, `state_directory`, `taildrop_directory`, `system_interface_name`, `advertise_routes` | credential, identity, path, network | auth key: all; rest: share/strict | category placeholder | [Tailscale](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tailscale.go) |
| Explicit local-file fields | suffix `_path`, `_directory`, `_directory_path`; `dhcp_lease_files`, `external_ui`, local rule-set `path`, cache-file `path`, hosts-file `path` | local environment | share/strict; secret-material paths all | `<REDACTED:PATH>` | [route](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/route.go), [rule set](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/rule_set.go), [experimental](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/experimental.go) |
| Transport, DoH, API dashboard path | plain `path` | protocol path | none | unchanged | [DNS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/dns.go), [transport](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/v2ray_transport.go) |
| WireGuard endpoint | `address`, `allowed_ips` | local/private network | share/strict | reserved address/CIDR placeholder | [WireGuard](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/wireguard.go) |
| TUN inbound stack options | `address`, `dns_address`, `loopback_address`, `route_address`, `route_exclude_address`, `inet4_address`, `inet6_address` | virtual tunnel stack configuration | retained in credentials and share; anonymized in strict | reserved address/CIDR placeholder | [TUN](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tun.go) |
| OpenVPN endpoint and bind/interface options | address, peer address, interface names, bind addresses | local network identity | share/strict | reserved network/interface placeholder | [OpenVPN](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/openvpn.go) |
| Route/DNS rules | `process_path`, `process_path_regex`, `wifi_ssid`, `wifi_bssid`, `source_mac_address`, `source_hostname`, interface-address fields, private `source_ip_cidr` | local identity | share/strict | category placeholder | [route rules](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/rule.go), [DNS rules](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/rule_dns.go) |
| Route/DNS/headless rules | literal domain fields | configuration fingerprint | strict | deterministic `domain-N.redacted.example`; regex uses safe regex | [rules](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/rule.go) |
| Route/DNS/headless rules | `ip_cidr`, `source_ip_cidr`, client-subnet and interface-address fields | configuration fingerprint | strict | reserved address/CIDR; number and list shape retained | [rules](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/rule.go) |
| Route/DNS/headless rules | process and package fields | configuration fingerprint | strict | deterministic process/package placeholder | [rules](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/rule.go) |
| TLS contexts (non-Reality) | `server_name`, `default_server_name`, `query_server_name` | private node SNI / server domain | share/strict | deterministic domain placeholder | [TLS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tls.go), [ACME](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/acme.go) |
| Reality TLS contexts | `reality.server_name` (camouflage SNI) | public camouflage domain | strict | deterministic domain placeholder (kept in credentials and share) | [TLS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tls.go) |
| Reality configuration | `reality.public_key` | peer fingerprint | share/strict | `<REDACTED:FINGERPRINT>` | [TLS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tls.go) |
| WireGuard reserved | `reserved` | routing/client authentication metadata | share/strict | numeric arrays become zero arrays | [WireGuard](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/wireguard.go) |
| TLS/WireGuard/SSH public material | `public_key`, certificate public-key hashes, `peer_fingerprint`, `fingerprint`, `host_key` | stable peer fingerprint | strict | key/fingerprint placeholder | [TLS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tls.go), [WireGuard](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/wireguard.go) |
| TLS/certificate contexts | `certificate`, `client_certificate`, `mca_certificate`, certificate-authority content | certificate identity | client-identifying content: share; all: strict | `<REDACTED:CERTIFICATE>` | [TLS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/tls.go), [OpenConnect](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/openconnect.go) |
| `handshake_for_server_name` object keys | SNI domain keys | sensitive object key | strict | deterministic `sni-N.redacted.example`, collision checked | [ShadowTLS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/shadowtls.go) |
| DNS hosts `predefined` object keys and values | host keys and address values | local host identity | private address values: share; keys and all values: strict | deterministic host key and reserved address | [DNS](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/dns.go) |
| `interface_address` object keys | interface names | local interface identity | share/strict | deterministic `interface-N`, collision checked | [rules](https://github.com/SagerNet/sing-box/blob/df34f5068b961fe3390a61eb3e773ad9bf4d98e2/option/rule.go) |
| Any string not otherwise classified | high-entropy material | suspicious only | all | unchanged; audit finding only | defense-in-depth audit |

## Generic fallback allowlist

The normalized-key fallback does **not** treat these as secrets solely by name: `public_key`, `certificate_public_key_sha256`, `client_certificate_public_key_sha256`, `key_type`, `key_direction`, `host_key_algorithms`, `server_port`, `server_ports`, `listen_port`, `port`, `tag`, `outbound`, `inbound`, `detour`, `rule_set`, `http_client`, `certificate_provider`, and network-namespace references. Mode-specific strict rules may still redact public keys and fingerprints.

## Safe placeholders

- IPv4: `192.0.2.1` onward within documentation ranges
- IPv4 CIDR: `192.0.2.0/24`
- IPv6: `2001:db8::1`
- IPv6 CIDR: `2001:db8::/32`
- Domain: `redacted.example` then deterministic subdomains
- URL: `https://redacted.example/`
- Email: `redacted@example.com`
- MAC: `02:00:00:00:00:01`
- UUID: `00000000-0000-4000-8000-000000000000`

Mappings exist only in memory for one invocation and are never logged or persisted.
