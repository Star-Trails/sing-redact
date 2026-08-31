package redact

import (
	"strings"
	"testing"

	"github.com/Star-Trails/sing-box-redact/internal/jsonx"
)

func sanitize(t *testing.T, input string, mode Mode) (*jsonx.Value, string) {
	t.Helper()
	root, err := jsonx.Parse([]byte(input))
	if err != nil {
		t.Fatalf("parse input: %v", err)
	}
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	operations, err := engine.Plan(root, mode)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if _, err = Apply(root, operations); err != nil {
		t.Fatalf("apply: %v", err)
	}
	output, err := root.MarshalIndent()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return root, string(output)
}

func stringAt(t *testing.T, root *jsonx.Value, path ...any) string {
	t.Helper()
	value, ok := root.At(path)
	if !ok || value.Kind != jsonx.String {
		t.Fatalf("%s is not a string", jsonx.FormatPath(path))
	}
	return value.Str
}

func TestVLESSModeMatrix(t *testing.T) {
	input := `{"outbounds":[{"type":"vless","tag":"proxy","server":"node.secret.example","server_port":443,"uuid":"bf000d23-0752-40b4-affe-68f7707a9661"}]}`
	credentials, _ := sanitize(t, input, ModeCredentials)
	if got := stringAt(t, credentials, "outbounds", 0, "server"); got != "node.secret.example" {
		t.Fatalf("credentials server = %q", got)
	}
	if got := stringAt(t, credentials, "outbounds", 0, "uuid"); got != "00000000-0000-4000-8000-000000000000" {
		t.Fatalf("credentials uuid = %q", got)
	}
	share, _ := sanitize(t, input, ModeShare)
	if got := stringAt(t, share, "outbounds", 0, "server"); got != "redacted.example" {
		t.Fatalf("share server = %q", got)
	}
	if got := stringAt(t, share, "outbounds", 0, "tag"); got != "proxy" {
		t.Fatalf("share tag = %q", got)
	}
	port, ok := share.At([]any{"outbounds", 0, "server_port"})
	if !ok || port.Kind != jsonx.Number || port.Num.String() != "443" {
		t.Fatalf("share server_port changed: %#v", port)
	}
}

func TestDNSServerReferenceIsNotEndpoint(t *testing.T) {
	input := `{"route":{"rules":[{"action":"resolve","server":"dns-direct"}]}}`
	for _, mode := range []Mode{ModeShare, ModeStrict} {
		root, _ := sanitize(t, input, mode)
		if got := stringAt(t, root, "route", "rules", 0, "server"); got != "dns-direct" {
			t.Fatalf("mode %s changed DNS reference to %q", mode, got)
		}
	}
}

func TestRealityModeMatrix(t *testing.T) {
	input := `{"outbounds":[{"type":"vless","tls":{"reality":{"public_key":"PUBLIC","short_id":["12345678","abcdef12"]}}}]}`
	credentials, _ := sanitize(t, input, ModeCredentials)
	if got := stringAt(t, credentials, "outbounds", 0, "tls", "reality", "public_key"); got != "PUBLIC" {
		t.Fatalf("credentials public_key = %q", got)
	}
	credShortIDs, _ := credentials.At([]any{"outbounds", 0, "tls", "reality", "short_id"})
	if len(credShortIDs.Arr) != 2 || credShortIDs.Arr[0].Str != "0000000000000000" || credShortIDs.Arr[1].Str != "0000000000000000" {
		t.Fatalf("credentials short IDs = %#v", credShortIDs)
	}
	for _, mode := range []Mode{ModeShare, ModeStrict} {
		root, _ := sanitize(t, input, mode)
		if got := stringAt(t, root, "outbounds", 0, "tls", "reality", "public_key"); got != "<REDACTED:FINGERPRINT>" {
			t.Fatalf("mode %s public_key = %q", mode, got)
		}
		shortIDs, _ := root.At([]any{"outbounds", 0, "tls", "reality", "short_id"})
		if len(shortIDs.Arr) != 2 || shortIDs.Arr[0].Str != "0000000000000000" || shortIDs.Arr[1].Str != "0000000000000000" {
			t.Fatalf("mode %s short IDs = %#v", mode, shortIDs)
		}
	}
}

func TestHeaderAndHTTPPath(t *testing.T) {
	input := `{"transport":{"path":"/dns-query","headers":{"Authorization":"Bearer SECRET","User-Agent":"Mozilla/5.0"}}}`
	for _, mode := range []Mode{ModeCredentials, ModeShare, ModeStrict} {
		root, _ := sanitize(t, input, mode)
		if got := stringAt(t, root, "transport", "headers", "Authorization"); got != "<REDACTED:AUTHORIZATION>" {
			t.Fatalf("mode %s authorization = %q", mode, got)
		}
		if got := stringAt(t, root, "transport", "headers", "User-Agent"); got != "Mozilla/5.0" {
			t.Fatalf("mode %s user agent = %q", mode, got)
		}
		if got := stringAt(t, root, "transport", "path"); got != "/dns-query" {
			t.Fatalf("mode %s HTTP path = %q", mode, got)
		}
	}
}

func TestSecretKeyPathAndProviderCredentials(t *testing.T) {
	input := `{"private_key_path":"C:\\Users\\Alice\\.ssh\\id_ed25519","api_token":"CF_SECRET","access_key_id":"ALI_ID","access_key_secret":"ALI_SECRET","security_token":"ALI_STS"}`
	for _, mode := range []Mode{ModeCredentials, ModeShare, ModeStrict} {
		root, output := sanitize(t, input, mode)
		if got := stringAt(t, root, "private_key_path"); got != "<REDACTED:PATH>" {
			t.Fatalf("mode %s private key path = %q", mode, got)
		}
		for _, secret := range []string{"CF_SECRET", "ALI_ID", "ALI_SECRET", "ALI_STS", `C:\Users\Alice`} {
			if strings.Contains(output, secret) {
				t.Fatalf("mode %s leaked %q", mode, secret)
			}
		}
	}
}

func TestSensitiveObjectKeysAndCollision(t *testing.T) {
	input := `{"handshake_for_server_name":{"sni-1.redacted.example":{"server":"already.example"},"my-secret-domain.example":{"server":"origin.example"}}}`
	root, output := sanitize(t, input, ModeStrict)
	object, ok := root.At([]any{"handshake_for_server_name"})
	if !ok || object.Kind != jsonx.Object || len(object.Obj) != 2 {
		t.Fatalf("handshake object = %#v", object)
	}
	if object.Obj[0].Key != "sni-1.redacted.example" || object.Obj[1].Key != "sni-1-2.redacted.example" {
		t.Fatalf("rewritten keys = %q, %q", object.Obj[0].Key, object.Obj[1].Key)
	}
	if strings.Contains(output, "my-secret-domain.example") || strings.Contains(output, "origin.example") {
		t.Fatalf("strict object-key redaction leaked input: %s", output)
	}
}

func TestEmbeddedURLCredentialUsesURLParser(t *testing.T) {
	input := `{"url":"https://alice:secret@example.com/api?token=abc&keep=yes"}`
	root, output := sanitize(t, input, ModeCredentials)
	value := stringAt(t, root, "url")
	if strings.Contains(value, "alice") || strings.Contains(value, "secret") || strings.Contains(value, "token=abc") {
		t.Fatalf("URL credential leaked: %q", value)
	}
	if !strings.Contains(value, "example.com/api") || !strings.Contains(value, "keep=yes") {
		t.Fatalf("URL troubleshooting structure lost: %q", value)
	}
	if strings.Contains(output, "abc") {
		t.Fatalf("serialized URL leaked query token: %s", output)
	}
}

func TestTypeAndArrayShapePreserved(t *testing.T) {
	input := `{"short_id":["12345678","abcdef12"],"reserved":[1,2,3],"enabled":true,"port":443,"nothing":null}`
	root, _ := sanitize(t, input, ModeStrict)
	shortID, _ := root.At([]any{"short_id"})
	reserved, _ := root.At([]any{"reserved"})
	if shortID.Kind != jsonx.Array || len(shortID.Arr) != 2 || reserved.Kind != jsonx.Array || len(reserved.Arr) != 3 {
		t.Fatal("array shape changed")
	}
	for _, value := range reserved.Arr {
		if value.Kind != jsonx.Number || value.Num.String() != "0" {
			t.Fatalf("reserved element type/value = %#v", value)
		}
	}
	enabled, _ := root.At([]any{"enabled"})
	port, _ := root.At([]any{"port"})
	nothing, _ := root.At([]any{"nothing"})
	if enabled.Kind != jsonx.Bool || !enabled.Bool || port.Kind != jsonx.Number || port.Num.String() != "443" || nothing.Kind != jsonx.Null {
		t.Fatal("non-sensitive scalar types changed")
	}
}

func TestDeterministicEndpointMapping(t *testing.T) {
	input := `{"outbounds":[{"type":"vless","server":"same.example","server_port":443},{"type":"trojan","server":"other.example","server_port":443},{"type":"vmess","server":"same.example","server_port":8443}]}`
	root, _ := sanitize(t, input, ModeShare)
	first := stringAt(t, root, "outbounds", 0, "server")
	second := stringAt(t, root, "outbounds", 1, "server")
	third := stringAt(t, root, "outbounds", 2, "server")
	if first != "redacted.example" || second != "domain-2.redacted.example" || third != first {
		t.Fatalf("endpoint mapping = %q, %q, %q", first, second, third)
	}
}

func TestECHConfigModeMatrix(t *testing.T) {
	const publicConfig = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	input := `{"outbounds":[{"type":"vless","tls":{"ech":{"enabled":true,"config":["` + publicConfig + `"]}}}]}`
	credentials, _ := sanitize(t, input, ModeCredentials)
	config, ok := credentials.At([]any{"outbounds", 0, "tls", "ech", "config"})
	if !ok || config.Kind != jsonx.Array || len(config.Arr) != 1 || config.Arr[0].Str != publicConfig {
		t.Fatalf("credentials ECH config = %#v", config)
	}
	for _, mode := range []Mode{ModeShare, ModeStrict} {
		root, _ := sanitize(t, input, mode)
		config, ok := root.At([]any{"outbounds", 0, "tls", "ech", "config"})
		if !ok || config.Kind != jsonx.Array || len(config.Arr) != 1 || config.Arr[0].Str != "<REDACTED:FINGERPRINT>" {
			t.Fatalf("mode %s ECH config = %#v", mode, config)
		}
	}
}

func TestTunInboundAddressPreservedInShareMode(t *testing.T) {
	input := `{"inbounds":[{"type":"tun","tag":"tun-in","address":["172.19.0.1/30","fdfe:dcba:9876::1/126"],"dns_address":["172.19.0.2"],"auto_route":true,"strict_route":true,"stack":"mixed"}]}`
	for _, mode := range []Mode{ModeCredentials, ModeShare} {
		root, output := sanitize(t, input, mode)
		address, ok := root.At([]any{"inbounds", 0, "address"})
		if !ok || address.Kind != jsonx.Array || len(address.Arr) != 2 {
			t.Fatalf("mode %s tun address changed: %#v", mode, address)
		}
		if address.Arr[0].Str != "172.19.0.1/30" || address.Arr[1].Str != "fdfe:dcba:9876::1/126" {
			t.Fatalf("mode %s tun address values modified: %s", mode, output)
		}
		dnsAddress, ok := root.At([]any{"inbounds", 0, "dns_address"})
		if !ok || dnsAddress.Kind != jsonx.Array || len(dnsAddress.Arr) != 1 || dnsAddress.Arr[0].Str != "172.19.0.2" {
			t.Fatalf("mode %s tun dns_address modified: %s", mode, output)
		}
	}
}

func TestServerNameRealityVsStandardTLS(t *testing.T) {
	input := `{
		"outbounds": [
			{
				"type": "vless",
				"server": "vps.example.com",
				"tls": {
					"enabled": true,
					"server_name": "itunes.apple.com",
					"reality": {"enabled": true, "public_key": "REALITY_PUB", "short_id": "12345678"}
				}
			},
			{
				"type": "naive",
				"server": "naive-vps.example.com",
				"tls": {
					"enabled": true,
					"server_name": "naive-sni.secret.example"
				}
			},
			{
				"type": "hysteria2",
				"server": "hy2-vps.example.com",
				"tls": {
					"enabled": true,
					"server_name": "hy2-sni.secret.example"
				}
			}
		]
	}`
	credentials, _ := sanitize(t, input, ModeCredentials)
	if got := stringAt(t, credentials, "outbounds", 0, "tls", "server_name"); got != "itunes.apple.com" {
		t.Fatalf("credentials reality server_name = %q", got)
	}
	if got := stringAt(t, credentials, "outbounds", 1, "tls", "server_name"); got != "naive-sni.secret.example" {
		t.Fatalf("credentials naive server_name = %q", got)
	}

	share, _ := sanitize(t, input, ModeShare)
	if got := stringAt(t, share, "outbounds", 0, "tls", "server_name"); got != "itunes.apple.com" {
		t.Fatalf("share reality camouflage SNI changed: %q", got)
	}
	if got := stringAt(t, share, "outbounds", 1, "tls", "server_name"); got == "naive-sni.secret.example" || !strings.Contains(got, "redacted.example") {
		t.Fatalf("share naive server_name not redacted: %q", got)
	}
	if got := stringAt(t, share, "outbounds", 2, "tls", "server_name"); got == "hy2-sni.secret.example" || !strings.Contains(got, "redacted.example") {
		t.Fatalf("share hy2 server_name not redacted: %q", got)
	}

	strict, _ := sanitize(t, input, ModeStrict)
	if got := stringAt(t, strict, "outbounds", 0, "tls", "server_name"); got == "itunes.apple.com" || !strings.Contains(got, "redacted.example") {
		t.Fatalf("strict reality camouflage SNI not redacted: %q", got)
	}
}

func TestCertificateProviderDomainAndReserved(t *testing.T) {
	input := `{
		"certificate_providers": [
			{"type": "acme", "domain": ["my-domain.example", "sub.my-domain.example"]}
		],
		"endpoints": [
			{"type": "wireguard", "peers": [{"public_key": "WARP_PUB", "reserved": [1, 2, 3]}]}
		]
	}`
	credentials, _ := sanitize(t, input, ModeCredentials)
	domains, _ := credentials.At([]any{"certificate_providers", 0, "domain"})
	if domains.Arr[0].Str != "my-domain.example" {
		t.Fatalf("credentials cert domain = %q", domains.Arr[0].Str)
	}
	reserved, _ := credentials.At([]any{"endpoints", 0, "peers", 0, "reserved"})
	if reserved.Arr[0].Num.String() != "1" {
		t.Fatalf("credentials reserved = %#v", reserved)
	}

	share, _ := sanitize(t, input, ModeShare)
	shareDomains, _ := share.At([]any{"certificate_providers", 0, "domain"})
	if shareDomains.Arr[0].Str == "my-domain.example" || !strings.Contains(shareDomains.Arr[0].Str, "redacted.example") {
		t.Fatalf("share cert domain not redacted: %q", shareDomains.Arr[0].Str)
	}
	shareReserved, _ := share.At([]any{"endpoints", 0, "peers", 0, "reserved"})
	for _, value := range shareReserved.Arr {
		if value.Num.String() != "0" {
			t.Fatalf("share reserved not zeroed: %#v", shareReserved)
		}
	}
	warpPub := stringAt(t, share, "endpoints", 0, "peers", 0, "public_key")
	if warpPub != "WARP_PUB" {
		t.Fatalf("share warp public key changed: %q", warpPub)
	}
}
