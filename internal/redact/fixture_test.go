package redact

import (
	"os"
	"strings"
	"testing"

	"github.com/Star-Trails/sing-redact/internal/audit"
	"github.com/Star-Trails/sing-redact/internal/jsonx"
)

func sanitizeFixture(t *testing.T, mode Mode) (*jsonx.Value, string) {
	t.Helper()
	content, err := os.ReadFile("../../testdata/all-sensitive.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	root, err := jsonx.Parse(content)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	engine, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	operations, err := engine.Plan(root, mode)
	if err != nil {
		t.Fatalf("plan fixture: %v", err)
	}
	findings, err := Apply(root, operations)
	if err != nil {
		t.Fatalf("apply fixture: %v", err)
	}
	if len(findings) < 50 {
		t.Fatalf("fixture produced only %d findings", len(findings))
	}
	output, err := root.MarshalIndent()
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if reparsed, parseErr := jsonx.Parse(output); parseErr != nil || reparsed.Kind != jsonx.Object {
		t.Fatalf("sanitized fixture is not parseable: %v", parseErr)
	}
	return root, string(output)
}

func TestFixtureMandatorySecretsDoNotLeak(t *testing.T) {
	mandatorySecrets := []string{
		"DNS_HEADER_SECRET",
		"bf000d23-0752-40b4-affe-68f7707a9661", "c15942d8-ba5e-49d3-b9b2-55be71a06b39", "20770855-8872-43b1-8695-2a9adf0f2a5b", "ab54b542-25d7-4f29-a212-5943cafb05cc",
		"TLS_SERVER_PRIVATE_KEY", "REALITY_PRIVATE_KEY_SECRET", "12345678", "abcdef12", "deadbeef", "ECH_PRIVATE_KEY_SECRET",
		"SHADOWTLS_IN_PASSWORD", "CLOUDFLARED_TUNNEL_TOKEN", "CCM_USER_TOKEN",
		"WS_API_KEY_SECRET", "TROJAN_PASSWORD", "TUIC_PASSWORD", "HYSTERIA2_PASSWORD", "HYSTERIA2_OBFS_PASSWORD", "ANYTLS_PASSWORD", "SHADOWTLS_PASSWORD", "SHADOWSOCKS_PASSWORD",
		"SSH_PASSWORD", "SSH_PRIVATE_KEY_SECRET", "SSH_KEY_PASSPHRASE", "alice-ssh", "NAIVE_PASSWORD", "NAIVE_HEADER_SECRET", "alice-naive", "SNELL_PSK_SECRET", "SNELL_USER_KEY_SECRET",
		"WIREGUARD_PRIVATE_KEY_SECRET", "WIREGUARD_PSK_SECRET", "TAILSCALE_AUTH_KEY_SECRET",
		"OPENCONNECT_PASSWORD", "OPENCONNECT_SESSION_COOKIE", "OPENCONNECT_TOTP_SECRET", "OPENCONNECT_TOKEN_PASSWORD", "openconnect-device-42", "alice@corp.example",
		"OPENCONNECT_CLIENT_KEY_SECRET", "OPENCONNECT_CLIENT_KEY_PASSWORD", "OPENCONNECT_MCA_KEY_SECRET", "OPENCONNECT_MCA_KEY_PASSWORD", "OPENCONNECT_FORM_SUBMISSION_KEY",
		"OPENVPN_PASSWORD", "OPENVPN_STATIC_KEY_SECRET", "OPENVPN_CLIENT_KEY_SECRET", "OPENVPN_CLIENT_KEY_PASSWORD", "alice-openvpn",
		"ACME_ACCOUNT_PRIVATE_KEY", "ACME_EXTERNAL_KEY_ID", "ACME_EXTERNAL_MAC_KEY", "ALIBABA_ACCESS_KEY_ID", "ALIBABA_ACCESS_KEY_SECRET", "ALIBABA_SECURITY_TOKEN",
		"CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ZONE_TOKEN", "ACMEDNS_PASSWORD", "acmedns-alice", "embedded-password", "ACMEDNS_QUERY_TOKEN", "ORIGIN_CA_API_TOKEN", "ORIGIN_CA_PRIVATE_KEY",
		"SING_BOX_API_SECRET", "HYSTERIA_REALM_TOKEN", "CLASH_API_SECRET", "alice:secret", "URL_QUERY_TOKEN",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.jwtSignatureSecret", "GENERIC_PEM_PRIVATE_KEY_SECRET",
	}
	for _, mode := range []Mode{ModeCredentials, ModeShare, ModeStrict} {
		t.Run(string(mode), func(t *testing.T) {
			root, output := sanitizeFixture(t, mode)
			for _, secret := range mandatorySecrets {
				if strings.Contains(output, secret) {
					t.Errorf("output leaked planted secret %q", secret)
				}
			}
			if findings := audit.Scan(root, string(mode)); len(findings) != 0 {
				t.Fatalf("sanitized fixture failed audit: %#v", findings)
			}
		})
	}
}

func TestFixtureModeDisclosureAndStructure(t *testing.T) {
	credentials, credentialsOutput := sanitizeFixture(t, ModeCredentials)
	if !strings.Contains(credentialsOutput, "node.secret.example") || !strings.Contains(credentialsOutput, `"server": "dns-private"`) {
		t.Fatal("credentials mode removed troubleshooting endpoints or references")
	}
	if got := stringAt(t, credentials, "outbounds", 0, "transport", "path"); got != "/transport-path" {
		t.Fatalf("credentials transport path = %q", got)
	}

	share, shareOutput := sanitizeFixture(t, ModeShare)
	for _, privateValue := range []string{
		"node.secret.example", "vpn.corp.example", "openvpn.corp.example", "wg-peer.secret.example",
		"172.16.10.20", "192.168.1.2", "Ethernet 2", `C:\\Users\\Alice\\rules\\local.srs`,
		"Alice Home WiFi", "alice-laptop", "REALITY_OUT_PUBLIC", "REALITY_PUBLIC_KEY",
		"cert.private.example",
	} {
		if strings.Contains(shareOutput, privateValue) {
			t.Errorf("share output retained %q", privateValue)
		}
	}
	for _, diagnosticValue := range []string{"private.example.com", "private-app.exe", "com.corp.secret", `"server": "dns-private"`, `"outbound": "proxy-vless"`, `"server_port": 443`, `"path": "/transport-path"`} {
		if !strings.Contains(shareOutput, diagnosticValue) {
			t.Errorf("share output removed diagnostic value %q", diagnosticValue)
		}
	}
	if got := stringAt(t, share, "outbounds", 0, "tag"); got != "proxy-vless" {
		t.Fatalf("share tag = %q", got)
	}

	_, strictOutput := sanitizeFixture(t, ModeStrict)
	for _, fingerprint := range []string{
		"private.example.com", "private-app.exe", "com.corp.secret", "OPENVPN_PEER_FINGERPRINT", "REALITY_OUT_PUBLIC", "WIREGUARD_PUBLIC_KEY", "my-secret-domain.example", "nas.home", "Ethernet 2",
	} {
		if strings.Contains(strictOutput, fingerprint) {
			t.Errorf("strict output retained fingerprint %q", fingerprint)
		}
	}
	for _, reference := range []string{`"tag": "proxy-vless"`, `"server": "dns-private"`, `"outbound": "proxy-vless"`, `"final": "proxy-select"`} {
		if !strings.Contains(strictOutput, reference) {
			t.Errorf("strict output broke reference %q", reference)
		}
	}
}

func TestFixtureRedactionIsIdempotent(t *testing.T) {
	for _, mode := range []Mode{ModeCredentials, ModeShare, ModeStrict} {
		t.Run(string(mode), func(t *testing.T) {
			_, first := sanitizeFixture(t, mode)
			root, err := jsonx.Parse([]byte(first))
			if err != nil {
				t.Fatal(err)
			}
			engine, err := NewEngine()
			if err != nil {
				t.Fatal(err)
			}
			operations, err := engine.Plan(root, mode)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Apply(root, operations); err != nil {
				t.Fatal(err)
			}
			second, err := root.MarshalIndent()
			if err != nil {
				t.Fatal(err)
			}
			if first != string(second) {
				t.Fatal("second redaction changed sanitized output")
			}
		})
	}
}
