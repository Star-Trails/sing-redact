package audit

import (
	"testing"

	"github.com/Star-Trails/sing-box-redact/internal/jsonx"
)

func TestScanFindsResidualSecretsWithoutValues(t *testing.T) {
	root, err := jsonx.Parse([]byte(`{
		"authorization":"Bearer remaining-secret",
		"url":"https://alice:secret@example.com/?token=abc",
		"material":"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
		"jwt":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature",
		"opaque":"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	findings := Scan(root, "share")
	categories := make(map[string]bool)
	for _, finding := range findings {
		categories[finding.Category] = true
		if finding.Path == "" {
			t.Fatal("audit finding lacks JSON path")
		}
	}
	for _, expected := range []string{"AUTHORIZATION_REMAINS", "URL_CREDENTIAL_REMAINS", "PRIVATE_KEY_REMAINS", "JWT_REMAINS", "SUSPICIOUS_HIGH_ENTROPY"} {
		if !categories[expected] {
			t.Errorf("missing audit category %s: %#v", expected, findings)
		}
	}
}

func TestScanAcceptsToolPlaceholders(t *testing.T) {
	root, err := jsonx.Parse([]byte(`{"password":"<REDACTED:PASSWORD>","token":"<REDACTED:TOKEN>","server":"redacted.example","uuid":"00000000-0000-4000-8000-000000000000"}`))
	if err != nil {
		t.Fatal(err)
	}
	if findings := Scan(root, "share"); len(findings) != 0 {
		t.Fatalf("placeholders produced findings: %#v", findings)
	}
}

func TestScanAllowsExpectedPublicMaterialOutsideStrict(t *testing.T) {
	root, err := jsonx.Parse([]byte(`{
		"outbounds": [{
			"tls": {
				"reality": {"public_key": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"},
				"ech": {"config": ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"]}
			}
		}]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if findings := Scan(root, "share"); len(findings) != 0 {
		t.Fatalf("share audit rejected expected public material: %#v", findings)
	}
	if findings := Scan(root, "credentials"); len(findings) != 0 {
		t.Fatalf("credentials audit rejected expected public material: %#v", findings)
	}
	if findings := Scan(root, "strict"); len(findings) != 2 {
		t.Fatalf("strict audit findings = %#v, want two fingerprints", findings)
	}
}
