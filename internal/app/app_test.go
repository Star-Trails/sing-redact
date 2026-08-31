package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Star-Trails/sing-box-redact/internal/jsonx"
)

func TestStdoutContainsOnlySanitizedJSON(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := &App{
		Stdin:  strings.NewReader(`{"outbounds":[{"type":"trojan","server":"node.example","server_port":443,"password":"REAL_PASSWORD"}]}`),
		Stdout: &stdout,
		Stderr: &stderr,
	}
	if code := application.Run([]string{"--stdin", "--stdout", "--report"}); code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "REAL_PASSWORD") || strings.Contains(stdout.String(), "Redacted") {
		t.Fatalf("stdout mixed logs or secret: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "<REDACTED:PASSWORD>") {
		t.Fatalf("stdout lacks replacement: %s", stdout.String())
	}
	if _, err := jsonx.Parse(stdout.Bytes()); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
	if !strings.Contains(stderr.String(), "Redacted 2 values") {
		t.Fatalf("report not written to stderr: %s", stderr.String())
	}
}

func TestDefaultOutputAndExplicitOverwrite(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "home-router.json")
	if err := os.WriteFile(inputPath, []byte(`{"api_token":"SECRET_TOKEN"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(directory, "home-router.redacted.json")
	var firstStderr bytes.Buffer
	first := &App{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &firstStderr}
	if code := first.Run([]string{inputPath}); code != 0 {
		t.Fatalf("first exit code = %d, stderr = %s", code, firstStderr.String())
	}
	content, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("default output missing: %v", err)
	}
	if strings.Contains(string(content), "SECRET_TOKEN") {
		t.Fatal("default output leaked token")
	}
	originalTarget := append([]byte(nil), content...)

	var secondStderr bytes.Buffer
	second := &App{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &secondStderr}
	if code := second.Run([]string{inputPath}); code != 2 {
		t.Fatalf("overwrite exit code = %d, stderr = %s", code, secondStderr.String())
	}
	content, err = os.ReadFile(targetPath)
	if err != nil || !bytes.Equal(content, originalTarget) {
		t.Fatal("failed overwrite changed existing target")
	}

	var thirdStderr bytes.Buffer
	third := &App{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &thirdStderr}
	if code := third.Run([]string{inputPath, "--force"}); code != 0 {
		t.Fatalf("forced overwrite exit code = %d, stderr = %s", code, thirdStderr.String())
	}
}

func TestCheckExitCodesAndNoOutputFile(t *testing.T) {
	directory := t.TempDir()
	inputPath := filepath.Join(directory, "config.json")
	if err := os.WriteFile(inputPath, []byte(`{"password":"SECRET"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := &App{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &stderr}
	if code := application.Run([]string{inputPath, "--check"}); code != 1 {
		t.Fatalf("check exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Credentials:") {
		t.Fatalf("check summary = %s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(directory, "config.redacted.json")); !os.IsNotExist(err) {
		t.Fatal("--check created an output file")
	}

	stdout.Reset()
	cleanPath := filepath.Join(directory, "clean.json")
	if err := os.WriteFile(cleanPath, []byte(`{"type":"direct","server_port":443}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := application.Run([]string{cleanPath, "--check"}); code != 0 {
		t.Fatalf("clean check exit code = %d, stdout = %s", code, stdout.String())
	}
}

func TestVersionReportsExactPolicySnapshot(t *testing.T) {
	var stdout bytes.Buffer
	application := &App{Stdin: strings.NewReader(""), Stdout: &stdout, Stderr: &bytes.Buffer{}}
	if code := application.Run([]string{"--version"}); code != 0 {
		t.Fatalf("version exit code = %d", code)
	}
	for _, expected := range []string{"sing-box-redact 0.1.0", "sing-box 1.14.0 testing", PolicyCommit[:12], PolicySchemaDate} {
		if !strings.Contains(stdout.String(), expected) {
			t.Fatalf("version output lacks %q: %s", expected, stdout.String())
		}
	}
}

func TestShareModeAllowsExpectedHighEntropyPublicMaterial(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := &App{
		Stdin: strings.NewReader(`{
			"outbounds": [{
				"type": "vless",
				"tls": {
					"reality": {"public_key": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"},
					"ech": {"config": ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"]}
				}
			}]
		}`),
		Stdout: &stdout,
		Stderr: &stderr,
	}
	if code := application.Run([]string{"--stdin", "--stdout", "--mode", "share"}); code != 0 {
		t.Fatalf("share mode exit code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "<REDACTED:FINGERPRINT>") {
		t.Fatalf("share mode did not redact reality public_key: %s", stdout.String())
	}
	if strings.Contains(stderr.String(), "SUSPICIOUS_HIGH_ENTROPY") {
		t.Fatalf("share mode reported expected public material: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	application.Stdin = strings.NewReader(`{
		"endpoints": [{
			"type": "wireguard",
			"peers": [{"public_key": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"}]
		}]
	}`)
	if code := application.Run([]string{"--stdin", "--stdout", "--mode", "share"}); code != 0 {
		t.Fatalf("wireguard share exit code = %d, stderr = %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "SUSPICIOUS_HIGH_ENTROPY") {
		t.Fatalf("wireguard share reported public key: %s", stderr.String())
	}
}
