package jsonx

import (
	"strings"
	"testing"
)

func TestParseJSONCAndPreserveObjectOrder(t *testing.T) {
	input := []byte(`{
		// comment
		"z": 1,
		"a": [true,],
		# hash comment
		"path": "/dns-query",
	}`)
	value, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := []string{value.Obj[0].Key, value.Obj[1].Key, value.Obj[2].Key}; strings.Join(got, ",") != "z,a,path" {
		t.Fatalf("object key order = %v", got)
	}
	output, err := value.MarshalIndent()
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}
	if !strings.Contains(string(output), `"path": "/dns-query"`) {
		t.Fatalf("output lost HTTP path: %s", output)
	}
	if !strings.HasSuffix(string(output), "\n") {
		t.Fatal("output does not end with newline")
	}
	if _, err = Parse(output); err != nil {
		t.Fatalf("serialized output is not valid JSON: %v", err)
	}
}

func TestMarshalDoesNotHTMLEscapePlaceholders(t *testing.T) {
	value := &Value{Kind: Object, Obj: []Member{{Key: "password", Value: &Value{Kind: String, Str: "<REDACTED:PASSWORD>"}}}}
	output, err := value.MarshalIndent()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), `\u003c`) || !strings.Contains(string(output), `<REDACTED:PASSWORD>`) {
		t.Fatalf("placeholder encoding = %s", output)
	}
}
