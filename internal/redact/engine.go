package redact

import (
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/Star-Trails/sing-box-redact/internal/jsonx"
	"github.com/Star-Trails/sing-box-redact/internal/report"
	"github.com/itchyny/gojq"
)

type Mode string

const (
	ModeCredentials Mode = "credentials"
	ModeShare       Mode = "share"
	ModeStrict      Mode = "strict"
)

func ParseMode(value string) (Mode, error) {
	mode := Mode(strings.ToLower(value))
	switch mode {
	case ModeCredentials, ModeShare, ModeStrict:
		return mode, nil
	default:
		return "", fmt.Errorf("invalid mode %q; expected credentials, share, or strict", value)
	}
}

//go:embed rules/redact.jq
var redactRule string

type Engine struct {
	code *gojq.Code
}

type Operation struct {
	Kind     string
	Path     []any
	Action   string
	Category string
}

func NewEngine() (*Engine, error) {
	query, err := gojq.Parse(redactRule)
	if err != nil {
		return nil, fmt.Errorf("parse embedded redaction policy: %w", err)
	}
	code, err := gojq.Compile(query, gojq.WithVariables([]string{"$mode"}))
	if err != nil {
		return nil, fmt.Errorf("compile embedded redaction policy: %w", err)
	}
	return &Engine{code: code}, nil
}

func (e *Engine) Plan(root *jsonx.Value, mode Mode) ([]Operation, error) {
	if root == nil || root.Kind != jsonx.Object {
		return nil, errors.New("sing-box configuration root must be an object")
	}
	iterator := e.code.Run(root.Any(), string(mode))
	var output any
	value, ok := iterator.Next()
	if !ok {
		return nil, errors.New("redaction policy returned no result")
	}
	if runErr, isError := value.(error); isError {
		return nil, fmt.Errorf("execute redaction policy: %w", runErr)
	}
	output = value
	if extra, exists := iterator.Next(); exists {
		if runErr, isError := extra.(error); isError {
			return nil, fmt.Errorf("execute redaction policy: %w", runErr)
		}
		return nil, errors.New("redaction policy returned multiple results")
	}
	items, ok := output.([]any)
	if !ok {
		return nil, errors.New("redaction policy returned invalid result")
	}
	operations := make([]Operation, 0, len(items))
	for _, item := range items {
		object, objectOK := item.(map[string]any)
		if !objectOK {
			return nil, errors.New("redaction policy returned invalid operation")
		}
		operation, parseErr := parseOperation(object)
		if parseErr != nil {
			return nil, parseErr
		}
		operations = append(operations, operation)
	}
	return operations, nil
}

func parseOperation(object map[string]any) (Operation, error) {
	kind, kindOK := object["kind"].(string)
	action, actionOK := object["action"].(string)
	category, categoryOK := object["category"].(string)
	rawPath, pathOK := object["path"].([]any)
	if !kindOK || !actionOK || !categoryOK || !pathOK || (kind != "value" && kind != "key") {
		return Operation{}, errors.New("redaction policy returned malformed operation")
	}
	path := make([]any, len(rawPath))
	for index, segment := range rawPath {
		switch typed := segment.(type) {
		case string:
			path[index] = typed
		case int:
			path[index] = typed
		case int64:
			path[index] = int(typed)
		default:
			return Operation{}, errors.New("redaction policy returned malformed path")
		}
	}
	return Operation{Kind: kind, Path: path, Action: action, Category: category}, nil
}

func Apply(root *jsonx.Value, operations []Operation) ([]report.Finding, error) {
	mapper := NewMapper()
	findings := make([]report.Finding, 0, len(operations))
	for _, operation := range operations {
		if operation.Kind != "value" {
			continue
		}
		value, exists := root.At(operation.Path)
		if !exists {
			return nil, fmt.Errorf("redaction path no longer exists: %s", jsonx.FormatPath(operation.Path))
		}
		if mapper.replace(operation.Action, value) {
			findings = append(findings, report.Finding{Category: operation.Category, Path: jsonx.FormatPath(operation.Path)})
		}
	}
	for _, operation := range operations {
		if operation.Kind != "key" {
			continue
		}
		parent, original, exists := root.ParentObject(operation.Path)
		if !exists {
			return nil, fmt.Errorf("redaction key path no longer exists: %s", jsonx.FormatPath(operation.Path))
		}
		memberIndex := -1
		for index := range parent.Obj {
			if parent.Obj[index].Key == original {
				memberIndex = index
				break
			}
		}
		if memberIndex < 0 {
			return nil, fmt.Errorf("redaction key no longer exists: %s", jsonx.FormatPath(operation.Path))
		}
		replacement := mapper.objectKey(operation.Action, original)
		if replacement == original {
			continue
		}
		replacement = collisionSafeKey(parent, memberIndex, replacement)
		parent.Obj[memberIndex].Key = replacement
		findings = append(findings, report.Finding{Category: operation.Category, Path: jsonx.FormatPath(operation.Path)})
	}
	return report.Dedupe(findings), nil
}

func collisionSafeKey(parent *jsonx.Value, memberIndex int, candidate string) string {
	available := func(value string) bool {
		for index, member := range parent.Obj {
			if index != memberIndex && member.Key == value {
				return false
			}
		}
		return true
	}
	if available(candidate) {
		return candidate
	}
	for suffix := 2; ; suffix++ {
		var alternate string
		if strings.HasSuffix(candidate, ".redacted.example") {
			alternate = strings.TrimSuffix(candidate, ".redacted.example") + fmt.Sprintf("-%d.redacted.example", suffix)
		} else {
			alternate = fmt.Sprintf("%s-%d", candidate, suffix)
		}
		if available(alternate) {
			return alternate
		}
	}
}
