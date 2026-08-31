package jsonx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/tailscale/hujson"
)

type Kind uint8

const (
	Null Kind = iota
	Object
	Array
	String
	Number
	Bool
)

type Member struct {
	Key   string
	Value *Value
}

type Value struct {
	Kind Kind
	Obj  []Member
	Arr  []*Value
	Str  string
	Num  json.Number
	Bool bool
}

func Parse(input []byte) (*Value, error) {
	standard, err := hujson.Standardize(stripHashComments(input))
	if err != nil {
		return nil, errors.New("invalid JSON syntax")
	}
	decoder := json.NewDecoder(bytes.NewReader(standard))
	decoder.UseNumber()
	value, err := decodeValue(decoder)
	if err != nil {
		return nil, errors.New("invalid JSON syntax")
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, errors.New("invalid JSON syntax")
	}
	return value, nil
}

func decodeValue(decoder *json.Decoder) (*Value, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case nil:
		return &Value{Kind: Null}, nil
	case bool:
		return &Value{Kind: Bool, Bool: value}, nil
	case string:
		return &Value{Kind: String, Str: value}, nil
	case json.Number:
		return &Value{Kind: Number, Num: value}, nil
	case json.Delim:
		switch value {
		case '{':
			result := &Value{Kind: Object}
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				if keyErr != nil {
					return nil, keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return nil, errors.New("duplicate object key")
				}
				seen[key] = struct{}{}
				child, childErr := decodeValue(decoder)
				if childErr != nil {
					return nil, childErr
				}
				result.Obj = append(result.Obj, Member{Key: key, Value: child})
			}
			if _, err = decoder.Token(); err != nil {
				return nil, err
			}
			return result, nil
		case '[':
			result := &Value{Kind: Array}
			for decoder.More() {
				child, childErr := decodeValue(decoder)
				if childErr != nil {
					return nil, childErr
				}
				result.Arr = append(result.Arr, child)
			}
			if _, err = decoder.Token(); err != nil {
				return nil, err
			}
			return result, nil
		}
	}
	return nil, fmt.Errorf("unsupported JSON token")
}

func (v *Value) Any() any {
	switch v.Kind {
	case Null:
		return nil
	case Bool:
		return v.Bool
	case String:
		return v.Str
	case Number:
		if integer, err := v.Num.Int64(); err == nil {
			return integer
		}
		if floating, err := v.Num.Float64(); err == nil {
			return floating
		}
		return v.Num.String()
	case Array:
		result := make([]any, len(v.Arr))
		for index, child := range v.Arr {
			result[index] = child.Any()
		}
		return result
	case Object:
		result := make(map[string]any, len(v.Obj))
		for _, member := range v.Obj {
			result[member.Key] = member.Value.Any()
		}
		return result
	default:
		panic("unknown JSON kind")
	}
}

func (v *Value) Clone() *Value {
	if v == nil {
		return nil
	}
	clone := *v
	if v.Kind == Object {
		clone.Obj = make([]Member, len(v.Obj))
		for index, member := range v.Obj {
			clone.Obj[index] = Member{Key: member.Key, Value: member.Value.Clone()}
		}
	}
	if v.Kind == Array {
		clone.Arr = make([]*Value, len(v.Arr))
		for index, child := range v.Arr {
			clone.Arr[index] = child.Clone()
		}
	}
	return &clone
}

func (v *Value) MarshalIndent() ([]byte, error) {
	var output bytes.Buffer
	if err := encodeValue(&output, v, 0); err != nil {
		return nil, err
	}
	output.WriteByte('\n')
	return output.Bytes(), nil
}

func encodeValue(output *bytes.Buffer, value *Value, depth int) error {
	if value == nil {
		return errors.New("nil JSON value")
	}
	switch value.Kind {
	case Null:
		output.WriteString("null")
	case Bool:
		output.WriteString(strconv.FormatBool(value.Bool))
	case Number:
		output.WriteString(value.Num.String())
	case String:
		encoded := marshalJSONString(value.Str)
		output.Write(encoded)
	case Array:
		if len(value.Arr) == 0 {
			output.WriteString("[]")
			return nil
		}
		output.WriteString("[\n")
		for index, child := range value.Arr {
			writeIndent(output, depth+1)
			if err := encodeValue(output, child, depth+1); err != nil {
				return err
			}
			if index+1 < len(value.Arr) {
				output.WriteByte(',')
			}
			output.WriteByte('\n')
		}
		writeIndent(output, depth)
		output.WriteByte(']')
	case Object:
		if len(value.Obj) == 0 {
			output.WriteString("{}")
			return nil
		}
		output.WriteString("{\n")
		for index, member := range value.Obj {
			writeIndent(output, depth+1)
			encodedKey := marshalJSONString(member.Key)
			output.Write(encodedKey)
			output.WriteString(": ")
			if err := encodeValue(output, member.Value, depth+1); err != nil {
				return err
			}
			if index+1 < len(value.Obj) {
				output.WriteByte(',')
			}
			output.WriteByte('\n')
		}
		writeIndent(output, depth)
		output.WriteByte('}')
	default:
		return errors.New("unknown JSON kind")
	}
	return nil
}

func marshalJSONString(value string) []byte {
	encoded, _ := json.Marshal(value)
	encoded = bytes.ReplaceAll(encoded, []byte(`\u003c`), []byte("<"))
	encoded = bytes.ReplaceAll(encoded, []byte(`\u003e`), []byte(">"))
	return bytes.ReplaceAll(encoded, []byte(`\u0026`), []byte("&"))
}
func writeIndent(output *bytes.Buffer, depth int) {
	output.WriteString(strings.Repeat("  ", depth))
}

func (v *Value) At(path []any) (*Value, bool) {
	current := v
	for _, segment := range path {
		switch typed := segment.(type) {
		case string:
			if current.Kind != Object {
				return nil, false
			}
			found := false
			for index := range current.Obj {
				if current.Obj[index].Key == typed {
					current = current.Obj[index].Value
					found = true
					break
				}
			}
			if !found {
				return nil, false
			}
		case int:
			if current.Kind != Array || typed < 0 || typed >= len(current.Arr) {
				return nil, false
			}
			current = current.Arr[typed]
		default:
			return nil, false
		}
	}
	return current, true
}

func (v *Value) ParentObject(path []any) (*Value, string, bool) {
	if len(path) == 0 {
		return nil, "", false
	}
	key, ok := path[len(path)-1].(string)
	if !ok {
		return nil, "", false
	}
	parent, ok := v.At(path[:len(path)-1])
	if !ok || parent.Kind != Object {
		return nil, "", false
	}
	return parent, key, true
}

var simpleJSONPathKey = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)

func FormatPath(path []any) string {
	var result strings.Builder
	result.WriteByte('$')
	for _, segment := range path {
		switch typed := segment.(type) {
		case string:
			if simpleJSONPathKey.MatchString(typed) {
				result.WriteByte('.')
				result.WriteString(typed)
			} else {
				encoded, _ := json.Marshal(typed)
				result.WriteByte('[')
				result.Write(encoded)
				result.WriteByte(']')
			}
		case int:
			fmt.Fprintf(&result, "[%d]", typed)
		}
	}
	return result.String()
}
