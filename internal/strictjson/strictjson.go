// Package strictjson decodes VeriProv's own configuration files strictly.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// Decode decodes data, which must be exactly one JSON value, into v. At every
// depth it rejects duplicate keys and keys that do not exactly name a field of
// the struct they decode into, including keys that match a field only
// case-insensitively, which encoding/json alone would accept.
//
// The types reachable from v must not embed structs.
func Decode(data []byte, v any) error {
	scanner := json.NewDecoder(bytes.NewReader(data))
	if err := checkValue(scanner, reflect.TypeOf(v)); err != nil {
		return err
	}
	if err := requireEnd(scanner); err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func requireEnd(decoder *json.Decoder) error {
	switch _, err := decoder.Token(); {
	case err == nil:
		return errors.New("unexpected data after the JSON value")
	case errors.Is(err, io.EOF):
		return nil
	default:
		return err
	}
}

// checkValue consumes one JSON value, checking the keys of its objects
// against t. A nil t checks only for duplicate keys.
func checkValue(decoder *json.Decoder, t reflect.Type) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	t = target(t)
	switch token {
	case json.Delim('{'):
		fields := jsonFields(t)
		var elem reflect.Type
		if t != nil && t.Kind() == reflect.Map {
			elem = t.Elem()
		}
		seen := make(map[string]bool)
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, _ := token.(string) // object keys are always strings
			if seen[key] {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = true
			valueType := elem
			if fields != nil {
				fieldType, known := fields[key]
				if !known {
					return fmt.Errorf("unknown field %q", key)
				}
				valueType = fieldType
			}
			if err := checkValue(decoder, valueType); err != nil {
				return err
			}
		}
	case json.Delim('['):
		var elem reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			elem = t.Elem()
		}
		for decoder.More() {
			if err := checkValue(decoder, elem); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	_, err = decoder.Token()
	return err
}

// target dereferences pointers and returns nil for types that decode
// themselves.
func target(t reflect.Type) reflect.Type {
	for t != nil {
		if t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType) {
			return nil
		}
		if t.Kind() != reflect.Pointer {
			return t
		}
		t = t.Elem()
	}
	return nil
}

// jsonFields maps the JSON names of t's fields to their types, as
// encoding/json names them. It returns nil when t is not a struct.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	if t == nil || t.Kind() != reflect.Struct {
		return nil
	}
	fields := make(map[string]reflect.Type)
	for field := range t.Fields() {
		tag := field.Tag.Get("json")
		if !field.IsExported() || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
	return fields
}
