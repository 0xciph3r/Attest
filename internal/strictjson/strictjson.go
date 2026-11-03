// Package strictjson decodes security-relevant JSON documents without the
// leniencies of encoding/json that let a document mean something other
// than what a reviewer reads.
//
// encoding/json keeps the last of duplicate keys and matches field names
// case-insensitively, so {"uid":1000,"UID":0} decodes as uid 0 and
// {"Allow":true} sets a field a reviewer searching for "allow" misses. It
// also ignores unknown fields and stops after the first value. Decode
// rejects all of these: struct field names must match exactly.
package strictjson

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// MaxDepth bounds nesting so hostile input cannot exhaust the stack.
const MaxDepth = 32

// ErrInvalid is wrapped by every error Decode returns.
var ErrInvalid = errors.New("strictjson: invalid document")

// Decode decodes exactly one JSON value from data into v. It rejects
// duplicate object keys (compared case-insensitively, as encoding/json
// matches fields), struct field names that are unknown or differ in case
// from their tag, nesting deeper than MaxDepth, and any data after the
// value other than whitespace.
func Decode(data []byte, v any) error {
	if err := checkKeys(data, reflect.TypeOf(v)); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return nil
}

func checkKeys(data []byte, t reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walk(dec, t, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	return nil
}

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()
var textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()

// fieldType returns the type of the struct field encoding/json would decode
// key into, requiring an exact name match. Types with custom unmarshalers
// and non-struct types impose no constraint (nil).
func fieldType(t reflect.Type, key string) (reflect.Type, bool) {
	for _, f := range reflect.VisibleFields(t) {
		if !f.IsExported() || f.Anonymous {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		if name == key {
			return f.Type, true
		}
	}
	return nil, false
}

// elem strips pointers and stops at types that decode themselves.
func elem(t reflect.Type) reflect.Type {
	for t != nil {
		if t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType) ||
			t.Implements(textUnmarshalerType) || reflect.PointerTo(t).Implements(textUnmarshalerType) {
			return nil
		}
		if t.Kind() != reflect.Pointer {
			return t
		}
		t = t.Elem()
	}
	return nil
}

func walk(dec *json.Decoder, t reflect.Type, depth int) error {
	t = elem(t)
	if depth > MaxDepth {
		return fmt.Errorf("%w: nested deeper than %d", ErrInvalid, MaxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	switch tok {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return fmt.Errorf("%w: %w", ErrInvalid, err)
			}
			key := strings.ToLower(k.(string))
			if seen[key] {
				return fmt.Errorf("%w: duplicate key %q", ErrInvalid, k)
			}
			seen[key] = true
			var child reflect.Type
			switch {
			case t != nil && t.Kind() == reflect.Struct:
				ft, ok := fieldType(t, k.(string))
				if !ok {
					return fmt.Errorf("%w: unknown field %q (names are case-sensitive)", ErrInvalid, k)
				}
				child = ft
			case t != nil && t.Kind() == reflect.Map:
				child = t.Elem()
			}
			if err := walk(dec, child, depth+1); err != nil {
				return err
			}
		}
	case json.Delim('['):
		var child reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			child = t.Elem()
		}
		for dec.More() {
			if err := walk(dec, child, depth+1); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	if _, err := dec.Token(); err != nil { // closing delimiter
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return nil
}
