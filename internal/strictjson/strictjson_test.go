package strictjson

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type doc struct {
	Name  string `json:"name"`
	UID   uint32 `json:"uid"`
	Inner *struct {
		Allow bool `json:"allow"`
	} `json:"inner"`
	List []map[string]int `json:"list"`
}

func TestDecodeAccepts(t *testing.T) {
	var d doc
	if err := Decode([]byte(` {"name":"a","uid":7,"inner":{"allow":true},"list":[{"a":1},{"a":2}]}`+"\n\t"), &d); err != nil {
		t.Fatal(err)
	}
	if d.Name != "a" || d.UID != 7 || !d.Inner.Allow || len(d.List) != 2 {
		t.Fatalf("%+v", d)
	}
	// Map keys are data, not field names: any case is allowed.
	if err := Decode([]byte(`{"list":[{"A":1,"b":2}]}`), &d); err != nil {
		t.Fatal(err)
	}
	// Types that decode themselves (time.Time, text unmarshalers) are
	// leaves, as is decoding into an untyped value.
	var tm struct {
		At time.Time `json:"at"`
	}
	if err := Decode([]byte(`{"at":"2026-01-02T03:04:05Z"}`), &tm); err != nil {
		t.Fatal(err)
	}
	var anyv any
	if err := Decode([]byte(`{"Any":{"Case":1}}`), &anyv); err != nil {
		t.Fatal(err)
	}
	// The same key in sibling objects is not a duplicate.
	if err := Decode([]byte(`{"list":[{"a":1},{"a":1}],"inner":{"allow":false}}`), &d); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeRejects(t *testing.T) {
	for name, in := range map[string]string{
		"duplicate key":              `{"uid":1000,"uid":0}`,
		"duplicate key, other case":  `{"uid":1000,"UID":0}`,
		"duplicate nested key":       `{"inner":{"allow":false,"allow":true}}`,
		"duplicate key in map value": `{"list":[{"a":1,"a":2}]}`,
		"duplicate after nesting":    `{"inner":{"allow":false},"name":"x","Inner":{"allow":true}}`,
		"unknown field":              `{"name":"a","gid":1}`,
		"case-variant field":         `{"Name":"a"}`,
		"case-variant nested field":  `{"inner":{"Allow":true}}`,
		"case-variant in slice":      `{"list":[{"a":1}],"LIST":[]}`,
		"unknown nested field":       `{"inner":{"allow":true,"deny":true}}`,
		"second value":               `{"name":"a"} {"name":"b"}`,
		"trailing garbage":           `{"name":"a"}x`,
		"trailing comma":             `{"name":"a",}`,
		"truncated":                  `{"name":"a"`,
		"unterminated string":        `{"name":"a}`,
		"wrong type":                 `{"uid":"1000"}`,
		"negative uint":              `{"uid":-1}`,
		"overflowing uint":           `{"uid":4294967296}`,
		"fractional uint":            `{"uid":1.5}`,
		"too deep":                   strings.Repeat(`[`, MaxDepth+2) + strings.Repeat(`]`, MaxDepth+2),
		"empty input":                ``,
		"whitespace only":            " \n",
		"comment":                    `{"name":"a"} // x`,
		"single quotes":              `{'name':'a'}`,
		"NaN":                        `{"uid":NaN}`,
	} {
		var d doc
		if err := Decode([]byte(in), &d); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
