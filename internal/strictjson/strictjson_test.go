package strictjson

import "testing"

type item struct {
	Name string `json:"name"`
}

type document struct {
	Items []item `json:"items"`
}

func TestDecodeAcceptsKnownFields(t *testing.T) {
	var got document
	if err := Decode([]byte(` {"items":[{"name":"a"},{"name":"b"}]} `), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 2 || got.Items[1].Name != "b" {
		t.Fatalf("decoded %+v", got)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":        `{"items":[],"extra":1}`,
		"nested unknown field": `{"items":[{"name":"a","extra":1}]}`,
		"duplicate key":        `{"items":[],"items":[]}`,
		"nested duplicate key": `{"items":[{"name":"a","name":"b"}]}`,
		"case duplicate key":   `{"items":[],"ITEMS":[]}`,
		"case-folded key":      `{"ITEMS":[]}`,
		"nested case-folded":   `{"items":[{"Name":"a"}]}`,
		"trailing value":       `{"items":[]} {}`,
		"malformed":            `{"items":[}`,
		"empty":                ``,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			var got document
			if err := Decode([]byte(input), &got); err == nil {
				t.Fatalf("accepted %s", input)
			}
		})
	}
}
