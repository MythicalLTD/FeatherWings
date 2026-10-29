package parser

import "testing"

func TestSetValueWithSjsonTypes(t *testing.T) {
	cases := []struct {
		name, doc, replace, value, want string
	}{
		{"new key number", `{}`, `"x"`, "25565", `{"p":25565}`},
		{"new key bool", `{}`, `"x"`, "true", `{"p":true}`},
		{"new key lax number stays string", `{}`, `"x"`, "007", `{"p":"007"}`},
		{"new key version stays string", `{}`, `"x"`, "1.20.1", `{"p":"1.20.1"}`},
		{"existing string kept string", `{"p":"a"}`, `"x"`, "123", `{"p":"123"}`},
		{"existing number bad value", `{"p":1}`, `"x"`, "25565x", `{"p":"25565x"}`},
		{"existing number large int", `{"p":1}`, `"x"`, "9007199254740993", `{"p":9007199254740993}`},
		{"explicit number", `{"p":"a"}`, `5`, "42", `{"p":42}`},
		{"explicit number invalid", `{"p":"a"}`, `5`, "+5", `{"p":"+5"}`},
		{"explicit bool", `{"p":"a"}`, `true`, "false", `{"p":false}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfr := replacement(t, `{"match":"p","replace_with":`+c.replace+`}`)
			got, err := cfr.setValueWithSjson(c.doc, "p", c.value)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Fatalf("got %s, want %s", got, c.want)
			}
		})
	}
}
