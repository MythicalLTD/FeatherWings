package environment

import "testing"

func TestVariablesGet(t *testing.T) {
	tests := []struct {
		name      string
		variables Variables
		key       string
		want      string
	}{
		{
			name:      "missing key returns an empty string",
			variables: Variables{},
			key:       "SERVER_VAR",
			want:      "",
		},
		{
			name:      "nil value returns an empty string",
			variables: Variables{"SERVER_VAR": nil},
			key:       "SERVER_VAR",
			want:      "",
		},
		{
			name:      "string value is returned verbatim",
			variables: Variables{"SERVER_VAR": "hello"},
			key:       "SERVER_VAR",
			want:      "hello",
		},
		{
			name:      "int value is formatted in base 10",
			variables: Variables{"SERVER_VAR": 42},
			key:       "SERVER_VAR",
			want:      "42",
		},
		{
			name:      "int32 value is formatted in base 10",
			variables: Variables{"SERVER_VAR": int32(42)},
			key:       "SERVER_VAR",
			want:      "42",
		},
		{
			name:      "int64 value is formatted in base 10",
			variables: Variables{"SERVER_VAR": int64(42)},
			key:       "SERVER_VAR",
			want:      "42",
		},
		{
			name:      "float32 value uses percent-f formatting",
			variables: Variables{"SERVER_VAR": float32(1.5)},
			key:       "SERVER_VAR",
			want:      "1.500000",
		},
		{
			name:      "float64 value uses percent-f formatting",
			variables: Variables{"SERVER_VAR": float64(1.5)},
			key:       "SERVER_VAR",
			want:      "1.500000",
		},
		{
			name:      "bool value is formatted as true or false",
			variables: Variables{"SERVER_VAR": true},
			key:       "SERVER_VAR",
			want:      "true",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.variables.Get(tt.key); got != tt.want {
				t.Fatalf("Variables.Get(%q) = %q, want %q", tt.key, got, tt.want)
			}
		})
	}
}
