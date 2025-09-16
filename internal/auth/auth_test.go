package auth

import (
	"errors"
	"net/http"
	"testing"
)

type resultFormat struct {
	apiKey string
	err    error
}

var ErrMalformedHeader = errors.New("malformed authorization header")

func TestGetAPIKey(t *testing.T) {
	tests := []http.Header{
		{
			"Authorization": {"ApiKey sk_test_4f8b1c2d9a6e7b3f5a0c8d2e1f4a7b9c"},
		},
		{
			"Authorization": {"ApiKeysk_test_4f8b1c2d9a6e7b3f5a0c8d2e1f4a7b9c"},
		},
		{
			"Authorization": {"sk_test_4f8b1c2d9a6e7b3f5a0c8d2e1f4a7b9c ApiKey"},
		},
		{
			"Authorization": {"ApiKey "},
		},
		{
			"Authorization": {"ApiKey"},
		},
		{
			"Anything": {"hello"},
		},
		{
			"Anything": {"ApiKey sk_test_4f8b1c2d9a6e7b3f5a0c8d2e1f4a7b9c"},
		},
	}
	expected_results := []resultFormat{
		{
			apiKey: "sk_test_4f8b1c2d9a6e7b3f5a0c8d2e1f4a7b9c",
			err:    nil,
		},
		{
			apiKey: "",
			err:    ErrMalformedHeader,
		},
		{
			apiKey: "",
			err:    ErrMalformedHeader,
		},
		{
			apiKey: "",
			err:    ErrMalformedHeader,
		},
		{
			apiKey: "",
			err:    ErrMalformedHeader,
		},
		{
			apiKey: "",
			err:    ErrNoAuthHeaderIncluded,
		},
		{
			apiKey: "",
			err:    ErrNoAuthHeaderIncluded,
		},
	}

	for i, test := range tests {
		apiKey, err := GetAPIKey(test)
		if apiKey != expected_results[i].apiKey {
			t.Fatalf("For %v\nexpected:\napiKey: %v, err: %v\ngot:\napiKey: %v, err: %v", test, expected_results[i].apiKey, expected_results[i].err, apiKey, err)
		}
		if err == nil && expected_results[i].err == nil {
			continue
		}
		if err == nil || expected_results[i].err == nil {
			t.Fatalf("For %v\nexpected:\napiKey: %v, err: %v\ngot:\napiKey: %v, err: %v", test, expected_results[i].apiKey, expected_results[i].err, apiKey, err)
		}
		if err.Error() != expected_results[i].err.Error() {
			t.Fatalf("For %v\nexpected:\napiKey: %v, err: %v\ngot:\napiKey: %v, err: %v", test, expected_results[i].apiKey, expected_results[i].err, apiKey, err)
		}
	}
}
