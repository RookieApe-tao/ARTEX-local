package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestApplyDeliveryReportReasoningOverride(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		body       string
		mark       bool
		wantEffort string
	}{
		{
			name:       "marked Responses API request disables reasoning",
			path:       "/compatible-mode/v1/responses",
			body:       `{"model":"qwen3.8-flash","input":"draft","reasoning":{"effort":"xhigh"}}`,
			mark:       true,
			wantEffort: "none",
		},
		{
			name:       "marked Chat Completions request disables reasoning",
			path:       "/v1/chat/completions",
			body:       `{"model":"qwen3.8-flash","messages":[],"thinking":{"type":"disabled"},"reasoning_effort":"high"}`,
			mark:       true,
			wantEffort: "none",
		},
		{
			name:       "unmarked request preserves configured reasoning",
			path:       "/v1/responses",
			body:       `{"model":"qwen3.8-flash","input":"ordinary","reasoning":{"effort":"xhigh"}}`,
			wantEffort: "xhigh",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.mark {
				ctx = WithDeliveryReportReasoningDisabled(ctx)
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://model.example"+tt.path, strings.NewReader(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			updated, err := applyDeliveryReportReasoningOverride(req)
			if err != nil {
				t.Fatal(err)
			}
			if updated == req && tt.mark {
				t.Fatal("marked completion request was not cloned")
			}
			var payload map[string]json.RawMessage
			if err := json.NewDecoder(updated.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			var effort string
			if tt.path == "/v1/chat/completions" {
				if err := json.Unmarshal(payload["reasoning_effort"], &effort); err != nil {
					t.Fatal(err)
				}
				if _, ok := payload["thinking"]; ok {
					t.Fatal("non-standard thinking field should be removed when effort none is set")
				}
			} else {
				var reasoning struct {
					Effort string `json:"effort"`
				}
				if err := json.Unmarshal(payload["reasoning"], &reasoning); err != nil {
					t.Fatal(err)
				}
				effort = reasoning.Effort
			}
			if effort != tt.wantEffort {
				t.Fatalf("reasoning effort=%q want %q", effort, tt.wantEffort)
			}
		})
	}
}
