package reporteval

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
)

//go:embed cases/*.json
var caseFiles embed.FS

var allowedCases = []string{"concurrency", "idor", "incomplete", "injection", "non-http", "session"}

type Evidence struct {
	Purpose          string `json:"purpose"`
	Source           string `json:"source"`
	RequestComplete  bool   `json:"request_complete,omitempty"`
	ResponseComplete bool   `json:"response_complete,omitempty"`
	Request          string `json:"request,omitempty"`
	Response         string `json:"response,omitempty"`
	Command          string `json:"command,omitempty"`
	Stdout           string `json:"stdout,omitempty"`
	Stderr           string `json:"stderr,omitempty"`
	ExitCode         int    `json:"exit_code,omitempty"`
}

type Facts struct {
	Observations []string `json:"observations"`
	Conditions   []string `json:"conditions"`
	Limitations  []string `json:"limitations"`
	CVSSVector   string   `json:"cvss_vector"`
}

type Case struct {
	SchemaVersion int        `json:"schema_version"`
	ID            string     `json:"id"`
	Kind          string     `json:"kind"`
	Name          string     `json:"name"`
	Synthetic     bool       `json:"synthetic"`
	TestTime      string     `json:"test_time"`
	Target        string     `json:"target"`
	Facts         Facts      `json:"facts"`
	Evidence      []Evidence `json:"evidence"`
}

// IDs returns the fixed, sorted sample identifiers accepted by the evaluator.
func IDs() []string {
	return append([]string(nil), allowedCases...)
}

// Load returns only model-visible sample material. Reference reports, review
// criteria, and evidence labels used internally by the evaluator are excluded.
func Load(id string) (Case, []byte, error) {
	allowed := false
	for _, candidate := range allowedCases {
		if id == candidate {
			allowed = true
			break
		}
	}
	if !allowed {
		return Case{}, nil, fmt.Errorf("unknown report evaluation case")
	}
	raw, err := fs.ReadFile(caseFiles, "cases/"+id+".json")
	if err != nil {
		return Case{}, nil, fmt.Errorf("read report evaluation case: %w", err)
	}
	var sample Case
	if err := json.Unmarshal(raw, &sample); err != nil {
		return Case{}, nil, fmt.Errorf("decode report evaluation case: %w", err)
	}
	if sample.ID != id || !sample.Synthetic || sample.Name == "" || len(sample.Evidence) == 0 {
		return Case{}, nil, fmt.Errorf("report evaluation case is incomplete")
	}
	var material map[string]any
	if err := json.Unmarshal(raw, &material); err != nil {
		return Case{}, nil, fmt.Errorf("decode report evaluation model material: %w", err)
	}
	delete(material, "reference_report")
	delete(material, "review")
	if evidence, ok := material["evidence"].([]any); ok {
		for _, item := range evidence {
			if row, ok := item.(map[string]any); ok {
				delete(row, "id")
			}
		}
	}
	encoded, err := json.Marshal(material)
	if err != nil {
		return Case{}, nil, fmt.Errorf("encode report evaluation case: %w", err)
	}
	return sample, encoded, nil
}
