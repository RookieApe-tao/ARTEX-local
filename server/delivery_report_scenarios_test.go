package server

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type deliveryReportScenario struct {
	SchemaVersion int    `json:"schema_version"`
	ID            string `json:"id"`
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	Synthetic     bool   `json:"synthetic"`
	TestTime      string `json:"test_time"`
	Target        string `json:"target"`
	Facts         struct {
		Observations []string `json:"observations"`
		Conditions   []string `json:"conditions"`
		Limitations  []string `json:"limitations"`
		TestTool     string   `json:"test_tool"`
		CVSSVector   string   `json:"cvss_vector"`
	} `json:"facts"`
	Evidence []struct {
		ID               string `json:"id"`
		Purpose          string `json:"purpose"`
		Source           string `json:"source"`
		RequestComplete  bool   `json:"request_complete"`
		ResponseComplete bool   `json:"response_complete"`
		Request          string `json:"request"`
		Response         string `json:"response"`
		Command          string `json:"command"`
		Stdout           string `json:"stdout"`
		Stderr           string `json:"stderr"`
		ExitCode         int    `json:"exit_code"`
	} `json:"evidence"`
	Review struct {
		MustPreserve []string `json:"must_preserve"`
		MustNotClaim []string `json:"must_not_claim"`
		EvidenceGaps []string `json:"evidence_gaps"`
	} `json:"review"`
	ReferenceReport string `json:"reference_report"`
}

func TestDeliveryReportScenarioCorpus(t *testing.T) {
	base := filepath.Join("..", "tools", "report-eval", "cases")
	paths, err := filepath.Glob(filepath.Join(base, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{
		"idor": false, "injection": false, "concurrency": false,
		"session": false, "non-http": false, "incomplete": false,
	}
	if len(paths) != len(expected) {
		t.Fatalf("expected %d synthetic scenarios, got %d", len(expected), len(paths))
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var scenario deliveryReportScenario
			decoder := json.NewDecoder(strings.NewReader(string(raw)))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&scenario); err != nil {
				t.Fatal(err)
			}
			seen, ok := expected[scenario.ID]
			if !ok || seen {
				t.Fatalf("unexpected or duplicate scenario id %q", scenario.ID)
			}
			expected[scenario.ID] = true
			if scenario.SchemaVersion != 1 || !scenario.Synthetic || scenario.Name == "" {
				t.Fatal("scenario must identify itself as a named synthetic fixture")
			}
			if _, err := time.Parse(time.RFC3339, scenario.TestTime); err != nil {
				t.Fatalf("test time has no explicit timezone: %v", err)
			}
			if len(scenario.Facts.Observations) == 0 || len(scenario.Facts.Conditions) == 0 || len(scenario.Facts.Limitations) == 0 ||
				len(scenario.Review.MustPreserve) == 0 || len(scenario.Review.MustNotClaim) == 0 || len(scenario.Review.EvidenceGaps) == 0 {
				t.Fatal("scenario must provide observations, conditions, limits, and human review criteria")
			}
			if filepath.Base(scenario.ReferenceReport) != scenario.ReferenceReport {
				t.Fatal("reference report must stay within the case directory")
			}
			content, err := os.ReadFile(filepath.Join(base, scenario.ReferenceReport))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateDeliveryReportTemplate(string(content), scenario.Facts.CVSSVector); err != nil {
				t.Fatalf("human reference does not satisfy the production save contract: %v", err)
			}
			if len(scenario.Evidence) == 0 {
				t.Fatal("scenario evidence is empty")
			}
			ids := map[string]bool{}
			for _, item := range scenario.Evidence {
				if item.ID == "" || ids[item.ID] || item.Purpose == "" || item.Source == "" {
					t.Fatalf("evidence id, purpose, or source is missing or duplicated: %q", item.ID)
				}
				ids[item.ID] = true
				if regexp.MustCompile(`\b` + regexp.QuoteMeta(item.ID) + `\b`).Match(content) {
					t.Errorf("reference leaks internal evidence id %s instead of a descriptive name", item.ID)
				}
				if !strings.Contains(string(content), "**"+item.Purpose+"**\n") {
					t.Errorf("reference cannot locate material by its descriptive name %q", item.Purpose)
				}
				containsMaterial := func(material string) {
					t.Helper()
					if material != "" && !strings.Contains(string(content), strings.TrimSpace(strings.ReplaceAll(material, "\r\n", "\n"))) {
						t.Errorf("reference omitted original material for %s", item.ID)
					}
				}
				if scenario.Kind == "non_http" {
					if item.Command == "" || item.Request != "" || item.Response != "" {
						t.Fatal("non-HTTP scenario must provide commands without invented HTTP packets")
					}
					containsMaterial(item.Command)
					containsMaterial(item.Stdout)
					containsMaterial(item.Stderr)
					continue
				}
				if scenario.Kind != "http" || scenario.Target != "https://report-eval.invalid" {
					t.Fatal("HTTP fixtures must use the fixed .invalid offline address")
				}
				request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(item.Request)))
				if err != nil {
					t.Fatal(err)
				}
				if request.Host != "report-eval.invalid" || !item.RequestComplete {
					t.Fatal("fixture request must be complete and use the offline host")
				}
				_, readErr := io.ReadAll(request.Body)
				request.Body.Close()
				if readErr != nil {
					t.Fatalf("request body is incomplete: %v", readErr)
				}
				response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(item.Response)), request)
				if err != nil {
					t.Fatal(err)
				}
				_, readErr = io.ReadAll(response.Body)
				response.Body.Close()
				if item.ResponseComplete && readErr != nil {
					t.Fatalf("complete response body is truncated: %v", readErr)
				}
				if !item.ResponseComplete && (scenario.ID != "incomplete" || readErr == nil) {
					t.Fatal("missing body must be explicit and confined to the incomplete-evidence scenario")
				}
				containsMaterial(item.Request)
				containsMaterial(item.Response)
			}
		})
	}
}
