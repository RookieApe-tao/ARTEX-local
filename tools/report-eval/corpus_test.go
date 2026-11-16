package reporteval

import (
	"bytes"
	"testing"
)

func TestLoadAllowsOnlySyntheticCasesAndExcludesReviewMaterial(t *testing.T) {
	for _, id := range IDs() {
		sample, material, err := Load(id)
		if err != nil {
			t.Fatalf("Load(%q): %v", id, err)
		}
		if sample.ID != id || !sample.Synthetic || len(sample.Evidence) == 0 {
			t.Fatalf("Load(%q) returned incomplete sample", id)
		}
		for _, forbidden := range [][]byte{
			[]byte(`"reference_report"`), []byte(`"review"`), []byte(`"id":"E`),
		} {
			if bytes.Contains(material, forbidden) {
				t.Fatalf("Load(%q) exposed internal material %q", id, forbidden)
			}
		}
	}
	if _, _, err := Load("../idor"); err == nil {
		t.Fatal("Load accepted an identifier outside the fixed sample list")
	}
}
