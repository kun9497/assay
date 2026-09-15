package advisory

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAffected_CrossMappedFrom_RoundTrip(t *testing.T) {
	a := Affected{Ecosystem: "openSUSE Leap:15.6", Name: "curl", CrossMappedFrom: "SLES:15.SP6"}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"cross_mapped_from":"SLES:15.SP6"`) {
		t.Fatalf("field not serialized: %s", b)
	}
	var back Affected
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.CrossMappedFrom != "SLES:15.SP6" {
		t.Fatalf("round-trip lost the field: %q", back.CrossMappedFrom)
	}
}

func TestAffected_CrossMappedFrom_OmitEmpty(t *testing.T) {
	b, _ := json.Marshal(Affected{Ecosystem: "npm", Name: "left-pad"})
	if strings.Contains(string(b), "cross_mapped_from") {
		t.Fatalf("empty field must be omitted: %s", b)
	}
}
