package api_test

import (
	"os"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestOpenAPIContractIsClosedAndDocumentsRuntimePhases(t *testing.T) {
	b, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatalf("parse OpenAPI: %v", err)
	}
	if doc["openapi"] != "3.1.0" {
		t.Fatalf("openapi=%v", doc["openapi"])
	}
	paths := mustMap(t, doc["paths"])
	for _, path := range []string{"/healthz", "/readyz", "/v1/status", "/v1/zones", "/v1/audit", "/v1/rotations/plan", "/v1/rotations/trigger", "/v1/rotations/resume", "/v1/enrollment/arm"} {
		if _, ok := paths[path]; !ok {
			t.Fatalf("missing path %s", path)
		}
	}
	components := mustMap(t, doc["components"])
	schemas := mustMap(t, components["schemas"])
	for _, name := range []string{"Status", "ZoneStatus", "Workflow", "RotationRequest", "TriggerRequest", "ResumeRequest", "ArmEnrollmentRequest", "Plan"} {
		schema := mustMap(t, schemas[name])
		if schema["additionalProperties"] != false {
			t.Fatalf("schema %s is not closed", name)
		}
	}
	workflow := mustMap(t, schemas["Workflow"])
	properties := mustMap(t, workflow["properties"])
	phase := mustMap(t, properties["phase"])
	got := stringsOf(t, phase["enum"])
	want := []string{"idle", "prepublish", "wait_publish", "activate_new", "wait_new_signature", "deactivate_old", "parent_remove", "wait_parent_remove", "wait_retire", "delete_old", "enroll_discovered", "enroll_wait_publish", "enroll_parent_add", "enroll_wait_parent", "blocked"}
	if !slices.Equal(got, want) {
		t.Fatalf("phase enum=%v want=%v", got, want)
	}
}

func mustMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected object, got %T", v)
	}
	return m
}

func stringsOf(t *testing.T, v any) []string {
	t.Helper()
	values, ok := v.([]any)
	if !ok {
		t.Fatalf("expected array, got %T", v)
	}
	out := make([]string, len(values))
	for i, value := range values {
		var ok bool
		out[i], ok = value.(string)
		if !ok {
			t.Fatalf("enum item %d has type %T", i, value)
		}
	}
	return out
}
