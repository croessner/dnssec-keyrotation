package workflow_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Execute the workflow's actual Bash step with a registry-free Docker fixture.
func workflowScript(t *testing.T, file, job, id string) string {
	t.Helper()
	data, err := os.ReadFile("../../.github/workflows/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				ID  string `yaml:"id"`
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	var script string
	for _, step := range workflow.Jobs[job].Steps {
		if step.ID == id {
			script = step.Run
		}
	}
	if script == "" {
		t.Fatal("missing comparison step")
	}
	return script
}

func TestStableRefreshComparison(t *testing.T) {
	script := workflowScript(t, "docker-refresh-stable.yaml", "detect", "compare")
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, published, want string
		large                 bool
	}{
		{"unchanged", digest, "false", false},
		{"changed", "sha256:" + strings.Repeat("b", 64), "true", false},
		{"streamed_manifest", digest, "false", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			stub := `#!/bin/bash
set -euo pipefail
if [[ "$*" == "buildx imagetools inspect golang:fixture" ]]; then
  printf 'Digest: %s\n' "$TEST_DIGEST"
  if [[ "$TEST_LARGE" == true ]]; then
    # Force writes after awk has had a chance to read the digest.
    for ((i=0; i<8192; i++)); do printf '%0100d\n' "$i"; done
  fi
elif [[ "$1" == pull ]]; then
  [[ "$2" == "registry.example.test/controller:v1.0.0" ]]
elif [[ "$1 $2" == "image inspect" ]]; then
  [[ "${@: -1}" == "registry.example.test/controller:v1.0.0" ]]
  printf '%s\n' "$TEST_PUBLISHED"
else
  exit 42
fi
`
			for name, contents := range map[string]string{
				"docker":     stub,
				"Dockerfile": "ARG GO_IMAGE=golang:fixture@" + digest + "\n",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(dir, "outputs")
			cmd := exec.Command("bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script)
			cmd.Dir = dir
			large := "false"
			if tc.large {
				large = "true"
			}
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"),
				"IMAGE=registry.example.test/controller", "RELEASE_TAG=v1.0.0",
				"GITHUB_OUTPUT="+output, "TEST_DIGEST="+digest,
				"TEST_PUBLISHED="+tc.published, "TEST_LARGE="+large)
			if result, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("comparison failed: %v\n%s", err, result)
			}
			result, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"should_rebuild=" + tc.want + "\n", "base_image=golang:fixture@" + digest + "\n"} {
				if !strings.Contains(string(result), want) {
					t.Fatalf("missing %q in %s", want, result)
				}
			}
		})
	}
}

func TestStableBuildTags(t *testing.T) {
	script := workflowScript(t, "docker-stable-build.yaml", "metadata", "release")
	for _, tag := range []string{"v1.0.0", "v1.1.0-rc.1"} {
		t.Run(tag, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "outputs")
			cmd := exec.Command("bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script)
			cmd.Dir = "../.."
			cmd.Env = append(os.Environ(), "RELEASE_TAG="+tag, "IMAGE=registry.example.test/controller", "BASE_IMAGE_OVERRIDE=", "REBUILD_SUFFIX=rebuild-20261015", "BUILD_REASON=scheduled-base-refresh", "GITHUB_SHA=HEAD", "GITHUB_REPOSITORY=example/controller", "GITHUB_OUTPUT="+output)
			if result, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("metadata: %v\n%s", err, result)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			tags := strings.Split(strings.SplitN(string(data), "tags<<EOF\n", 2)[1], "\nEOF")[0]
			for _, want := range []string{tag, tag + "-rebuild-20261015", strings.TrimPrefix(tag, "v")} {
				if !strings.Contains("\n"+tags+"\n", "\nregistry.example.test/controller:"+want+"\n") {
					t.Errorf("missing tag %s in %s", want, tags)
				}
			}
			for _, floating := range []string{"v1", "v1.0", "latest"} {
				got := strings.Contains("\n"+tags+"\n", "\nregistry.example.test/controller:"+floating+"\n")
				if got != (tag == "v1.0.0") {
					t.Errorf("unexpected floating tag %s presence=%v for %s", floating, got, tag)
				}
			}
		})
	}
}
