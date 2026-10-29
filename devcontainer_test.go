package soroauth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The dev container installs Go, Node, Rust and stellar-cli at the versions the
// repository pins. These tests keep it honest: it must read the pins rather
// than restate them (a restated pin drifts), it must copy every pin file, the
// CI job that builds it must run whenever a pin moves, and the one pin that had
// no file (stellar-cli) must agree with the places that mention it.

// pinFiles are the files the container reads its versions from.
var pinFiles = []string{
	"go.mod",
	"testdata/gen/package.json",
	"e2e/contracts/rust-toolchain.toml",
	"e2e/contracts/stellar-cli.version",
	"e2e/contracts/stellar-cli.sha256",
	"bindings/rust/rust-toolchain.toml",
	"testdata/parity-rust/rust-toolchain.toml",
}

func readRepoFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestDevcontainerConfigurationIsConsistent(t *testing.T) {
	var cfg struct {
		Build struct {
			Dockerfile string `json:"dockerfile"`
			Context    string `json:"context"`
		} `json:"build"`
		PostCreateCommand string `json:"postCreateCommand"`
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, ".devcontainer/devcontainer.json")), &cfg); err != nil {
		t.Fatalf("devcontainer.json must be plain JSON the tools can read: %v", err)
	}

	if cfg.Build.Context != ".." {
		t.Errorf("build context = %q: the Dockerfile copies pin files from the repository root, so the context must be %q", cfg.Build.Context, "..")
	}
	dockerfile := filepath.ToSlash(filepath.Join(".devcontainer", cfg.Build.Dockerfile))
	text := readRepoFile(t, dockerfile)

	for _, pin := range pinFiles {
		if !regexp.MustCompile("(?m)^COPY " + regexp.QuoteMeta(pin) + " ").MatchString(text) {
			t.Errorf("%s does not COPY the pin file %s, so the image cannot read that version", dockerfile, pin)
		}
		if !strings.Contains(readRepoFile(t, ".devcontainer/Dockerfile.dockerignore"), "!"+pin+"\n") {
			t.Errorf("Dockerfile.dockerignore does not let %s into the build context", pin)
		}
	}

	script := strings.Fields(strings.TrimPrefix(cfg.PostCreateCommand, "bash "))
	if len(script) != 1 {
		t.Fatalf("postCreateCommand = %q, want `bash <script>`", cfg.PostCreateCommand)
	}
	if _, err := os.Stat(script[0]); err != nil {
		t.Errorf("postCreateCommand runs %s: %v", script[0], err)
	}
	for _, name := range []string{"pins.sh", "install-toolchains.sh", "verify.sh"} {
		if _, err := os.Stat(filepath.Join(".devcontainer", name)); err != nil {
			t.Error(err)
		}
	}
}

// TestDevcontainerDoesNotRestateAPin is the point of reading versions from the
// pin files: a version typed into the container's files is a second copy that
// will drift. It looks for the pinned values themselves.
func TestDevcontainerDoesNotRestateAPin(t *testing.T) {
	goVersion := regexp.MustCompile(`(?m)^go (\d+\.\d+\.\d+)$`).FindStringSubmatch(readRepoFile(t, "go.mod"))
	var pkg struct {
		Engines struct {
			Node string `json:"node"`
		} `json:"engines"`
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, "testdata/gen/package.json")), &pkg); err != nil {
		t.Fatal(err)
	}
	pinned := map[string]string{
		"stellar-cli": strings.TrimSpace(readRepoFile(t, "e2e/contracts/stellar-cli.version")),
		"rust":        rustChannel(t, "e2e/contracts/rust-toolchain.toml"),
		"node":        strings.TrimPrefix(pkg.Engines.Node, ">="),
	}
	if goVersion != nil {
		pinned["go"] = goVersion[1]
	}
	for name, value := range pinned {
		if value == "" {
			t.Errorf("could not read the %s pin", name)
		}
	}

	// Every file the container is made of, except the pin files it reads.
	entries, err := os.ReadDir(".devcontainer")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "Dockerfile.dockerignore" {
			continue
		}
		body := readRepoFile(t, ".devcontainer/"+e.Name())
		for name, value := range pinned {
			if value != "" && strings.Contains(body, value) {
				t.Errorf(".devcontainer/%s contains the %s pin %q: read it from the pin file instead, a copy will drift", e.Name(), name, value)
			}
		}
	}
}

func rustChannel(t *testing.T, path string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^channel *= *"([^"]+)"`).FindStringSubmatch(readRepoFile(t, path))
	if m == nil {
		t.Fatalf("%s pins no channel", path)
	}
	return m[1]
}

func TestAllRustToolchainFilesPinOneChannel(t *testing.T) {
	// The container installs every channel it finds, so a straggler would cost
	// a second toolchain download for nothing; the files exist to agree.
	want := rustChannel(t, "e2e/contracts/rust-toolchain.toml")
	for _, path := range pinFiles {
		if strings.HasSuffix(path, "rust-toolchain.toml") {
			if got := rustChannel(t, path); got != want {
				t.Errorf("%s pins Rust %s, e2e/contracts pins %s", path, got, want)
			}
		}
	}
}

func TestStellarCLIPinHasOneSourceAndTheDocsAgreeWithIt(t *testing.T) {
	version := strings.TrimSpace(readRepoFile(t, "e2e/contracts/stellar-cli.version"))
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(version) {
		t.Fatalf("stellar-cli.version = %q, want a full X.Y.Z version", version)
	}

	// The checksums cover this version and both architectures the container
	// supports; a bump without new sums would otherwise fail only at image build.
	sums := readRepoFile(t, "e2e/contracts/stellar-cli.sha256")
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"} {
		line := regexp.MustCompile(`(?m)^[0-9a-f]{64}  stellar-cli-` + regexp.QuoteMeta(version) + `-` + triple + `\.tar\.gz$`)
		if !line.MatchString(sums) {
			t.Errorf("stellar-cli.sha256 has no checksum line for stellar-cli-%s-%s.tar.gz", version, triple)
		}
	}

	// "stellar-cli 28.0.0", "`stellar-cli` 28.0.0", "stellar-cli@28.0.0", and
	// the same wrapped across a line in prose.
	mention := regexp.MustCompile("stellar-cli[`*@\\s]{1,5}(\\d+\\.\\d+\\.\\d+)")
	for _, path := range []string{"Makefile", "CONTRIBUTING.md", "docs/fixture-quickstart.md", "e2e/contracts/rust-toolchain.toml"} {
		matches := mention.FindAllStringSubmatch(readRepoFile(t, path), -1)
		if len(matches) == 0 {
			t.Errorf("%s no longer states the stellar-cli version, so this check protects nothing there", path)
		}
		for _, m := range matches {
			if m[1] != version {
				t.Errorf("%s says stellar-cli %s but e2e/contracts/stellar-cli.version pins %s", path, m[1], version)
			}
		}
	}
}

func TestDevcontainerWorkflowRunsWhenAPinMoves(t *testing.T) {
	var wf struct {
		On struct {
			Push struct {
				Paths []string `yaml:"paths"`
			} `yaml:"push"`
			Schedule []map[string]string `yaml:"schedule"`
		} `yaml:"on"`
	}
	if err := yaml.Unmarshal([]byte(readRepoFile(t, ".github/workflows/ci-devcontainer.yml")), &wf); err != nil {
		t.Fatal(err)
	}

	covered := func(file string) bool {
		for _, p := range wf.On.Push.Paths {
			if p == file || (strings.HasSuffix(p, "/**") && strings.HasPrefix(file, strings.TrimSuffix(p, "**"))) {
				return true
			}
		}
		return false
	}
	for _, pin := range pinFiles {
		if !covered(pin) {
			t.Errorf("a change to %s does not trigger the dev container build", pin)
		}
	}
	for _, file := range []string{".devcontainer/Dockerfile", ".devcontainer/verify.sh", ".github/workflows/ci-devcontainer.yml"} {
		if !covered(file) {
			t.Errorf("a change to %s does not trigger the dev container build", file)
		}
	}
	if len(wf.On.Schedule) == 0 {
		t.Error("the dev container build has no schedule, so upstream drift would go unnoticed")
	}
}

func TestContributingPresentsTheDevcontainerAsAnOption(t *testing.T) {
	text := readRepoFile(t, "CONTRIBUTING.md")
	if !strings.Contains(text, ".devcontainer") {
		t.Fatal("CONTRIBUTING.md does not mention the dev container")
	}
	if !strings.Contains(text, "not required") {
		t.Error("CONTRIBUTING.md must say the dev container is not required: the local instructions stay the reference")
	}
}
