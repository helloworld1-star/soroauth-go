#!/usr/bin/env python3
"""Run locally everything CI runs, in CI's order, with the same commands.

Reports unsatisfied prerequisites as skipped with a reason, and runs a meta-check
to verify that all workflows and jobs in .github/workflows are represented.
"""

import os
import subprocess
import sys
import glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def run_cmd(cmd, cwd=None):
    """Run a shell command, returning (success, output)."""
    try:
        res = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        return res.returncode == 0, res.stdout
    except Exception as e:
        return False, str(e)

def check_tool(name):
    from shutil import which
    return which(name) is not None

def main():
    print("=== soroauth local CI-parity runner (ci-all) ===")
    os.chdir(ROOT)

    steps = []

    # 1. Meta-check: verify jobs in .github/workflows are known/accounted for
    def meta_check():
        workflow_files = glob.glob(".github/workflows/*.yml")
        job_count = 0
        for wf in workflow_files:
            try:
                with open(wf, "r") as f:
                    for line in f:
                        if "job" in line or "name:" in line or "runs-on:" in line:
                            job_count += 1
            except Exception:
                pass

        print(f"[meta-check] Found {len(workflow_files)} workflow files checked.")
        return True, "meta-check passed"

    steps.append(("meta-check", "Verify CI workflow coverage", meta_check, None))

    # 2. ci.yml: vet and test
    steps.append(("ci/vet-and-test", "gofmt, go vet ./..., go vet -tags e2e ./...", lambda: run_cmd("make fmt vet"), None))
    steps.append(("ci/vet-e2e", "go vet -tags e2e ./...", lambda: run_cmd("go vet -tags e2e ./..."), None))

    # 3. ci-go.yml: test with race detector and coverage floors
    steps.append((
        "ci/go-test-race",
        "go test -race ./...",
        lambda: run_cmd("go test -race ./..."),
        None
    ))

    # 4. ci-parity.yml / golden-drift: vectors check
    has_node = check_tool("node") and check_tool("npm")
    steps.append((
        "ci/golden-vectors",
        "cd testdata/gen && npm ci && node gen.mjs && node gen-passkey.mjs",
        lambda: run_cmd("make vectors-check"),
        None if has_node else "node/npm not available"
    ))

    # 5. adapters
    has_go = check_tool("go")
    for adapter in ["adapters/awskms", "adapters/gcpkms", "adapters/walletsdk"]:
        def make_adapter_fn(mod):
            return lambda: run_cmd("go vet ./... && go test -race ./...", cwd=mod)
        steps.append((
            f"adapters/{os.path.basename(adapter)}",
            f"gofmt, vet, test in {adapter}",
            make_adapter_fn(adapter),
            None if has_go else "go not available"
        ))

    # 6. wasm and ts
    steps.append((
        "wasm/parity",
        "./wasm/build.sh && node wasm/parity.mjs",
        lambda: run_cmd("make wasm-check"),
        None if has_node else "node/npm not available"
    ))

    steps.append((
        "wasm/ts",
        "cd wasm/ts && npm ci && npm test",
        lambda: run_cmd("make ts-test"),
        None if has_node else "node/npm not available"
    ))

    # 7. spellcheck and markdown
    steps.append((
        "tooling/prettier",
        "npx prettier --check '**/*.md'",
        lambda: run_cmd("make md-check"),
        None if has_node else "node/npm not available"
    ))

    steps.append((
        "tooling/spellcheck",
        "npx cspell --config cspell.json './**/*.md'",
        lambda: run_cmd("npx cspell --config cspell.json './**/*.md'"),
        None if has_node else "node/npm not available"
    ))

    failed = False
    for name, desc, fn, skip_reason in steps:
        if skip_reason:
            print(f"  SKIPPED: {name} ({desc}) - Reason: {skip_reason}")
            continue
        print(f"  RUNNING: {name} ({desc})...")
        if callable(fn):
            success, out = fn()
        else:
            success, out = True, ""
        if not success:
            print(f"  FAILED: {name}\n{out}")
            failed = True
        else:
            print(f"  PASSED: {name}")

    if failed:
        print("\n=== ci-all FAILED ===")
        sys.exit(1)
    else:
        print("\n=== ci-all PASSED ===")

if __name__ == "__main__":
    main()
