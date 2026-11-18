# 🛡️ Kubernetes Security Linter

[![CI](https://github.com/DaveyD347/k8s-security-linter/actions/workflows/ci.yml/badge.svg)](https://github.com/DaveyD347/k8s-security-linter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

A GitHub Action (and CLI) that catches insecure Kubernetes configuration **before it reaches a cluster**. It scans raw manifests and Helm charts for privileged containers, containers running as root, host namespace sharing, overly permissive RBAC, missing resource limits and more. Every rule maps to the [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes) where one applies.

Findings show up three ways in GitHub:

- **Inline annotations** on the pull request diff, pointing at the exact line.
- **A job summary** table with counts by severity.
- **The Security tab** via SARIF upload to code scanning (optional).

## Quick start

```yaml
# .github/workflows/k8s-security.yml
name: Kubernetes security lint
on: [pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: DaveyD347/k8s-security-linter@v1
        with:
          path: k8s
          fail-on: high
```

That's it. The step fails if any finding is `high` or `critical`. A fuller example with Helm values and SARIF upload is in [`docs/example-workflow.yml`](docs/example-workflow.yml).

### Sending results to the Security tab

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v5
  - uses: DaveyD347/k8s-security-linter@v1
    with:
      path: .
      upload-sarif: true
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Files or directories to scan, one per line or comma-separated. Any directory containing `Chart.yaml` is rendered with `helm template`. |
| `fail-on` | `high` | Fail when a finding is at or above `low`, `medium`, `high` or `critical`. Use `none` to report only. |
| `skip-rules` | | Comma-separated rule IDs to skip, e.g. `KSL010,KSL011`. |
| `rules` | | Comma-separated rule IDs to run. Empty runs all rules. |
| `exclude` | | Comma-separated globs to ignore, e.g. `tests/*,vendor/*`. |
| `config` | | Path to a config file. `.k8slint.yaml` is picked up automatically. |
| `helm` | `true` | Render Helm charts before linting. |
| `helm-values` | | Comma-separated values files passed to `helm template`. |
| `sarif-file` | `k8slint-results.sarif` | Where to write SARIF results. |
| `upload-sarif` | `false` | Upload SARIF to code scanning (needs `security-events: write`). |
| `python-version` | | Install a specific Python first. Empty uses the runner's `python3`. |

## Outputs

| Output | Description |
|---|---|
| `findings` | Total number of findings. |
| `critical`, `high`, `medium`, `low` | Findings per severity. |
| `sarif-file` | Path of the SARIF report. |

```yaml
- id: k8slint
  uses: DaveyD347/k8s-security-linter@v1
  with: { fail-on: none }
- run: echo "Found ${{ steps.k8slint.outputs.high }} high-severity issues"
```

## Rules

| ID | Check | Severity | CIS |
|---|---|---|---|
| `KSL001` | Privileged container | critical | 5.2.2 |
| `KSL002` | Privilege escalation allowed | medium | 5.2.6 |
| `KSL003` | Container may run as root | high | 5.2.7 |
| `KSL004` | Host PID namespace shared | high | 5.2.3 |
| `KSL005` | Host IPC namespace shared | high | 5.2.4 |
| `KSL006` | Host network namespace shared | high | 5.2.5 |
| `KSL007` | Dangerous capabilities added | high | 5.2.9 |
| `KSL008` | Capabilities not dropped | low | 5.2.10 |
| `KSL009` | Missing resource limits | medium | – |
| `KSL010` | Missing resource requests | low | – |
| `KSL011` | Writable root filesystem | low | – |
| `KSL012` | Image tag not pinned | medium | – |
| `KSL013` | hostPath volume mounted | high | 5.2.12 |
| `KSL014` | Host port bound | medium | 5.2.13 |
| `KSL015` | Service account token auto-mounted | low | 5.1.6 |
| `KSL016` | No seccomp profile | low | 5.7.2 |
| `KSL017` | Resource in the default namespace | low | 5.7.4 |
| `KSL101` | Wildcard RBAC permissions | high | 5.1.3 |
| `KSL102` | Binding to cluster-admin | critical | 5.1.1 |
| `KSL103` | Read access to Secrets | high | 5.1.2 |
| `KSL104` | Permission to create pods | medium | 5.1.4 |
| `KSL105` | Privilege escalation verbs | high | 5.1.8 |
| `KSL106` | Binding grants access to all authenticated users | critical | 5.1.1 |

Run `k8slint --list-rules` for the same list in your terminal. Each finding includes a one-line fix.

Pod rules apply to every workload kind: `Pod`, `Deployment`, `StatefulSet`, `DaemonSet`, `ReplicaSet`, `ReplicationController`, `Job` and `CronJob`, including init and ephemeral containers. Container settings correctly inherit from the pod-level `securityContext`.

## Suppressing findings

**For one resource**, add an annotation with the rule IDs to ignore (or `all`):

```yaml
metadata:
  name: node-exporter
  annotations:
    k8slint.io/ignore: "KSL004,KSL006"   # needs host PID and network by design
```

**For the whole repository**, add a `.k8slint.yaml` (see [`.k8slint.example.yaml`](.k8slint.example.yaml)):

```yaml
skip-rules: [KSL010, KSL011]
exclude: ["tests/fixtures/*"]
severity:
  KSL012: high        # make unpinned images a blocker
helm-values: [charts/app/values-prod.yaml]
```

## Helm charts

Any directory with a `Chart.yaml` is rendered with `helm template` and the output is linted, so findings reflect the values you actually deploy. Findings are reported against the template file that produced them (from Helm's `# Source:` comments). Raw template files are never parsed as plain YAML, so `{{ }}` syntax won't cause errors.

Helm is preinstalled on GitHub-hosted Ubuntu runners. On other runners add [`azure/setup-helm`](https://github.com/Azure/setup-helm) first; if Helm is missing, charts are skipped with a warning.

## Using the CLI locally

```bash
pip install git+https://github.com/DaveyD347/k8s-security-linter
k8slint k8s/ charts/                 # human-readable output
k8slint . --fail-on medium           # stricter gate
k8slint . -f json > findings.json    # machine-readable
k8slint . --sarif-file results.sarif # for code scanning or IDE viewers
```

Try it on the bundled examples:

```text
$ k8slint examples/manifests/insecure-deployment.yaml
examples/manifests/insecure-deployment.yaml:26: CRITICAL KSL001 Privileged container [CIS 5.2.2]
    Deployment/legacy-api: container 'api' runs privileged
    fix: Remove `securityContext.privileged: true` or set it to false.
examples/manifests/insecure-deployment.yaml:17: HIGH KSL006 Host network namespace shared [CIS 5.2.5]
    Deployment/legacy-api: pod uses the host network (hostNetwork: true)
    fix: Remove `hostNetwork: true` from the pod spec.
...
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage or parse error.

## How it works

1. **Discovery** walks the given paths for `.yaml`/`.yml` files and Helm charts.
2. **Parsing** uses PyYAML's composer to build the YAML node tree (the AST) rather than plain dicts, so every key keeps its line number. Multi-document files, `kind: List` and YAML merge keys are handled.
3. **Rules** are small, independent functions registered with a decorator that carries the rule's severity, CIS reference and remediation. Adding a rule is one function in [`src/k8slint/rules.py`](src/k8slint/rules.py).
4. **Reporting** emits text, JSON, SARIF 2.1.0 (with `security-severity` so GitHub ranks alerts), workflow annotations and a Markdown job summary.

The composite action passes every input through environment variables rather than interpolating it into shell, so a crafted input can't inject commands.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite covers every rule, the loader, Helm rendering (with a stub `helm` binary), the config file and CLI output formats. CI also runs the action against the examples to confirm it passes clean manifests and fails insecure ones.

## Releasing

```bash
git tag -a v1.0.0 -m "v1.0.0" && git push origin v1.0.0
git tag -f v1 && git push -f origin v1   # move the major tag users reference
```

## License

[MIT](LICENSE)
