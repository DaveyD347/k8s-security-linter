import os
import stat
import textwrap

import pytest

from k8slint.scanner import Config, scan

INSECURE = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  namespace: t\nspec:\n  hostPID: true\n  containers:\n    - name: c\n"


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text))
    return path


def test_scans_directory_recursively(tmp_path):
    write(tmp_path / "a" / "pod.yaml", INSECURE)
    write(tmp_path / "b" / "c" / "pod.yml", INSECURE)
    write(tmp_path / "notes.txt", "hostPID: true")
    r = scan([str(tmp_path)], root=tmp_path)
    assert r.files_scanned == 2 and r.resources_scanned == 2
    assert {f.file for f in r.findings} == {"a/pod.yaml", "b/c/pod.yml"}


def test_findings_sorted_by_severity(tmp_path):
    write(tmp_path / "pod.yaml", INSECURE)
    r = scan([str(tmp_path)], root=tmp_path)
    sevs = [f.severity for f in r.findings]
    assert sevs == sorted(sevs, reverse=True)


def test_skip_and_only_rules(tmp_path):
    write(tmp_path / "pod.yaml", INSECURE)
    cfg = Config()
    cfg.merge(only=["KSL004", "KSL003"], skip=["ksl003"])
    r = scan([str(tmp_path)], cfg, root=tmp_path)
    assert {f.rule_id for f in r.findings} == {"KSL004"}


def test_unknown_rule_rejected(tmp_path):
    cfg = Config()
    cfg.merge(skip=["KSL999"])
    with pytest.raises(ValueError, match="KSL999"):
        scan([str(tmp_path)], cfg, root=tmp_path)


def test_exclude_glob(tmp_path):
    write(tmp_path / "keep" / "pod.yaml", INSECURE)
    write(tmp_path / "vendor" / "pod.yaml", INSECURE)
    cfg = Config()
    cfg.merge(exclude=["vendor/*"])
    r = scan([str(tmp_path)], cfg, root=tmp_path)
    assert {f.file for f in r.findings} == {"keep/pod.yaml"}


def test_ignore_annotation(tmp_path):
    write(
        tmp_path / "pod.yaml",
        """\
        apiVersion: v1
        kind: Pod
        metadata:
          name: p
          namespace: t
          annotations:
            k8slint.io/ignore: "KSL004, ksl003"
        spec:
          hostPID: true
          containers:
            - name: c
        """,
    )
    r = scan([str(tmp_path)], root=tmp_path)
    ids = {f.rule_id for f in r.findings}
    assert "KSL004" not in ids and "KSL003" not in ids and "KSL009" in ids
    assert r.suppressed == 2


def test_config_file(tmp_path):
    write(tmp_path / "pod.yaml", INSECURE)
    cfg_path = write(
        tmp_path / ".k8slint.yaml",
        """\
        skip-rules: [KSL010, KSL011]
        severity:
          KSL004: low
        """,
    )
    cfg = Config.from_file(cfg_path)
    r = scan([str(tmp_path / "pod.yaml")], cfg, root=tmp_path)
    ids = {f.rule_id for f in r.findings}
    assert "KSL010" not in ids and "KSL011" not in ids
    assert next(f for f in r.findings if f.rule_id == "KSL004").severity.name == "LOW"


def test_invalid_yaml_is_an_error_not_a_crash(tmp_path):
    write(tmp_path / "bad.yaml", "kind: [oops")
    write(tmp_path / "pod.yaml", INSECURE)
    r = scan([str(tmp_path)], root=tmp_path)
    assert r.errors and r.findings


def test_missing_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan([str(tmp_path / "nope")], root=tmp_path)


# ------------------------------ Helm ---------------------------------------

FAKE_HELM = """#!/bin/sh
# Stand-in for `helm template`: records its args and prints a rendered chart.
echo "$@" > "$(dirname "$0")/helm-args.txt"
cat <<'YAML'
---
# Source: demo/templates/sa.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: k8slint-demo
---
# Source: demo/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: k8slint-demo
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
YAML
"""


@pytest.fixture
def fake_helm(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    helm = bindir / "helm"
    helm.write_text(FAKE_HELM)
    helm.chmod(helm.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    return bindir


def make_chart(root):
    write(root / "charts" / "demo" / "Chart.yaml", "apiVersion: v2\nname: demo\nversion: 0.1.0\n")
    # Raw templates are not valid YAML; the scanner must not parse them directly.
    write(root / "charts" / "demo" / "templates" / "deployment.yaml", "{{- if .Values.x }}\nkind: {{ .Values.kind }}\n{{- end }}\n")
    write(root / "charts" / "demo" / "values.yaml", "x: 1\n")


def test_helm_chart_is_rendered(tmp_path, fake_helm):
    make_chart(tmp_path)
    cfg = Config()
    cfg.merge(helm_values=["prod.yaml"])
    r = scan([str(tmp_path)], cfg, root=tmp_path)
    assert r.charts_rendered == 1 and not r.errors
    priv = [f for f in r.findings if f.rule_id == "KSL001"]
    assert priv and priv[0].file == "charts/demo/templates/deployment.yaml"
    assert priv[0].origin == "helm:charts/demo" and priv[0].line == 1
    assert "--values prod.yaml" in (fake_helm / "helm-args.txt").read_text()


def test_helm_missing_warns(tmp_path, monkeypatch):
    make_chart(tmp_path)
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    r = scan([str(tmp_path)], root=tmp_path)
    assert r.charts_rendered == 0 and not r.errors
    assert any("helm is not installed" in w for w in r.warnings)


def test_helm_disabled(tmp_path, fake_helm):
    make_chart(tmp_path)
    cfg = Config()
    cfg.helm = False
    r = scan([str(tmp_path)], cfg, root=tmp_path)
    assert r.charts_rendered == 0 and r.findings == []
