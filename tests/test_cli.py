import json

import pytest

from k8slint.cli import main

INSECURE = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n  namespace: t\nspec:\n  containers:\n    - name: c\n      image: app:1\n      securityContext: {privileged: true}\n"
LOW_ONLY = (
    "apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n  namespace: default\n"
)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    (tmp_path / "k8s").mkdir()
    return tmp_path


def test_exit_codes_follow_fail_on(repo):
    (repo / "k8s" / "svc.yaml").write_text(LOW_ONLY)
    assert main(["k8s"]) == 0
    assert main(["k8s", "--fail-on", "low"]) == 1
    assert main(["k8s", "--fail-on", "none"]) == 0


def test_critical_fails_by_default(repo):
    (repo / "k8s" / "pod.yaml").write_text(INSECURE)
    assert main(["k8s"]) == 1


def test_bad_severity_is_usage_error(repo, capsys):
    assert main(["k8s", "--fail-on", "urgent"]) == 2
    assert "unknown severity" in capsys.readouterr().err


def test_invalid_yaml_exit_2(repo):
    (repo / "k8s" / "bad.yaml").write_text("a: [")
    assert main(["k8s", "--fail-on", "none"]) == 2


def test_json_output(repo, capsys):
    (repo / "k8s" / "pod.yaml").write_text(INSECURE)
    main(["k8s", "-f", "json", "--fail-on", "none"])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["by_severity"]["critical"] == 1
    assert data["findings"][0]["rule"] == "KSL001"


def test_sarif_file_is_valid_shape(repo):
    (repo / "k8s" / "pod.yaml").write_text(INSECURE)
    main(["k8s", "--sarif-file", "out/results.sarif", "--fail-on", "none"])
    sarif = json.loads((repo / "out" / "results.sarif").read_text())
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "k8s/pod.yaml"
        assert loc["region"]["startLine"] >= 1
    crit = next(r for r in run["results"] if r["ruleId"] == "KSL001")
    assert crit["level"] == "error" and crit["properties"]["security-severity"] == "9.5"


def test_github_mode_writes_outputs_summary_and_annotations(repo, monkeypatch, capsys):
    (repo / "k8s" / "pod.yaml").write_text(INSECURE)
    out, summary = repo / "gh_out", repo / "gh_summary"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    main(["k8s", "--no-color"])
    stdout = capsys.readouterr().out
    assert "::error file=k8s/pod.yaml,line=10,title=KSL001 Privileged container::" in stdout
    outputs = dict(line.split("=", 1) for line in out.read_text().splitlines())
    assert outputs["critical"] == "1" and int(outputs["findings"]) >= 1
    assert "Kubernetes security lint" in summary.read_text()


def test_config_file_autodetected(repo):
    (repo / "k8s" / "svc.yaml").write_text(LOW_ONLY)
    (repo / ".k8slint.yaml").write_text("skip-rules: [KSL017]\n")
    assert main(["k8s", "--fail-on", "low"]) == 0


def test_list_rules(capsys):
    assert main(["--list-rules"]) == 0
    assert "KSL101" in capsys.readouterr().out


def test_examples_produce_expected_findings(examples, monkeypatch, capsys):
    monkeypatch.chdir(examples.parent)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert main(["examples/manifests", "-f", "json", "--no-helm"]) == 1
    data = json.loads(capsys.readouterr().out)
    rules = {f["rule"] for f in data["findings"]}
    assert {"KSL001", "KSL003", "KSL004", "KSL101", "KSL102", "KSL106"} <= rules
    assert not any(f["file"] == "examples/manifests/secure-deployment.yaml" for f in data["findings"])
