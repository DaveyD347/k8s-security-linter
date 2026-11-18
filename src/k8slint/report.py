"""Output formats: human text, JSON, SARIF 2.1.0, GitHub annotations, Markdown summary."""

from __future__ import annotations

import json
import os

from . import __version__
from .rules import RULES, Finding, Severity
from .scanner import ScanResult

TOOL_URI = "https://github.com/DaveyD347/k8s-security-linter"

_COLORS = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_RESET = "\033[0m"


def _counts(findings: list[Finding]) -> dict[str, int]:
    out = {s.name.lower(): 0 for s in sorted(Severity, reverse=True)}
    for f in findings:
        out[f.severity.name.lower()] += 1
    return out


def text(result: ScanResult, color: bool = False) -> str:
    lines: list[str] = []
    for f in result.findings:
        sev = f.severity.name
        if color:
            sev = f"{_COLORS[f.severity]}{sev}{_RESET}"
        cis = f" [CIS {f.cis}]" if f.cis else ""
        lines.append(f"{f.file}:{f.line}: {sev} {f.rule_id} {f.title}{cis}")
        lines.append(f"    {f.resource}: {f.message}")
        lines.append(f"    fix: {f.remediation}")
    for w in result.warnings:
        lines.append(f"warning: {w}")
    for e in result.errors:
        lines.append(f"error: {e}")
    c = _counts(result.findings)
    summary = ", ".join(f"{n} {k}" for k, n in c.items())
    lines.append("")
    lines.append(
        f"Scanned {result.resources_scanned} resources in {result.files_scanned} files"
        f" and {result.charts_rendered} Helm charts: {len(result.findings)} findings ({summary})"
        + (f", {result.suppressed} suppressed" if result.suppressed else "")
    )
    return "\n".join(lines)


def to_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "version": __version__,
            "summary": {
                "files": result.files_scanned,
                "resources": result.resources_scanned,
                "charts": result.charts_rendered,
                "findings": len(result.findings),
                "suppressed": result.suppressed,
                "by_severity": _counts(result.findings),
            },
            "findings": [f.to_dict() for f in result.findings],
            "warnings": result.warnings,
            "errors": result.errors,
        },
        indent=2,
    )


_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
# GitHub code scanning reads `security-severity` (0-10) to rank alerts.
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0"}


def to_sarif(result: ScanResult) -> str:
    rules = []
    for r in RULES.values():
        tags = ["security", "kubernetes"]
        if r.cis:
            tags.append(f"CIS-{r.cis}")
        rules.append(
            {
                "id": r.id,
                "name": r.title.title().replace(" ", "").replace("-", ""),
                "shortDescription": {"text": r.title},
                "fullDescription": {"text": r.description},
                "help": {
                    "text": f"{r.description}\n\nRemediation: {r.remediation}",
                    "markdown": f"{r.description}\n\n**Remediation:** {r.remediation}"
                    + (f"\n\nCIS Kubernetes Benchmark: {r.cis}" if r.cis else ""),
                },
                "defaultConfiguration": {"level": _SARIF_LEVEL[r.severity]},
                "properties": {"tags": tags, "security-severity": _SECURITY_SEVERITY[r.severity]},
            }
        )
    results = []
    for f in result.findings:
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.resource}: {f.message}. {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
                "partialFingerprints": {"k8slint/v1": f"{f.rule_id}:{f.file}:{f.resource}:{f.message}"},
                "properties": {"security-severity": _SECURITY_SEVERITY[f.severity]},
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "k8s-security-linter",
                        "version": __version__,
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _esc_data(s: str) -> str:
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _esc_prop(s: str) -> str:
    return _esc_data(s).replace(":", "%3A").replace(",", "%2C")


def github_annotations(result: ScanResult, limit: int = 50) -> str:
    """Workflow commands that show findings inline on the PR diff."""
    level = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "notice"}
    out = []
    for f in result.findings[:limit]:
        title = _esc_prop(f"{f.rule_id} {f.title}")
        out.append(
            f"::{level[f.severity]} file={_esc_prop(f.file)},line={max(1, f.line)},title={title}::"
            + _esc_data(f"{f.resource}: {f.message}. Fix: {f.remediation}")
        )
    return "\n".join(out)


def markdown_summary(result: ScanResult, fail_on: Severity | None) -> str:
    c = _counts(result.findings)
    icon = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🔵"}
    lines = ["## 🛡️ Kubernetes security lint", ""]
    lines.append(
        f"Scanned **{result.resources_scanned}** resources in {result.files_scanned} files"
        f" and {result.charts_rendered} Helm charts."
    )
    lines.append("")
    lines.append("| Severity | Findings |")
    lines.append("|---|---:|")
    for k, n in c.items():
        lines.append(f"| {icon[k]} {k.title()} | {n} |")
    lines.append("")
    if result.findings:
        lines.append("<details><summary>Findings</summary>")
        lines.append("")
        lines.append("| Rule | Severity | Location | Resource | Issue |")
        lines.append("|---|---|---|---|---|")
        for f in result.findings[:200]:
            msg = f.message.replace("|", "\\|")
            lines.append(f"| `{f.rule_id}` | {f.severity.name.lower()} | `{f.file}:{f.line}` | `{f.resource}` | {msg} |")
        if len(result.findings) > 200:
            lines.append(f"\n_…and {len(result.findings) - 200} more._")
        lines.append("")
        lines.append("</details>")
    else:
        lines.append("No findings. ✅")
    if fail_on is not None:
        lines.append("")
        lines.append(f"Failing threshold: `{fail_on.name.lower()}`")
    return "\n".join(lines) + "\n"


def write_step_summary(md: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(md)
