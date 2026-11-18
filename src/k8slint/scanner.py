"""File discovery, Helm rendering, suppressions and the main scan loop."""

from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .loader import Document, LoadError, iter_documents
from .rules import RULES, Finding, Severity, run_rules

IGNORE_ANNOTATION = "k8slint.io/ignore"
YAML_SUFFIXES = {".yaml", ".yml"}
DEFAULT_EXCLUDES = [".git/*", "*/.git/*", "node_modules/*", "*/node_modules/*", ".github/*"]


@dataclass
class Config:
    skip_rules: set[str] = field(default_factory=set)
    only_rules: set[str] | None = None
    exclude: list[str] = field(default_factory=list)
    helm: bool = True
    helm_values: list[str] = field(default_factory=list)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str | os.PathLike) -> "Config":
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"{path}: config must be a mapping")
        cfg = cls()
        cfg.merge(
            skip=raw.get("skip-rules") or [],
            only=raw.get("rules"),
            exclude=raw.get("exclude") or [],
            helm_values=raw.get("helm-values") or [],
        )
        if raw.get("helm") is False:
            cfg.helm = False
        for rid, sev in (raw.get("severity") or {}).items():
            cfg.severity_overrides[str(rid).upper()] = Severity.parse(str(sev))
        return cfg

    def merge(self, skip=(), only=None, exclude=(), helm_values=()) -> None:
        self.skip_rules |= {str(r).strip().upper() for r in skip if str(r).strip()}
        if only:
            self.only_rules = {str(r).strip().upper() for r in only if str(r).strip()}
        self.exclude.extend(exclude)
        self.helm_values.extend(helm_values)

    def enabled_rules(self) -> set[str]:
        unknown = (self.skip_rules | (self.only_rules or set())) - set(RULES)
        if unknown:
            raise ValueError(f"unknown rule id(s): {', '.join(sorted(unknown))}")
        base = self.only_rules if self.only_rules is not None else set(RULES)
        return base - self.skip_rules


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    resources_scanned: int = 0
    charts_rendered: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    suppressed: int = 0


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _excluded(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, p) for p in patterns)


def discover(paths: list[str], cfg: Config, root: Path) -> tuple[list[Path], list[Path]]:
    """Return (yaml_files, chart_dirs). Files inside a chart are left to Helm."""
    files: list[Path] = []
    charts: list[Path] = []
    patterns = DEFAULT_EXCLUDES + cfg.exclude
    for p in paths:
        path = Path(p)
        if path.is_file():
            if path.name == "Chart.yaml":
                charts.append(path.parent)
            else:
                files.append(path)
            continue
        if not path.is_dir():
            raise FileNotFoundError(f"path not found: {p}")
        if (path / "Chart.yaml").is_file():
            charts.append(path)
            continue
        for dirpath, dirnames, filenames in os.walk(path):
            d = Path(dirpath)
            dirnames[:] = sorted(
                n for n in dirnames if not _excluded(_rel(d / n, root) + "/x", patterns)
            )
            if d != path and (d / "Chart.yaml").is_file():
                charts.append(d)
                dirnames[:] = []
                continue
            for name in sorted(filenames):
                f = d / name
                if f.suffix in YAML_SUFFIXES and not _excluded(_rel(f, root), patterns):
                    files.append(f)
    return files, charts


def render_chart(chart: Path, values: list[str], helm_bin: str | None = None) -> str:
    helm = helm_bin or shutil.which("helm")
    if not helm:
        raise RuntimeError("helm is not installed; cannot render chart")
    cmd = [helm, "template", "k8slint", str(chart)]
    for v in values:
        cmd += ["--values", v]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"helm template failed for {chart}: {proc.stderr.strip()}")
    return proc.stdout


def _suppressed_rules(doc: Document) -> set[str]:
    meta = doc.data.get("metadata") or {}
    ann = (meta.get("annotations") or {}).get(IGNORE_ANNOTATION)
    if not ann:
        return set()
    return {r.strip().upper() for r in str(ann).split(",") if r.strip()}


def scan(paths: list[str], cfg: Config | None = None, root: str | os.PathLike = ".") -> ScanResult:
    cfg = cfg or Config()
    root_path = Path(root)
    enabled = cfg.enabled_rules()
    result = ScanResult()
    files, charts = discover(paths, cfg, root_path)

    documents: list[Document] = []
    for f in files:
        rel = _rel(f, root_path)
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            result.errors.append(f"{rel}: cannot read: {exc}")
            continue
        result.files_scanned += 1
        try:
            documents.extend(iter_documents(text, rel))
        except LoadError as exc:
            result.errors.append(str(exc))

    for chart in charts:
        rel_chart = _rel(chart, root_path)
        if not cfg.helm:
            result.warnings.append(f"{rel_chart}: Helm chart skipped (helm disabled)")
            continue
        try:
            rendered = render_chart(chart, cfg.helm_values)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            result.warnings.append(f"{rel_chart}: {exc}")
            continue
        result.charts_rendered += 1
        documents.extend(_split_helm_output(rendered, rel_chart, result))

    for doc in documents:
        result.resources_scanned += 1
        ignored = _suppressed_rules(doc)
        for finding in run_rules(doc, enabled):
            if finding.rule_id in ignored or "ALL" in ignored:
                result.suppressed += 1
                continue
            if finding.rule_id in cfg.severity_overrides:
                finding.severity = cfg.severity_overrides[finding.rule_id]
            result.findings.append(finding)

    result.findings.sort(key=lambda x: (-x.severity, x.file, x.line, x.rule_id))
    return result


def _split_helm_output(rendered: str, chart: str, result: ScanResult) -> list[Document]:
    """Helm prefixes each object with `# Source: chart/templates/x.yaml`.

    We map findings back to that template file so annotations land on the file
    a developer actually edits. Line numbers are relative to the rendered
    object rather than the template, so Helm findings point at line 1.
    """
    docs: list[Document] = []
    chunks = rendered.split("\n---")
    chart_path = Path(chart)
    for chunk in chunks:
        source = chart
        for line in chunk.splitlines():
            if line.startswith("# Source: "):
                tpl = line[len("# Source: "):].strip()
                # tpl looks like "<chart-name>/templates/deployment.yaml"
                parts = Path(tpl).parts
                source = (chart_path / Path(*parts[1:])).as_posix() if len(parts) > 1 else chart
                break
        try:
            for d in iter_documents(chunk, source, origin=f"helm:{chart}"):
                docs.append(d)
        except LoadError as exc:
            result.errors.append(f"{chart} (rendered): {exc}")
    return docs
