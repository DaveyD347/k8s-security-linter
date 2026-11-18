"""Command-line entry point: `k8slint [paths...]`."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, report
from .rules import RULES, Severity
from .scanner import Config, scan

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _split(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for v in values or []:
        out.extend(x.strip() for x in v.replace("\n", ",").split(",") if x.strip())
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="k8slint",
        description="Security linter for Kubernetes manifests and Helm charts.",
    )
    p.add_argument("paths", nargs="*", default=["."], help="files or directories to scan (default: .)")
    p.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text", help="output format for stdout")
    p.add_argument("--sarif-file", help="also write SARIF results to this file")
    p.add_argument(
        "--fail-on",
        default="high",
        help="exit 1 if any finding is at or above this severity: low, medium, high, critical, or none (default: high)",
    )
    p.add_argument("--skip", action="append", help="comma-separated rule IDs to skip (repeatable)")
    p.add_argument("--rules", action="append", help="comma-separated rule IDs to run (default: all)")
    p.add_argument("--exclude", action="append", help="glob of paths to exclude (repeatable)")
    p.add_argument("--config", help="config file (default: .k8slint.yaml if present)")
    p.add_argument("--helm-values", action="append", help="values file passed to `helm template` (repeatable)")
    p.add_argument("--no-helm", action="store_true", help="do not render Helm charts")
    p.add_argument("--github", action="store_true", help="emit GitHub annotations and a job summary (auto in Actions)")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--list-rules", action="store_true", help="print all rules and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def list_rules() -> str:
    lines = [f"{'ID':<8} {'SEVERITY':<9} {'CIS':<7} TITLE"]
    for r in RULES.values():
        lines.append(f"{r.id:<8} {r.severity.name.lower():<9} {r.cis or '-':<7} {r.title}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.list_rules:
        print(list_rules())
        return EXIT_OK

    try:
        if args.config:
            cfg = Config.from_file(args.config)
        elif Path(".k8slint.yaml").is_file():
            cfg = Config.from_file(".k8slint.yaml")
        else:
            cfg = Config()
        cfg.merge(
            skip=_split(args.skip),
            only=_split(args.rules) or None,
            exclude=_split(args.exclude),
            helm_values=_split(args.helm_values),
        )
        if args.no_helm:
            cfg.helm = False
        fail_on = None if args.fail_on.strip().lower() in ("none", "never", "off", "") else Severity.parse(args.fail_on)
        result = scan(args.paths, cfg)
    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"k8slint: error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if args.format == "json":
        print(report.to_json(result))
    elif args.format == "sarif":
        print(report.to_sarif(result))
    else:
        color = not args.no_color and (sys.stdout.isatty() or os.environ.get("GITHUB_ACTIONS") == "true")
        print(report.text(result, color=color))

    if args.sarif_file:
        Path(args.sarif_file).parent.mkdir(parents=True, exist_ok=True)
        Path(args.sarif_file).write_text(report.to_sarif(result), encoding="utf-8")

    if args.github or os.environ.get("GITHUB_ACTIONS") == "true":
        ann = report.github_annotations(result)
        if ann:
            print(ann)
        report.write_step_summary(report.markdown_summary(result, fail_on))
        out = os.environ.get("GITHUB_OUTPUT")
        if out:
            counts = {s: 0 for s in ("critical", "high", "medium", "low")}
            for f in result.findings:
                counts[f.severity.name.lower()] += 1
            with open(out, "a", encoding="utf-8") as fh:
                fh.write(f"findings={len(result.findings)}\n")
                for k, v in counts.items():
                    fh.write(f"{k}={v}\n")

    if result.errors:
        return EXIT_ERROR
    if fail_on is not None and any(f.severity >= fail_on for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
