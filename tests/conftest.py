import textwrap
from pathlib import Path

import pytest

from k8slint.loader import iter_documents
from k8slint.rules import RULES

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


def docs(yaml_text: str, source: str = "test.yaml"):
    return list(iter_documents(textwrap.dedent(yaml_text), source))


def check(rule_id: str, yaml_text: str):
    out = []
    for d in docs(yaml_text):
        out.extend(RULES[rule_id].check(d))
    return out


def pod(spec_body: str, kind: str = "Pod") -> str:
    """Wrap an indented PodSpec body in a minimal manifest."""
    body = textwrap.indent(textwrap.dedent(spec_body), "  ")
    return f"apiVersion: v1\nkind: {kind}\nmetadata:\n  name: p\n  namespace: t\nspec:\n{body}"


@pytest.fixture
def examples():
    return EXAMPLES
