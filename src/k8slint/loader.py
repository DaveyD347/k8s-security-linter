"""YAML loading that keeps line numbers.

PyYAML's composer builds a node tree (the YAML AST) where every node carries
its start mark. We walk that tree ourselves so each mapping remembers the line
of every key. Rules use this to point findings at the exact line.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator

import yaml


class LineDict(dict):
    """A dict that also records the 1-based line of each key."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.lines: dict[str, int] = {}
        self.line: int = 0

    def line_of(self, key: str) -> int:
        return self.lines.get(key, self.line)


class LineList(list):
    def __init__(self, *args: Any) -> None:
        super().__init__(*args)
        self.line: int = 0


_SCALAR_LOADER = yaml.SafeLoader("")


def _construct(node: yaml.Node) -> Any:
    if isinstance(node, yaml.MappingNode):
        out = LineDict()
        out.line = node.start_mark.line + 1
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                merged = _construct(value_node)
                items = merged if isinstance(merged, list) else [merged]
                for m in items:
                    if isinstance(m, LineDict):
                        for k, v in m.items():
                            out.setdefault(k, v)
                            out.lines.setdefault(k, m.line_of(k))
                continue
            key = _construct(key_node)
            key = str(key) if not isinstance(key, (str, int, float, bool)) else key
            out[key] = _construct(value_node)
            out.lines[key] = key_node.start_mark.line + 1
        return out
    if isinstance(node, yaml.SequenceNode):
        seq = LineList(_construct(n) for n in node.value)
        seq.line = node.start_mark.line + 1
        return seq
    # Scalars: let PyYAML's safe constructor resolve ints, bools, nulls, etc.
    return _SCALAR_LOADER.construct_object(node, deep=True)


@dataclass
class Document:
    """One Kubernetes object parsed from a file."""

    source: str
    data: LineDict
    index: int = 0
    origin: str | None = None  # e.g. "helm:charts/app" when rendered from a chart
    extra: dict = field(default_factory=dict)

    @property
    def kind(self) -> str:
        return str(self.data.get("kind", ""))

    @property
    def name(self) -> str:
        meta = self.data.get("metadata") or {}
        return str(meta.get("name", "<unnamed>"))

    @property
    def namespace(self) -> str | None:
        meta = self.data.get("metadata") or {}
        ns = meta.get("namespace")
        return str(ns) if ns is not None else None

    @property
    def ref(self) -> str:
        return f"{self.kind}/{self.name}"


class LoadError(Exception):
    pass


def iter_documents(text: str, source: str, origin: str | None = None) -> Iterator[Document]:
    """Yield every Kubernetes object in a YAML stream, flattening `kind: List`."""
    try:
        nodes = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    except yaml.YAMLError as exc:
        raise LoadError(f"{source}: invalid YAML: {exc}") from exc
    for i, node in enumerate(nodes):
        if node is None:
            continue
        data = _construct(node)
        if not isinstance(data, LineDict):
            continue
        if data.get("kind") == "List" and isinstance(data.get("items"), list):
            for item in data["items"]:
                if isinstance(item, LineDict) and "kind" in item:
                    yield Document(source, item, i, origin)
            continue
        if "kind" in data and "apiVersion" in data:
            yield Document(source, data, i, origin)
