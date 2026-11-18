import pytest

from k8slint.loader import LoadError, iter_documents

from conftest import docs


def test_multi_document_and_line_numbers():
    ds = docs(
        """\
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: a
        ---
        apiVersion: v1
        kind: Pod
        metadata:
          name: b
        spec:
          hostPID: true
        """
    )
    assert [d.ref for d in ds] == ["ConfigMap/a", "Pod/b"]
    assert ds[1].data["spec"].line_of("hostPID") == 11


def test_skips_non_kubernetes_yaml_and_empty_docs():
    ds = docs(
        """\
        ---
        name: just some config
        ---
        apiVersion: v1
        kind: Service
        metadata: {name: s}
        """
    )
    assert [d.kind for d in ds] == ["Service"]


def test_flattens_list_kind():
    ds = docs(
        """\
        apiVersion: v1
        kind: List
        items:
          - apiVersion: v1
            kind: Pod
            metadata: {name: one}
          - apiVersion: v1
            kind: Pod
            metadata: {name: two}
        """
    )
    assert [d.name for d in ds] == ["one", "two"]


def test_merge_keys_are_resolved():
    ds = docs(
        """\
        apiVersion: v1
        kind: Pod
        metadata: {name: m}
        spec:
          base: &base
            hostNetwork: true
          <<: *base
        """
    )
    assert ds[0].data["spec"]["hostNetwork"] is True


def test_scalar_types_resolved():
    ds = docs("apiVersion: v1\nkind: Pod\nmetadata: {name: x}\nspec: {a: 0, b: false, c: null}\n")
    spec = ds[0].data["spec"]
    assert spec["a"] == 0 and spec["b"] is False and spec["c"] is None


def test_invalid_yaml_raises():
    with pytest.raises(LoadError):
        list(iter_documents("kind: [unclosed", "bad.yaml"))
