import pytest

from k8slint.rules import RULES

from conftest import check, docs, pod

HARDENED = """\
automountServiceAccountToken: false
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  seccompProfile: {type: RuntimeDefault}
containers:
  - name: app
    image: app:1.2.3
    resources:
      requests: {cpu: 10m, memory: 16Mi}
      limits: {cpu: 100m, memory: 64Mi}
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: {drop: [ALL]}
"""


@pytest.mark.parametrize("kind", ["Pod"])
def test_hardened_pod_has_no_findings(kind):
    for d in docs(pod(HARDENED, kind)):
        for r in RULES.values():
            assert list(r.check(d)) == [], r.id


def test_hardened_example_file_passes(examples):
    text = (examples / "manifests" / "secure-deployment.yaml").read_text()
    for d in docs(text):
        for r in RULES.values():
            assert list(r.check(d)) == [], r.id


def test_every_rule_has_metadata():
    for r in RULES.values():
        assert r.id.startswith("KSL") and r.title and r.description and r.remediation


@pytest.mark.parametrize(
    "kind,wrapper",
    [
        ("Deployment", "spec:\n  template:\n    spec:\n{body}"),
        ("StatefulSet", "spec:\n  template:\n    spec:\n{body}"),
        ("DaemonSet", "spec:\n  template:\n    spec:\n{body}"),
        ("Job", "spec:\n  template:\n    spec:\n{body}"),
        ("CronJob", "spec:\n  jobTemplate:\n    spec:\n      template:\n        spec:\n{body}"),
    ],
)
def test_all_workload_kinds_are_inspected(kind, wrapper):
    depth = wrapper.count("\n") * 2
    body = "\n".join(" " * depth + line for line in ["containers:", "  - name: c", "    image: x:1", "    securityContext: {privileged: true}"])
    text = f"apiVersion: apps/v1\nkind: {kind}\nmetadata: {{name: w}}\n" + wrapper.format(body=body)
    found = check("KSL001", text)
    assert len(found) == 1 and found[0].resource == f"{kind}/w"


def test_privileged_points_at_line():
    f = check("KSL001", pod("containers:\n  - name: c\n    image: x:1\n    securityContext:\n      privileged: true\n"))
    assert len(f) == 1
    assert f[0].line == 11
    assert f[0].cis == "5.2.2"


def test_privileged_false_is_fine():
    assert check("KSL001", pod("containers:\n  - name: c\n    securityContext: {privileged: false}\n")) == []


def test_init_containers_are_checked():
    f = check("KSL001", pod("initContainers:\n  - name: setup\n    securityContext: {privileged: true}\ncontainers:\n  - name: c\n"))
    assert "init container 'setup'" in f[0].message


def test_run_as_root_explicit_uid_zero():
    f = check("KSL003", pod("containers:\n  - name: c\n    securityContext: {runAsUser: 0}\n"))
    assert "runAsUser: 0" in f[0].message


def test_run_as_root_inherits_pod_security_context():
    assert check("KSL003", pod("securityContext: {runAsNonRoot: true}\ncontainers:\n  - name: c\n")) == []
    assert check("KSL003", pod("securityContext: {runAsUser: 1000}\ncontainers:\n  - name: c\n")) == []


def test_container_uid_zero_overrides_pod_non_root():
    f = check("KSL003", pod("securityContext: {runAsUser: 1000}\ncontainers:\n  - name: c\n    securityContext: {runAsUser: 0}\n"))
    assert len(f) == 1


def test_missing_run_as_non_root():
    assert len(check("KSL003", pod("containers:\n  - name: c\n"))) == 1


@pytest.mark.parametrize("rid,field", [("KSL004", "hostPID"), ("KSL005", "hostIPC"), ("KSL006", "hostNetwork")])
def test_host_namespaces(rid, field):
    assert len(check(rid, pod(f"{field}: true\ncontainers:\n  - name: c\n"))) == 1
    assert check(rid, pod(f"{field}: false\ncontainers:\n  - name: c\n")) == []


def test_dangerous_capabilities_including_cap_prefix():
    f = check("KSL007", pod("containers:\n  - name: c\n    securityContext:\n      capabilities: {add: [CAP_SYS_ADMIN, CHOWN]}\n"))
    assert "SYS_ADMIN" in f[0].message and "CHOWN" not in f[0].message


def test_harmless_capability_is_fine():
    assert check("KSL007", pod("containers:\n  - name: c\n    securityContext:\n      capabilities: {add: [NET_BIND_SERVICE]}\n")) == []


def test_capabilities_drop_all():
    assert len(check("KSL008", pod("containers:\n  - name: c\n    securityContext:\n      capabilities: {drop: [NET_RAW]}\n"))) == 1
    assert check("KSL008", pod("containers:\n  - name: c\n    securityContext:\n      capabilities: {drop: [all]}\n")) == []


def test_missing_limits_reports_which():
    f = check("KSL009", pod("containers:\n  - name: c\n    resources:\n      limits: {cpu: 1}\n"))
    assert f[0].message.endswith("no memory limit")


def test_requests_default_to_limits():
    assert check("KSL010", pod("containers:\n  - name: c\n    resources:\n      limits: {cpu: 1, memory: 1Gi}\n")) == []


def test_ephemeral_containers_skip_resource_rules():
    text = pod("containers: []\nephemeralContainers:\n  - name: debug\n")
    assert check("KSL009", text) == [] and check("KSL010", text) == []


@pytest.mark.parametrize(
    "image,bad",
    [
        ("nginx", True),
        ("nginx:latest", True),
        ("registry:5000/team/app", True),
        ("registry:5000/team/app:1.0", False),
        ("nginx:1.27", False),
        ("nginx@sha256:" + "a" * 64, False),
    ],
)
def test_image_pinning(image, bad):
    f = check("KSL012", pod(f"containers:\n  - name: c\n    image: {image}\n"))
    assert bool(f) is bad


def test_host_path():
    f = check("KSL013", pod("containers: []\nvolumes:\n  - name: root\n    hostPath: {path: /}\n  - name: tmp\n    emptyDir: {}\n"))
    assert len(f) == 1 and "'/'" in f[0].message


def test_host_port():
    assert len(check("KSL014", pod("containers:\n  - name: c\n    ports:\n      - containerPort: 80\n        hostPort: 8080\n"))) == 1
    assert check("KSL014", pod("containers:\n  - name: c\n    ports:\n      - containerPort: 80\n")) == []


def test_seccomp_unconfined_and_container_override():
    f = check("KSL016", pod("containers:\n  - name: c\n    securityContext:\n      seccompProfile: {type: Unconfined}\n"))
    assert "Unconfined" in f[0].message
    ok = pod("securityContext:\n  seccompProfile: {type: Unconfined}\ncontainers:\n  - name: c\n    securityContext:\n      seccompProfile: {type: RuntimeDefault}\n")
    assert check("KSL016", ok) == []


def test_default_namespace():
    text = "apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n  namespace: default\n"
    f = check("KSL017", text)
    assert f and f[0].line == 5


def test_non_workloads_ignored_by_pod_rules():
    text = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\ndata: {hostPID: 'true'}\n"
    for rid in ("KSL001", "KSL003", "KSL004", "KSL015"):
        assert check(rid, text) == []


# ------------------------------- RBAC --------------------------------------

def role(rules: str, kind: str = "Role") -> str:
    return f"apiVersion: rbac.authorization.k8s.io/v1\nkind: {kind}\nmetadata: {{name: r, namespace: n}}\nrules:\n{rules}"


def test_rbac_wildcards_each_field():
    f = check("KSL101", role("  - apiGroups: ['*']\n    resources: ['*']\n    verbs: ['*']\n", "ClusterRole"))
    assert {x.message for x in f} == {"grants '*' in apiGroups", "grants '*' in resources", "grants '*' in verbs"}


def test_rbac_no_wildcards():
    assert check("KSL101", role("  - apiGroups: ['']\n    resources: [pods]\n    verbs: [get]\n")) == []


def test_cluster_admin_binding():
    text = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata: {name: b}\n"
        "roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}\n"
        "subjects: [{kind: ServiceAccount, name: ci, namespace: ci}]\n"
    )
    assert len(check("KSL102", text)) == 1
    assert check("KSL106", text) == []


def test_binding_to_everyone():
    text = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata: {name: b, namespace: n}\n"
        "roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: view}\n"
        "subjects:\n  - kind: Group\n    name: system:unauthenticated\n"
    )
    assert len(check("KSL106", text)) == 1


def test_secrets_access():
    assert len(check("KSL103", role("  - apiGroups: ['']\n    resources: [secrets]\n    verbs: [list]\n"))) == 1
    # get on a named secret is the recommended least-privilege pattern
    assert check("KSL103", role("  - apiGroups: ['']\n    resources: [secrets]\n    resourceNames: [tls]\n    verbs: [get]\n")) == []
    # but list ignores resourceNames, so it still leaks every secret
    assert len(check("KSL103", role("  - apiGroups: ['']\n    resources: [secrets]\n    resourceNames: [tls]\n    verbs: [get, list]\n"))) == 1


def test_create_pods_and_escalation_verbs():
    assert len(check("KSL104", role("  - apiGroups: ['']\n    resources: [pods]\n    verbs: [create]\n"))) == 1
    assert check("KSL104", role("  - apiGroups: ['']\n    resources: [pods]\n    verbs: [get]\n")) == []
    f = check("KSL105", role("  - apiGroups: [rbac.authorization.k8s.io]\n    resources: [roles]\n    verbs: [impersonate, escalate]\n"))
    assert f[0].message == "grants escalate, impersonate"
