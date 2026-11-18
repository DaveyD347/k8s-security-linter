"""Security rules.

Each rule is a function that takes a Document and yields Findings. Rules are
registered with the @rule decorator, which also holds the metadata shown in
reports (severity, CIS Kubernetes Benchmark reference, remediation).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, Iterator

from .loader import Document, LineDict


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity '{value}' (choose from {choices})") from exc


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    cis: str | None
    check: Callable[[Document], Iterator["Finding"]]


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    title: str
    message: str
    file: str
    line: int
    resource: str
    remediation: str
    cis: str | None = None
    origin: str | None = None

    def to_dict(self) -> dict:
        return {
            "rule": self.rule_id,
            "severity": self.severity.name.lower(),
            "title": self.title,
            "message": self.message,
            "file": self.file,
            "line": self.line,
            "resource": self.resource,
            "remediation": self.remediation,
            "cis": self.cis,
            "origin": self.origin,
        }


RULES: dict[str, Rule] = {}


def rule(id: str, title: str, severity: Severity, description: str, remediation: str, cis: str | None = None):
    def decorator(fn: Callable[[Document], Iterator[tuple[str, int]]]):
        def check(doc: Document) -> Iterator[Finding]:
            for message, line in fn(doc):
                yield Finding(
                    rule_id=id,
                    severity=severity,
                    title=title,
                    message=message,
                    file=doc.source,
                    # Rendered Helm output has no stable mapping to template lines.
                    line=1 if doc.origin else (line or doc.data.line),
                    resource=doc.ref,
                    remediation=remediation,
                    cis=cis,
                    origin=doc.origin,
                )

        RULES[id] = Rule(id, title, severity, description, remediation, cis, check)
        return fn

    return decorator


# --------------------------------------------------------------------------
# Helpers for workloads
# --------------------------------------------------------------------------

WORKLOAD_KINDS = {
    "Pod",
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "ReplicaSet",
    "ReplicationController",
    "Job",
    "CronJob",
}

CONTAINER_FIELDS = ("initContainers", "containers", "ephemeralContainers")


def _get(d, *path):
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def pod_spec(doc: Document) -> LineDict | None:
    """Return the PodSpec for any workload kind, or None."""
    kind = doc.kind
    if kind not in WORKLOAD_KINDS:
        return None
    if kind == "Pod":
        spec = _get(doc.data, "spec")
    elif kind == "CronJob":
        spec = _get(doc.data, "spec", "jobTemplate", "spec", "template", "spec")
    else:
        spec = _get(doc.data, "spec", "template", "spec")
    return spec if isinstance(spec, LineDict) else None


def pod_metadata(doc: Document) -> dict:
    if doc.kind == "Pod":
        return doc.data.get("metadata") or {}
    if doc.kind == "CronJob":
        return _get(doc.data, "spec", "jobTemplate", "spec", "template", "metadata") or {}
    return _get(doc.data, "spec", "template", "metadata") or {}


def containers(spec: LineDict) -> Iterator[tuple[str, LineDict]]:
    for field in CONTAINER_FIELDS:
        for c in spec.get(field) or []:
            if isinstance(c, LineDict):
                yield field, c


def _cname(field: str, c: dict) -> str:
    label = {"initContainers": "init container", "ephemeralContainers": "ephemeral container"}.get(field, "container")
    return f"{label} '{c.get('name', '?')}'"


def _sc(c: dict) -> LineDict:
    sc = c.get("securityContext")
    return sc if isinstance(sc, LineDict) else LineDict()


def _effective(c: dict, spec: dict, key: str):
    """Container securityContext value, falling back to the pod securityContext."""
    csc = c.get("securityContext") or {}
    if key in csc:
        return csc[key]
    psc = spec.get("securityContext") or {}
    return psc.get(key)


# --------------------------------------------------------------------------
# Pod security rules
# --------------------------------------------------------------------------


@rule(
    "KSL001",
    "Privileged container",
    Severity.CRITICAL,
    "Privileged containers have full access to the host's devices and kernel capabilities.",
    "Remove `securityContext.privileged: true` or set it to false.",
    cis="5.2.2",
)
def privileged(doc):
    spec = pod_spec(doc)
    if spec is None:
        return
    for field, c in containers(spec):
        sc = _sc(c)
        if sc.get("privileged") is True:
            yield f"{_cname(field, c)} runs privileged", sc.line_of("privileged")


@rule(
    "KSL002",
    "Privilege escalation allowed",
    Severity.MEDIUM,
    "Without allowPrivilegeEscalation: false, a process can gain more privileges than its parent (e.g. via setuid binaries).",
    "Set `securityContext.allowPrivilegeEscalation: false` on every container.",
    cis="5.2.6",
)
def privilege_escalation(doc):
    spec = pod_spec(doc)
    if spec is None:
        return
    for field, c in containers(spec):
        sc = _sc(c)
        if sc.get("allowPrivilegeEscalation") is not False:
            line = sc.line_of("allowPrivilegeEscalation") if "allowPrivilegeEscalation" in sc else c.line
            yield f"{_cname(field, c)} does not set allowPrivilegeEscalation: false", line


@rule(
    "KSL003",
    "Container may run as root",
    Severity.HIGH,
    "Containers running as UID 0 make container escapes far more damaging.",
    "Set `runAsNonRoot: true` and a non-zero `runAsUser` in the pod or container securityContext.",
    cis="5.2.7",
)
def run_as_root(doc):
    spec = pod_spec(doc)
    if spec is None:
        return
    for field, c in containers(spec):
        uid = _effective(c, spec, "runAsUser")
        non_root = _effective(c, spec, "runAsNonRoot")
        sc = _sc(c)
        if uid == 0:
            line = sc.line_of("runAsUser") if "runAsUser" in sc else (spec.get("securityContext") or LineDict()).line_of("runAsUser")
            yield f"{_cname(field, c)} explicitly runs as root (runAsUser: 0)", line
        elif non_root is not True and not (isinstance(uid, int) and uid > 0):
            yield f"{_cname(field, c)} does not set runAsNonRoot: true or a non-zero runAsUser", c.line


@rule(
    "KSL004",
    "Host PID namespace shared",
    Severity.HIGH,
    "hostPID lets the pod see and signal every process on the node.",
    "Remove `hostPID: true` from the pod spec.",
    cis="5.2.3",
)
def host_pid(doc):
    spec = pod_spec(doc)
    if spec is not None and spec.get("hostPID") is True:
        yield "pod shares the host PID namespace (hostPID: true)", spec.line_of("hostPID")


@rule(
    "KSL005",
    "Host IPC namespace shared",
    Severity.HIGH,
    "hostIPC lets the pod read shared memory of processes on the node.",
    "Remove `hostIPC: true` from the pod spec.",
    cis="5.2.4",
)
def host_ipc(doc):
    spec = pod_spec(doc)
    if spec is not None and spec.get("hostIPC") is True:
        yield "pod shares the host IPC namespace (hostIPC: true)", spec.line_of("hostIPC")


@rule(
    "KSL006",
    "Host network namespace shared",
    Severity.HIGH,
    "hostNetwork exposes the node's network interfaces and bypasses NetworkPolicies.",
    "Remove `hostNetwork: true` from the pod spec.",
    cis="5.2.5",
)
def host_network(doc):
    spec = pod_spec(doc)
    if spec is not None and spec.get("hostNetwork") is True:
        yield "pod uses the host network (hostNetwork: true)", spec.line_of("hostNetwork")


DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_RAW", "DAC_READ_SEARCH", "BPF", "SYS_RAWIO"}


@rule(
    "KSL007",
    "Dangerous capabilities added",
    Severity.HIGH,
    "Capabilities like SYS_ADMIN or NET_RAW give containers powers close to root on the host.",
    "Remove the capability from `securityContext.capabilities.add`; add only what the workload truly needs.",
    cis="5.2.9",
)
def dangerous_caps(doc):
    spec = pod_spec(doc)
    if spec is None:
        return
    for field, c in containers(spec):
        caps = _sc(c).get("capabilities") or LineDict()
        added = caps.get("add") or []
        bad = sorted({str(x).upper().removeprefix("CAP_") for x in added} & DANGEROUS_CAPS)
        if bad:
            yield f"{_cname(field, c)} adds dangerous capabilities: {', '.join(bad)}", caps.line_of("add")


@rule(
    "KSL008",
    "Capabilities not dropped",
    Severity.LOW,
    "Containers start with a default capability set. Dropping ALL and adding back only what is needed shrinks the attack surface.",
    "Set `securityContext.capabilities.drop: [\"ALL\"]`.",
    cis="5.2.10",
)
def caps_not_dropped(doc):
    spec = pod_spec(doc)
    if spec is None:
        return
    for field, c in containers(spec):
        caps = _sc(c).get("capabilities") or {}
        dropped = {str(x).upper() for x in caps.get("drop") or []}
        if "ALL" not in dropped:
            yield f"{_cname(field, c)} does not drop ALL capabilities", c.line


@rule(
    "KSL009",
    "Missing resource limits",
    Severity.MEDIUM,
    "Without CPU and memory limits, one container can starve the node and its neighbours (a denial-of-service risk).",
    "Set `resources.limits.cpu` and `resources.limits.memory` on every container.",
)
def missing_limits(doc):
    spec = pod_spec(doc)
    if spec is None:
        return
    for field, c in containers(spec):
        if field == "ephemeralContainers":
            continue  # ephemeral containers cannot set resources
        limits = _get(c, "resources", "limits") or {}
        missing = [r for r in ("cpu", "memory") if r not in limits]
        if missing:
            yield f"{_cname(field, c)} has no {' or '.join(missing)} limit", c.line


@rule(
    "KSL010",
    "Missing resource requests",
    Severity.LOW,
    "Without requests the scheduler cannot place the pod sensibly and it is first to be evicted.",
    "Set `resources.requests.cpu` and `resources.requests.memory` on every container.",
)
def missing_requests(doc):
    spec = pod_spec(doc)
    if spec is None:
        return
    for field, c in containers(spec):
        if field == "ephemeralContainers":
            continue
        limits = _get(c, "resources", "limits") or {}
        requests = _get(c, "resources", "requests") or {}
        # Kubernetes defaults requests to limits when only limits are set.
        missing = [r for r in ("cpu", "memory") if r not in requests and r not in limits]
        if missing:
            yield f"{_cname(field, c)} has no {' or '.join(missing)} request", c.line


@rule(
    "KSL011",
    "Writable root filesystem",
    Severity.LOW,
    "A writable root filesystem lets an attacker drop tools or modify binaries inside the container.",
    "Set `securityContext.readOnlyRootFilesystem: true` and mount an emptyDir for paths that must be writable.",
)
def writable_rootfs(doc):
    spec = pod_spec(doc)
    if spec is None:
        return
    for field, c in containers(spec):
        if _sc(c).get("readOnlyRootFilesystem") is not True:
            yield f"{_cname(field, c)} does not set readOnlyRootFilesystem: true", c.line


@rule(
    "KSL012",
    "Image tag not pinned",
    Severity.MEDIUM,
    "Images with no tag or the 'latest' tag can change underneath you, which breaks reproducibility and lets a compromised registry push new code.",
    "Pin images to a specific version tag, or better, a digest (`image@sha256:...`).",
)
def unpinned_image(doc):
    spec = pod_spec(doc)
    if spec is None:
        return
    for field, c in containers(spec):
        image = c.get("image")
        if not isinstance(image, str) or "@sha256:" in image:
            continue
        last = image.rsplit("/", 1)[-1]
        tag = last.split(":", 1)[1] if ":" in last else None
        if tag is None or tag == "latest":
            yield f"{_cname(field, c)} uses image '{image}' without a pinned tag", c.line_of("image")


@rule(
    "KSL013",
    "hostPath volume mounted",
    Severity.HIGH,
    "hostPath volumes expose the node's filesystem; mounting paths like / or the container runtime socket is a classic escape.",
    "Use a PersistentVolumeClaim, configMap, secret or emptyDir instead of hostPath.",
    cis="5.2.12",
)
def host_path(doc):
    spec = pod_spec(doc)
    if spec is None:
        return
    for v in spec.get("volumes") or []:
        if isinstance(v, LineDict) and isinstance(v.get("hostPath"), dict):
            path = v["hostPath"].get("path", "?")
            yield f"volume '{v.get('name', '?')}' mounts host path '{path}'", v.line_of("hostPath")


@rule(
    "KSL014",
    "Host port bound",
    Severity.MEDIUM,
    "hostPort binds directly to the node's interface, bypassing Services and limiting scheduling.",
    "Remove `hostPort` and expose the pod through a Service instead.",
    cis="5.2.13",
)
def host_port(doc):
    spec = pod_spec(doc)
    if spec is None:
        return
    for field, c in containers(spec):
        for p in c.get("ports") or []:
            if isinstance(p, LineDict) and p.get("hostPort"):
                yield f"{_cname(field, c)} binds hostPort {p['hostPort']}", p.line_of("hostPort")


@rule(
    "KSL015",
    "Service account token auto-mounted",
    Severity.LOW,
    "Most pods never talk to the Kubernetes API; an auto-mounted token is a free credential for an attacker.",
    "Set `automountServiceAccountToken: false` on the pod spec (or the ServiceAccount) unless the pod needs API access.",
    cis="5.1.6",
)
def sa_token(doc):
    spec = pod_spec(doc)
    if spec is not None and spec.get("automountServiceAccountToken") is not False:
        yield "pod does not set automountServiceAccountToken: false", spec.line


@rule(
    "KSL016",
    "No seccomp profile",
    Severity.LOW,
    "Without a seccomp profile, containers can call every syscall the kernel offers.",
    "Set `securityContext.seccompProfile.type: RuntimeDefault` on the pod.",
    cis="5.7.2",
)
def seccomp(doc):
    spec = pod_spec(doc)
    if spec is None:
        return
    pod_type = _get(spec, "securityContext", "seccompProfile", "type")
    for field, c in containers(spec):
        t = _get(c, "securityContext", "seccompProfile", "type") or pod_type
        if t not in ("RuntimeDefault", "Localhost"):
            reason = "is Unconfined" if t == "Unconfined" else "is not set"
            yield f"{_cname(field, c)} seccomp profile {reason}", c.line


@rule(
    "KSL017",
    "Resource in the default namespace",
    Severity.LOW,
    "The default namespace makes it hard to apply RBAC, quotas and network policies per application.",
    "Set `metadata.namespace` to a dedicated namespace.",
    cis="5.7.4",
)
def default_namespace(doc):
    if doc.kind in WORKLOAD_KINDS or doc.kind in {"Service", "ConfigMap", "Secret", "Role", "RoleBinding", "ServiceAccount"}:
        if doc.namespace == "default":
            meta = doc.data.get("metadata")
            yield "is placed in the default namespace", meta.line_of("namespace")


# --------------------------------------------------------------------------
# RBAC rules
# --------------------------------------------------------------------------

RBAC_ROLE_KINDS = {"Role", "ClusterRole"}
RBAC_BINDING_KINDS = {"RoleBinding", "ClusterRoleBinding"}


def _rbac_rules(doc):
    if doc.kind not in RBAC_ROLE_KINDS:
        return
    for r in doc.data.get("rules") or []:
        if isinstance(r, LineDict):
            yield r


def _lower(xs):
    return {str(x).lower() for x in xs or []}


@rule(
    "KSL101",
    "Wildcard RBAC permissions",
    Severity.HIGH,
    "Wildcards in verbs, resources or apiGroups grant every current and future permission, which is almost never intended.",
    "Replace '*' with the explicit verbs, resources and apiGroups the subject needs.",
    cis="5.1.3",
)
def rbac_wildcard(doc):
    for r in _rbac_rules(doc):
        for key in ("verbs", "resources", "apiGroups"):
            if "*" in [str(x) for x in r.get(key) or []]:
                yield f"grants '*' in {key}", r.line_of(key)


@rule(
    "KSL102",
    "Binding to cluster-admin",
    Severity.CRITICAL,
    "cluster-admin is unrestricted superuser access to the whole cluster.",
    "Bind a narrowly scoped Role instead of cluster-admin.",
    cis="5.1.1",
)
def rbac_cluster_admin(doc):
    if doc.kind in RBAC_BINDING_KINDS:
        ref = doc.data.get("roleRef") or LineDict()
        if ref.get("name") == "cluster-admin":
            yield "binds the cluster-admin role", ref.line_of("name")


@rule(
    "KSL103",
    "Read access to Secrets",
    Severity.HIGH,
    "get/list/watch on secrets exposes every credential in scope; list and watch return secret values too.",
    "Grant access only to named secrets with `resourceNames`, or avoid reading secrets via the API.",
    cis="5.1.2",
)
def rbac_secrets(doc):
    for r in _rbac_rules(doc):
        resources = _lower(r.get("resources"))
        verbs = _lower(r.get("verbs"))
        if ("secrets" in resources or "*" in resources) and verbs & {"get", "list", "watch", "*"}:
            if r.get("resourceNames") and not verbs & {"list", "watch", "*"}:
                continue
            yield f"can read secrets ({', '.join(sorted(verbs & {'get', 'list', 'watch', '*'}))})", r.line_of("resources")


@rule(
    "KSL104",
    "Permission to create pods",
    Severity.MEDIUM,
    "Anyone who can create pods can mount any secret or service account in the namespace and often escalate to node access.",
    "Restrict pod creation to deployment tooling; prefer granting access to higher-level controllers.",
    cis="5.1.4",
)
def rbac_create_pods(doc):
    for r in _rbac_rules(doc):
        resources = _lower(r.get("resources"))
        verbs = _lower(r.get("verbs"))
        if "pods" in resources and verbs & {"create", "*"}:
            yield "can create pods", r.line_of("verbs")


@rule(
    "KSL105",
    "Privilege escalation verbs",
    Severity.HIGH,
    "The bind, escalate and impersonate verbs let a subject grant itself permissions it does not have.",
    "Remove bind, escalate and impersonate unless this is a trusted admin role.",
    cis="5.1.8",
)
def rbac_escalation(doc):
    for r in _rbac_rules(doc):
        bad = sorted(_lower(r.get("verbs")) & {"bind", "escalate", "impersonate"})
        if bad:
            yield f"grants {', '.join(bad)}", r.line_of("verbs")


@rule(
    "KSL106",
    "Binding grants access to all authenticated users",
    Severity.CRITICAL,
    "Binding a role to system:authenticated, system:unauthenticated or system:anonymous gives it to everyone who can reach the API server.",
    "Bind to specific users, groups or service accounts instead.",
    cis="5.1.1",
)
def rbac_broad_subject(doc):
    if doc.kind not in RBAC_BINDING_KINDS:
        return
    for s in doc.data.get("subjects") or []:
        if isinstance(s, LineDict) and s.get("name") in {"system:authenticated", "system:unauthenticated", "system:anonymous"}:
            yield f"binds to '{s['name']}'", s.line_of("name")


def run_rules(doc: Document, enabled: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for rid, r in RULES.items():
        if enabled is not None and rid not in enabled:
            continue
        findings.extend(r.check(doc))
    return findings
