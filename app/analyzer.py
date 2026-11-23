# ruff: noqa: I001
"""Deterministic, read-only checks for Kubernetes workload manifests."""
from dataclasses import asdict, dataclass
from typing import Any

import yaml


SUPPORTED_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    path: str
    recommendation: str
    points: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ManifestError(ValueError):
    """Raised when the supplied YAML cannot be parsed safely."""


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _container_path(kind: str) -> str:
    return "spec.jobTemplate.spec.template.spec" if kind == "CronJob" else "spec.template.spec"


def _pod_spec(resource: dict[str, Any], kind: str) -> dict[str, Any]:
    current: Any = resource
    for part in _container_path(kind).split("."):
        current = _mapping(current).get(part)
    return _mapping(current)


def _containers(pod_spec: dict[str, Any]) -> list[dict[str, Any]]:
    values = pod_spec.get("containers", [])
    if not isinstance(values, list):
        return []
    return [_mapping(item) for item in values]


def analyze_documents(yaml_text: str) -> dict[str, Any]:
    """Analyze supported Kubernetes workloads and return explainable findings."""
    if not yaml_text.strip():
        raise ManifestError("Provide at least one Kubernetes YAML document.")

    try:
        documents = list(yaml.safe_load_all(yaml_text))
    except yaml.YAMLError as exc:
        raise ManifestError(f"Invalid YAML: {exc.__class__.__name__}") from exc

    findings: list[Finding] = []
    analyzed = 0
    ignored = 0

    for index, raw in enumerate(documents):
        if raw is None:
            continue
        if not isinstance(raw, dict):
            ignored += 1
            continue

        kind = raw.get("kind")
        if kind not in SUPPORTED_KINDS:
            ignored += 1
            continue

        analyzed += 1
        base = f"documents[{index}]"
        pod_spec = _pod_spec(raw, kind)
        containers = _containers(pod_spec)

        if not containers:
            findings.append(Finding(
                "WORKLOAD_NO_CONTAINERS", "high", "No containers defined",
                "The workload pod template has no valid containers.", base,
                "Define at least one container in the pod template.", 25,
            ))
            continue

        if kind in {"Deployment", "StatefulSet"}:
            replicas = _mapping(raw.get("spec")).get("replicas", 1)
            if isinstance(replicas, int) and replicas < 2:
                findings.append(Finding(
                    "SINGLE_REPLICA", "medium", "Single replica configured",
                    "Only one replica is configured, so a pod disruption may cause downtime.",
                    f"{base}.spec.replicas",
                    "Consider at least two replicas when the application and budget support it.", 10,
                ))

        for container_index, container in enumerate(containers):
            path = f"{base}.{_container_path(kind)}.containers[{container_index}]"
            resources = _mapping(container.get("resources"))
            requests = _mapping(resources.get("requests"))
            limits = _mapping(resources.get("limits"))

            if not requests.get("cpu") or not requests.get("memory"):
                findings.append(Finding(
                    "MISSING_RESOURCE_REQUESTS", "medium", "Resource requests incomplete",
                    "CPU and memory requests help the scheduler place workloads predictably.",
                    f"{path}.resources.requests",
                    "Set realistic CPU and memory requests based on observed usage.", 8,
                ))
            if not limits.get("memory"):
                findings.append(Finding(
                    "MISSING_MEMORY_LIMIT", "medium", "Memory limit missing",
                    "Without a memory limit, this container can consume node memory without a per-container cap.",
                    f"{path}.resources.limits",
                    "Set a memory limit appropriate to the workload; validate it under representative load.", 8,
                ))

            image = container.get("image")
            if isinstance(image, str) and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
                findings.append(Finding(
                    "MUTABLE_IMAGE_TAG", "medium", "Image tag may be mutable",
                    "The image reference does not pin a specific version or digest.",
                    f"{path}.image",
                    "Use an explicit version tag or immutable image digest.", 7,
                ))

            for probe_name in ("readinessProbe", "livenessProbe"):
                if not isinstance(container.get(probe_name), dict):
                    findings.append(Finding(
                        f"MISSING_{probe_name.upper()}", "low", f"{probe_name} missing",
                        f"No {probe_name} is configured for this container.",
                        f"{path}.{probe_name}",
                        "Add an appropriate probe if the application exposes a reliable health signal.", 4,
                    ))

            security = _mapping(container.get("securityContext"))
            if security.get("privileged") is True:
                findings.append(Finding(
                    "PRIVILEGED_CONTAINER", "critical", "Privileged container",
                    "Privileged containers receive extended host-level capabilities.",
                    f"{path}.securityContext.privileged",
                    "Remove privileged mode unless a documented, reviewed requirement exists.", 25,
                ))
            if security.get("allowPrivilegeEscalation") is True:
                findings.append(Finding(
                    "PRIVILEGE_ESCALATION_ALLOWED", "high", "Privilege escalation allowed",
                    "The container explicitly allows processes to gain more privileges.",
                    f"{path}.securityContext.allowPrivilegeEscalation",
                    "Set allowPrivilegeEscalation to false where compatible.", 15,
                ))
            if security.get("runAsNonRoot") is not True:
                findings.append(Finding(
                    "RUN_AS_NON_ROOT_NOT_SET", "medium", "Non-root execution not enforced",
                    "The container security context does not enforce a non-root user.",
                    f"{path}.securityContext.runAsNonRoot",
                    "Set runAsNonRoot to true and configure a non-zero runAsUser if needed.", 8,
                ))

        if pod_spec.get("hostNetwork") is True:
            findings.append(Finding(
                "HOST_NETWORK_ENABLED", "high", "Host networking enabled",
                "The pod shares the host network namespace.",
                f"{base}.{_container_path(kind)}.hostNetwork",
                "Disable host networking unless the workload has a reviewed need for it.", 15,
            ))

    if analyzed == 0:
        raise ManifestError(
            "No supported workload found. Supported kinds: " + ", ".join(sorted(SUPPORTED_KINDS))
        )

    # Score is a transparent sum of rule weights, capped for a stable 0-100 scale.
    score = min(100, sum(item.points for item in findings))
    if score >= 60:
        risk = "critical"
    elif score >= 35:
        risk = "high"
    elif score >= 15:
        risk = "medium"
    else:
        risk = "low"

    return {
        "risk_score": score,
        "risk_level": risk,
        "summary": {
            "workloads_analyzed": analyzed,
            "documents_ignored": ignored,
            "findings": len(findings),
            "by_severity": {
                level: sum(item.severity == level for item in findings)
                for level in ("critical", "high", "medium", "low")
            },
        },
        "findings": [item.to_dict() for item in findings],
        "disclaimer": "Advisory analysis only; this tool does not validate cluster state or apply changes.",
    }
