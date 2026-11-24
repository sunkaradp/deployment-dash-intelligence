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
            ports = container.get("ports", [])
            if isinstance(ports, list):
                for port_index, port_value in enumerate(ports):
                    port = _mapping(port_value)
                    if isinstance(port.get("hostPort"), int) and port["hostPort"] > 0:
                        findings.append(Finding(
                            "HOST_PORT_EXPOSED", "medium", "Host port exposed",
                            "The container binds a port directly on the Kubernetes node.",
                            f"{path}.ports[{port_index}].hostPort",
                            "Prefer a Service or Ingress; use hostPort only when a reviewed networking requirement exists.", 8,
                        ))

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
            if not isinstance(image, str) or not image.strip():
                findings.append(Finding(
                    "MISSING_CONTAINER_IMAGE", "high", "Container image missing",
                    "The container does not define an image reference, so the workload cannot be deployed as written.",
                    f"{path}.image",
                    "Set the container image to a valid registry reference and prefer an immutable digest for release workloads.", 15,
                ))
            elif ":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest"):
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

            pod_security = _mapping(pod_spec.get("securityContext"))
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
            effective_run_as_non_root = security.get("runAsNonRoot", pod_security.get("runAsNonRoot"))
            if effective_run_as_non_root is not True:
                security_path = (
                    f"{path}.securityContext.runAsNonRoot"
                    if "runAsNonRoot" in security
                    else f"{base}.{_container_path(kind)}.securityContext.runAsNonRoot"
                )
                findings.append(Finding(
                    "RUN_AS_NON_ROOT_NOT_SET", "medium", "Non-root execution not enforced",
                    "Neither the pod nor this container enforces non-root execution.",
                    security_path,
                    "Set runAsNonRoot to true at pod or container level and configure a non-zero runAsUser if needed.", 8,
                ))

            effective_run_as_user = security.get("runAsUser", pod_security.get("runAsUser"))
            if effective_run_as_user == 0:
                run_as_user_path = (
                    f"{path}.securityContext.runAsUser"
                    if "runAsUser" in security
                    else f"{base}.{_container_path(kind)}.securityContext.runAsUser"
                )
                findings.append(Finding(
                    "RUN_AS_ROOT", "high", "Container runs as root",
                    "The effective runAsUser is explicitly set to UID 0.",
                    run_as_user_path,
                    "Use a dedicated non-zero UID and verify file permissions and image compatibility.", 15,
                ))

            if security.get("readOnlyRootFilesystem") is not True:
                findings.append(Finding(
                    "READ_ONLY_ROOT_FILESYSTEM_NOT_SET", "low", "Root filesystem is writable",
                    "The container does not explicitly make its root filesystem read-only.",
                    f"{path}.securityContext.readOnlyRootFilesystem",
                    "Set readOnlyRootFilesystem to true where the application can write to mounted volumes or temporary storage instead.", 4,
                ))

            capabilities = _mapping(security.get("capabilities"))
            added_capabilities = capabilities.get("add", [])
            dropped_capabilities = capabilities.get("drop", [])
            if isinstance(added_capabilities, list) and any(str(item).upper() == "ALL" for item in added_capabilities):
                findings.append(Finding(
                    "ALL_CAPABILITIES_ADDED", "critical", "All Linux capabilities added",
                    "The container explicitly adds every Linux capability.",
                    f"{path}.securityContext.capabilities.add",
                    "Remove the ALL capability grant and add only individually justified capabilities.", 25,
                ))
            if not isinstance(dropped_capabilities, list) or not any(str(item).upper() == "ALL" for item in dropped_capabilities):
                findings.append(Finding(
                    "ALL_CAPABILITIES_NOT_DROPPED", "medium", "Default Linux capabilities retained",
                    "The container does not explicitly drop all Linux capabilities.",
                    f"{path}.securityContext.capabilities.drop",
                    "Drop ALL capabilities, then add back only the minimum individually required capabilities.", 8,
                ))

            if security.get("allowPrivilegeEscalation") is not False and security.get("privileged") is not True:
                findings.append(Finding(
                    "PRIVILEGE_ESCALATION_NOT_DISABLED", "medium", "Privilege escalation not disabled",
                    "The container does not explicitly disable privilege escalation.",
                    f"{path}.securityContext.allowPrivilegeEscalation",
                    "Set allowPrivilegeEscalation to false unless a documented exception is required.", 8,
                ))

        pod_security = _mapping(pod_spec.get("securityContext"))
        seccomp = _mapping(pod_security.get("seccompProfile"))
        if seccomp.get("type") not in {"RuntimeDefault", "Localhost"}:
            findings.append(Finding(
                "SECCOMP_PROFILE_NOT_SET", "medium", "Seccomp profile not explicit",
                "The pod does not explicitly select RuntimeDefault or a Localhost seccomp profile.",
                f"{base}.{_container_path(kind)}.securityContext.seccompProfile",
                "Set seccompProfile.type to RuntimeDefault or a reviewed Localhost profile.", 8,
            ))

        for namespace_field, rule_id, title in (
            ("hostPID", "HOST_PID_ENABLED", "Host PID namespace enabled"),
            ("hostIPC", "HOST_IPC_ENABLED", "Host IPC namespace enabled"),
        ):
            if pod_spec.get(namespace_field) is True:
                findings.append(Finding(
                    rule_id, "high", title,
                    f"The pod shares the host {namespace_field[4:]} namespace.",
                    f"{base}.{_container_path(kind)}.{namespace_field}",
                    "Disable host namespace sharing unless the workload has a reviewed operational requirement.", 15,
                ))

        if pod_spec.get("automountServiceAccountToken") is True:
            findings.append(Finding(
                "SERVICE_ACCOUNT_TOKEN_AUTOMOUNTED", "medium", "Service account token automounted",
                "The pod explicitly requests an automatically mounted service account token.",
                f"{base}.{_container_path(kind)}.automountServiceAccountToken",
                "Disable token automounting when the workload does not need Kubernetes API access.", 8,
            ))

        volumes = pod_spec.get("volumes", [])
        if isinstance(volumes, list):
            for volume_index, volume_value in enumerate(volumes):
                volume = _mapping(volume_value)
                if isinstance(volume.get("hostPath"), dict):
                    findings.append(Finding(
                        "HOST_PATH_VOLUME", "high", "Host path volume mounted",
                        "The pod references a path on the node filesystem.",
                        f"{base}.{_container_path(kind)}.volumes[{volume_index}].hostPath",
                        "Avoid hostPath volumes where possible; use a narrowly scoped, read-only mount only when required and reviewed.", 15,
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
