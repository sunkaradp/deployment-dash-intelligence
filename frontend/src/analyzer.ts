import { loadAll } from "js-yaml";

export type Severity = "critical" | "high" | "medium" | "low";
export type Finding = { rule_id: string; severity: Severity; title: string; message: string; path: string; recommendation: string; help_uri?: string; resource?: string; container?: string; namespace?: string; points: number };
export type Analysis = { source: "yaml" | "sarif"; scanner_name?: string; risk_score: number; risk_level: Severity; summary: { workloads_analyzed: number; documents_ignored: number; findings: number; by_severity: Record<Severity, number> }; findings: Finding[]; disclaimer: string };

const MAX_INPUT_BYTES = 1_000_000;
const MAX_DOCUMENTS = 100;
const MAX_FINDINGS = 5_000;

const WEIGHTS = { WORKLOAD_NO_CONTAINERS: 25, MISSING_CONTAINER_IMAGE: 15, SINGLE_REPLICA: 10, MISSING_RESOURCE_REQUESTS: 8, MISSING_MEMORY_LIMIT: 8, MUTABLE_IMAGE_TAG: 7, MISSING_READINESSPROBE: 4, MISSING_LIVENESSPROBE: 4, PRIVILEGED_CONTAINER: 25, PRIVILEGE_ESCALATION_ALLOWED: 15, PRIVILEGE_ESCALATION_NOT_DISABLED: 8, RUN_AS_NON_ROOT_NOT_SET: 8, RUN_AS_ROOT: 15, READ_ONLY_ROOT_FILESYSTEM_NOT_SET: 4, ALL_CAPABILITIES_ADDED: 25, ALL_CAPABILITIES_NOT_DROPPED: 8, SECCOMP_PROFILE_NOT_SET: 8, HOST_PID_ENABLED: 15, HOST_IPC_ENABLED: 15, SERVICE_ACCOUNT_TOKEN_AUTOMOUNTED: 8, HOST_PATH_VOLUME: 15, HOST_PORT_EXPOSED: 8, HOST_NETWORK_ENABLED: 15 };

function obj(value: unknown): Record<string, any> { return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, any> : {}; }
function pathObject(value: unknown, path: string): Record<string, any> { let current: unknown = value; path.split(".").forEach((part) => { current = obj(current)[part]; }); return obj(current); }
function makeFinding(rule: keyof typeof WEIGHTS, severity: Severity, title: string, message: string, path: string, recommendation: string): Finding { return { rule_id: rule, severity, title, message, path, recommendation, points: WEIGHTS[rule] }; }

export function proposedFix(finding: Finding): { yaml: string; note: string } | null {
  const fixes: Record<string, { yaml: string; note: string }> = {
    PRIVILEGED_CONTAINER: { yaml: "securityContext:\n  privileged: false", note: "Review whether the workload genuinely requires privileged mode before applying." },
    PRIVILEGE_ESCALATION_ALLOWED: { yaml: "securityContext:\n  allowPrivilegeEscalation: false", note: "Validate compatibility with the container entrypoint and runtime." },
    PRIVILEGE_ESCALATION_NOT_DISABLED: { yaml: "securityContext:\n  allowPrivilegeEscalation: false", note: "Validate compatibility with the container entrypoint and runtime." },
    RUN_AS_NON_ROOT_NOT_SET: { yaml: "securityContext:\n  runAsNonRoot: true", note: "The image must support non-root execution; check file ownership and writable paths." },
    READ_ONLY_ROOT_FILESYSTEM_NOT_SET: { yaml: "securityContext:\n  readOnlyRootFilesystem: true", note: "Move required writes to explicitly mounted volumes or temporary storage first." },
    ALL_CAPABILITIES_NOT_DROPPED: { yaml: "securityContext:\n  capabilities:\n    drop:\n      - ALL", note: "Test the application after dropping capabilities; add back only individually justified capabilities." },
    SECCOMP_PROFILE_NOT_SET: { yaml: "securityContext:\n  seccompProfile:\n    type: RuntimeDefault", note: "Validate the workload under the runtime default seccomp profile." },
    HOST_PID_ENABLED: { yaml: "hostPID: false", note: "Confirm the workload does not depend on the host PID namespace." },
    HOST_IPC_ENABLED: { yaml: "hostIPC: false", note: "Confirm the workload does not depend on the host IPC namespace." },
    SERVICE_ACCOUNT_TOKEN_AUTOMOUNTED: { yaml: "automountServiceAccountToken: false", note: "Only disable this when the workload does not need Kubernetes API credentials." },
    HOST_NETWORK_ENABLED: { yaml: "hostNetwork: false", note: "Confirm the workload does not depend on the node network namespace." },
  };
  return fixes[finding.rule_id] || null;
}

export function analyzeYaml(source: string): Analysis {
  if (!source.trim()) throw new Error("Paste or upload at least one Kubernetes YAML manifest.");
  if (new TextEncoder().encode(source).length > MAX_INPUT_BYTES) throw new Error("Input exceeds the 1 MB safety limit.");
  const docs: unknown[] = [];
  try {
    const yamlOptions = { maxDepth: 50, maxTotalMergeKeys: 10_000 } as unknown as Parameters<typeof loadAll>[2];
    loadAll(source, (document: unknown) => {
      if (docs.length >= MAX_DOCUMENTS) throw new Error("Input exceeds the 100-document safety limit.");
      docs.push(document);
    }, yamlOptions);
  } catch (err) {
    throw new Error(err instanceof Error && /limit/.test(err.message) ? err.message : "The YAML could not be parsed. Check indentation, quotes and document separators.");
  }
  const findings: Finding[] = [];
  let analyzed = 0;
  let ignored = 0;
  const supported = ["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"];
  docs.forEach((doc, index) => {
    if (doc == null) return;
    const resource = obj(doc);
    const kind = String(resource.kind || "");
    if (!supported.includes(kind)) { ignored += 1; return; }
    analyzed += 1;
    const findingStart = findings.length;
    const base = "documents[" + index + "]";
    const workloadName = String(obj(resource.metadata).name || "name not set");
    const namespace = String(obj(resource.metadata).namespace || "");
    const workloadIdentity = kind + "/" + workloadName;
    const podPath = kind === "CronJob" ? "spec.jobTemplate.spec.template.spec" : "spec.template.spec";
    const pod = pathObject(resource, podPath);
    const containerGroups = (["containers", "initContainers", "ephemeralContainers"] as const).flatMap((field) =>
      (Array.isArray(pod[field]) ? pod[field] : []).map((value: unknown, index: number) => ({
        field,
        index,
        value: obj(value),
      })),
    );
    if (!containerGroups.length) {
      const finding = makeFinding("WORKLOAD_NO_CONTAINERS", "high", "No containers defined", "The workload pod template has no valid regular, init, or ephemeral containers.", base, "Define at least one container in the pod template.");
      finding.resource = workloadIdentity;
      finding.namespace = namespace || undefined;
      findings.push(finding);
      return;
    }
    if (kind === "Deployment" || kind === "StatefulSet") {
      const replicas = obj(resource.spec).replicas ?? 1;
      if (typeof replicas === "number" && replicas < 2) findings.push(makeFinding("SINGLE_REPLICA", "medium", "Single replica configured", "Only one replica is configured, so a pod disruption may cause downtime.", base + ".spec.replicas", "Consider at least two replicas when the application and budget support it."));
    }
    containerGroups.forEach(({ field, index: containerIndex, value: container }) => {
      if (findings.length >= MAX_FINDINGS) throw new Error("Analysis exceeds the 5,000-finding safety limit.");
      const path = base + "." + podPath + "." + field + "[" + containerIndex + "]";
      const isEphemeral = field === "ephemeralContainers";
      const supportsProbes = field === "containers";
      if (!isEphemeral && Array.isArray(container.ports)) container.ports.forEach((portValue: unknown, portIndex: number) => { const hostPort = obj(portValue).hostPort; if (typeof hostPort === "number" && hostPort > 0) findings.push(makeFinding("HOST_PORT_EXPOSED", "medium", "Host port exposed", "The container binds a port directly on the Kubernetes node.", path + ".ports[" + portIndex + "].hostPort", "Prefer a Service or Ingress; use hostPort only when a reviewed networking requirement exists.")); });
      if (!isEphemeral) {
        const resources = obj(container.resources);
        const requests = obj(resources.requests);
        const limits = obj(resources.limits);
        if (!requests.cpu || !requests.memory) findings.push(makeFinding("MISSING_RESOURCE_REQUESTS", "medium", "Resource requests incomplete", "CPU and memory requests help the scheduler place workloads predictably.", path + ".resources.requests", "Set realistic CPU and memory requests based on observed usage."));
        if (!limits.memory) findings.push(makeFinding("MISSING_MEMORY_LIMIT", "medium", "Memory limit missing", "Without a memory limit, this container can consume node memory without a per-container cap.", path + ".resources.limits", "Set a memory limit appropriate to the workload; validate it under representative load."));
      }
      if (typeof container.image !== "string" || !container.image.trim()) {
        findings.push(makeFinding("MISSING_CONTAINER_IMAGE", "high", "Container image missing", "The container does not define an image reference, so the workload cannot be deployed as written.", path + ".image", "Set the container image to a valid registry reference and prefer an immutable digest for release workloads."));
      } else {
        const image = container.image.split("/").pop() || "";
        if (image.indexOf(":") === -1 || image.endsWith(":latest")) findings.push(makeFinding("MUTABLE_IMAGE_TAG", "medium", "Image tag may be mutable", "The image reference does not pin a specific version or digest.", path + ".image", "Use an explicit version tag or immutable image digest."));
      }
      if (supportsProbes) (["readinessProbe", "livenessProbe"] as const).forEach((probe) => {
        if (!Object.keys(obj(container[probe])).length) {
          const rule = probe === "readinessProbe" ? "MISSING_READINESSPROBE" : "MISSING_LIVENESSPROBE";
          findings.push(makeFinding(rule, "low", probe + " missing", "No " + probe + " is configured for this container.", path + "." + probe, "Add an appropriate probe if the application exposes a reliable health signal."));
        }
      });
      const podSecurity = obj(pod.securityContext);
      const security = obj(container.securityContext);
      if (security.privileged === true) findings.push(makeFinding("PRIVILEGED_CONTAINER", "critical", "Privileged container", "Privileged containers receive extended host-level capabilities.", path + ".securityContext.privileged", "Remove privileged mode unless a documented, reviewed requirement exists."));
      if (security.allowPrivilegeEscalation === true) findings.push(makeFinding("PRIVILEGE_ESCALATION_ALLOWED", "high", "Privilege escalation allowed", "The container explicitly allows processes to gain more privileges.", path + ".securityContext.allowPrivilegeEscalation", "Set allowPrivilegeEscalation to false where compatible."));
      if (security.allowPrivilegeEscalation !== false && security.privileged !== true) findings.push(makeFinding("PRIVILEGE_ESCALATION_NOT_DISABLED", "medium", "Privilege escalation not disabled", "The container does not explicitly disable privilege escalation.", path + ".securityContext.allowPrivilegeEscalation", "Set allowPrivilegeEscalation to false unless a documented exception is required."));
      const runAsNonRoot = security.runAsNonRoot ?? podSecurity.runAsNonRoot;
      if (runAsNonRoot !== true) {
        const nonRootPath = Object.prototype.hasOwnProperty.call(security, "runAsNonRoot") ? path + ".securityContext.runAsNonRoot" : base + "." + podPath + ".securityContext.runAsNonRoot";
        findings.push(makeFinding("RUN_AS_NON_ROOT_NOT_SET", "medium", "Non-root execution not enforced", "Neither the pod nor this container enforces non-root execution.", nonRootPath, "Set runAsNonRoot to true at pod or container level and configure a non-zero runAsUser if needed."));
      }
      const runAsUser = security.runAsUser ?? podSecurity.runAsUser;
      if (runAsUser === 0) {
        const runAsUserPath = Object.prototype.hasOwnProperty.call(security, "runAsUser") ? path + ".securityContext.runAsUser" : base + "." + podPath + ".securityContext.runAsUser";
        findings.push(makeFinding("RUN_AS_ROOT", "high", "Container runs as root", "The effective runAsUser is explicitly set to UID 0.", runAsUserPath, "Use a dedicated non-zero UID and verify file permissions and image compatibility."));
      }
      if (security.readOnlyRootFilesystem !== true) findings.push(makeFinding("READ_ONLY_ROOT_FILESYSTEM_NOT_SET", "low", "Root filesystem is writable", "The container does not explicitly make its root filesystem read-only.", path + ".securityContext.readOnlyRootFilesystem", "Set readOnlyRootFilesystem to true where the application can write to mounted volumes or temporary storage instead."));
      const effectiveSeccomp = obj(security.seccompProfile || podSecurity.seccompProfile);
      if (!["RuntimeDefault", "Localhost"].includes(String(effectiveSeccomp.type || ""))) {
        const seccompPath = Object.prototype.hasOwnProperty.call(security, "seccompProfile") ? path + ".securityContext.seccompProfile" : base + "." + podPath + ".securityContext.seccompProfile";
        findings.push(makeFinding("SECCOMP_PROFILE_NOT_SET", "medium", "Seccomp profile not explicit", "Neither the pod nor this container selects RuntimeDefault or a Localhost seccomp profile.", seccompPath, "Set seccompProfile.type to RuntimeDefault or a reviewed Localhost profile."));
      }
      const capabilities = obj(security.capabilities);
      const added = Array.isArray(capabilities.add) ? capabilities.add : [];
      const dropped = Array.isArray(capabilities.drop) ? capabilities.drop : [];
      if (added.some((item: unknown) => String(item).toUpperCase() === "ALL")) findings.push(makeFinding("ALL_CAPABILITIES_ADDED", "critical", "All Linux capabilities added", "The container explicitly adds every Linux capability.", path + ".securityContext.capabilities.add", "Remove the ALL capability grant and add only individually justified capabilities."));
      if (!dropped.some((item: unknown) => String(item).toUpperCase() === "ALL")) findings.push(makeFinding("ALL_CAPABILITIES_NOT_DROPPED", "medium", "Default Linux capabilities retained", "The container does not explicitly drop all Linux capabilities.", path + ".securityContext.capabilities.drop", "Drop ALL capabilities, then add back only the minimum individually required capabilities."));

    });
    if (pod.hostPID === true) findings.push(makeFinding("HOST_PID_ENABLED", "high", "Host PID namespace enabled", "The pod shares the host PID namespace.", base + "." + podPath + ".hostPID", "Disable host namespace sharing unless the workload has a reviewed operational requirement."));
    if (pod.hostIPC === true) findings.push(makeFinding("HOST_IPC_ENABLED", "high", "Host IPC namespace enabled", "The pod shares the host IPC namespace.", base + "." + podPath + ".hostIPC", "Disable host namespace sharing unless the workload has a reviewed operational requirement."));
    if (pod.automountServiceAccountToken === true) findings.push(makeFinding("SERVICE_ACCOUNT_TOKEN_AUTOMOUNTED", "medium", "Service account token automounted", "The pod explicitly requests an automatically mounted service account token.", base + "." + podPath + ".automountServiceAccountToken", "Disable token automounting when the workload does not need Kubernetes API access."));
    if (Array.isArray(pod.volumes)) pod.volumes.forEach((volumeValue: unknown, volumeIndex: number) => { if (obj(obj(volumeValue).hostPath).path) findings.push(makeFinding("HOST_PATH_VOLUME", "high", "Host path volume mounted", "The pod references a path on the node filesystem.", base + "." + podPath + ".volumes[" + volumeIndex + "].hostPath", "Avoid hostPath volumes where possible; use a narrowly scoped, read-only mount only when required and reviewed.")); });
    if (pod.hostNetwork === true) findings.push(makeFinding("HOST_NETWORK_ENABLED", "high", "Host networking enabled", "The pod shares the host network namespace.", base + "." + podPath + ".hostNetwork", "Disable host networking unless the workload has a reviewed need for it."));
    if (findings.length > MAX_FINDINGS) throw new Error("Analysis exceeds the 5,000-finding safety limit.");
    findings.slice(findingStart).forEach((finding) => {
      finding.resource = workloadIdentity;
      finding.namespace = namespace || undefined;
      const containerIndexMatch = finding.path.match(/(initContainers|ephemeralContainers|containers)\[(\d+)\]/);
      if (containerIndexMatch) {
        const group = containerIndexMatch[1];
        const container = (Array.isArray(pod[group]) ? pod[group] : [])[Number(containerIndexMatch[2])];
        if (container && typeof obj(container).name === "string") finding.container = obj(container).name;
      }
    });
  });
  if (!analyzed) throw new Error("No supported workload found. Supported kinds: Deployment, StatefulSet, DaemonSet, Job and CronJob.");
  const score = Math.min(100, findings.reduce((sum, item) => sum + item.points, 0));
  const risk: Severity = score >= 60 ? "critical" : score >= 35 ? "high" : score >= 15 ? "medium" : "low";
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((item) => { bySeverity[item.severity] += 1; });
  return { source: "yaml", risk_score: score, risk_level: risk, summary: { workloads_analyzed: analyzed, documents_ignored: ignored, findings: findings.length, by_severity: bySeverity }, findings, disclaimer: "Advisory analysis only; this tool does not validate cluster state or apply changes." };
}

