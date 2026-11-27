import test from "node:test";
import assert from "node:assert/strict";
import { analyzeYaml, proposedFix } from "../.cli-build/analyzer.js";

const SAFE = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: storefront
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: storefront
  template:
    metadata:
      labels:
        app: storefront
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: web
          image: ghcr.io/acme/storefront:2.4.1
          resources:
            requests:
              cpu: "200m"
              memory: "256Mi"
            limits:
              cpu: "1"
              memory: "512Mi"
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
          securityContext:
            runAsNonRoot: true
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
`;

const RISKY = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: risky
spec:
  replicas: 1
  selector:
    matchLabels:
      app: risky
  template:
    metadata:
      labels:
        app: risky
    spec:
      hostNetwork: true
      containers:
        - name: app
          image: example/app:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
`;

test("safe workload has no findings", () => {
  const result = analyzeYaml(SAFE);
  assert.equal(result.risk_score, 0);
  assert.deepEqual(result.findings, []);
});

test("risky workload reports deterministic rule identifiers", () => {
  const result = analyzeYaml(RISKY);
  const ids = new Set(result.findings.map((finding) => finding.rule_id));
  for (const id of ["SINGLE_REPLICA", "MUTABLE_IMAGE_TAG", "PRIVILEGED_CONTAINER", "HOST_NETWORK_ENABLED"]) {
    assert.ok(ids.has(id), `expected rule ${id}`);
  }
  assert.ok(result.risk_score > 0);
  assert.deepEqual(result, analyzeYaml(RISKY));
});

test("multi-document input analyzes supported workloads and ignores other resources", () => {
  const source = `apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
---
` + SAFE;
  const result = analyzeYaml(source);
  assert.equal(result.summary.workloads_analyzed, 1);
  assert.equal(result.summary.documents_ignored, 1);
});

test("CronJob pod template is analyzed", () => {
  const source = `apiVersion: batch/v1
kind: CronJob
metadata:
  name: cleanup
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: cleanup
              image: example/cleanup:latest
          restartPolicy: OnFailure
`;
  const result = analyzeYaml(source);
  assert.equal(result.summary.workloads_analyzed, 1);
  assert.ok(result.findings.some((finding) => finding.rule_id === "MUTABLE_IMAGE_TAG"));
});


test("init containers are analyzed without requiring application probes", () => {
  const source = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: init-risk
spec:
  selector:
    matchLabels:
      app: init-risk
  template:
    metadata:
      labels:
        app: init-risk
    spec:
      initContainers:
        - name: bootstrap
          image: example/bootstrap:latest
          securityContext:
            privileged: true
      containers:
        - name: app
          image: example/app:1.0
`;
  const result = analyzeYaml(source);
  const privileged = result.findings.find((finding) => finding.rule_id === "PRIVILEGED_CONTAINER");
  assert.ok(privileged);
  assert.equal(privileged.container, "bootstrap");
  assert.match(privileged.path, /initContainers\[0\]/);
  assert.equal(result.findings.filter((finding) => finding.container === "bootstrap" && /PROBE/.test(finding.rule_id)).length, 0);
});

test("ephemeral containers receive security checks without unsupported resource or probe checks", () => {
  const source = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: debug-risk
spec:
  selector:
    matchLabels:
      app: debug-risk
  template:
    metadata:
      labels:
        app: debug-risk
    spec:
      containers:
        - name: app
          image: example/app:1.0
      ephemeralContainers:
        - name: debug
          image: example/debug:latest
          securityContext:
            privileged: true
`;
  const result = analyzeYaml(source);
  const debugFindings = result.findings.filter((finding) => finding.container === "debug");
  assert.ok(debugFindings.some((finding) => finding.rule_id === "PRIVILEGED_CONTAINER"));
  assert.ok(debugFindings.some((finding) => finding.rule_id === "MUTABLE_IMAGE_TAG"));
  assert.equal(debugFindings.some((finding) => ["MISSING_RESOURCE_REQUESTS", "MISSING_MEMORY_LIMIT", "MISSING_READINESSPROBE", "MISSING_LIVENESSPROBE"].includes(finding.rule_id)), false);
  assert.ok(debugFindings.every((finding) => finding.path.includes("ephemeralContainers[0]")));
});

test("input and document limits are enforced", () => {
  assert.throws(() => analyzeYaml("x".repeat(1_000_001)), /1 MB/);
  assert.throws(() => analyzeYaml(Array.from({ length: 101 }, () => "apiVersion: v1\nkind: ConfigMap").join("\n---\n")), /100-document/);
});

test("fix suggestions exist only for supported rule identifiers", () => {
  const risky = analyzeYaml(RISKY);
  const privileged = risky.findings.find((finding) => finding.rule_id === "PRIVILEGED_CONTAINER");
  assert.ok(privileged);
  assert.match(proposedFix(privileged).yaml, /privileged: false/);
  const unsupported = { ...privileged, rule_id: "UNKNOWN_RULE" };
  assert.equal(proposedFix(unsupported), null);
});

test("CLI reports findings and uses non-zero exit status", async () => {
  const { spawnSync } = await import("node:child_process");
  const { writeFile, mkdtemp, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "deploydash-"));
  try {
    await writeFile(join(dir, "risky.yaml"), RISKY, "utf8");
    const result = spawnSync(process.execPath, ["bin/deploydash.mjs", dir], { cwd: process.cwd(), encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(result.stdout, /PRIVILEGED_CONTAINER/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});


test("shared cross-engine fixture preserves core rule identifiers", async () => {
  const { readFile } = await import("node:fs/promises");
  const { resolve } = await import("node:path");
  const fixture = await readFile(resolve(process.cwd(), "../tests/fixtures/action-risky.yaml"), "utf8");
  const result = analyzeYaml(fixture);
  const ids = new Set(result.findings.map((finding) => finding.rule_id));
  for (const id of ["SINGLE_REPLICA", "MUTABLE_IMAGE_TAG", "PRIVILEGED_CONTAINER", "HOST_NETWORK_ENABLED"]) {
    assert.ok(ids.has(id), `shared fixture expected rule ${id}`);
  }
});
