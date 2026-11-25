import test from "node:test";
import assert from "node:assert/strict";
import { analyzeYaml, proposedFix } from "../.test-build/analyzer.js";

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
