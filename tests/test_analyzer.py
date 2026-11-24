import pytest
from fastapi.testclient import TestClient

from app.analyzer import ManifestError, analyze_documents
from app.main import app

client = TestClient(app)

SAFE_WORKLOAD = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: web
          image: example.com/web:1.2.3
          resources:
            requests:
              cpu: "100m"
              memory: "128Mi"
            limits:
              cpu: "500m"
              memory: "256Mi"
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
"""


def test_safe_workload_has_no_findings():
    result = analyze_documents(SAFE_WORKLOAD)
    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert result["summary"]["workloads_analyzed"] == 1
    assert result["findings"] == []


def test_risky_workload_reports_explainable_findings():
    result = analyze_documents("""
apiVersion: apps/v1
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
""")
    rule_ids = {finding["rule_id"] for finding in result["findings"]}
    assert "SINGLE_REPLICA" in rule_ids
    assert "MUTABLE_IMAGE_TAG" in rule_ids
    assert "PRIVILEGED_CONTAINER" in rule_ids
    assert "HOST_NETWORK_ENABLED" in rule_ids
    assert result["risk_score"] > 0
    assert all(f["path"] and f["recommendation"] for f in result["findings"])


def test_rejects_empty_yaml():
    try:
        analyze_documents("  ")
    except ManifestError as exc:
        assert "at least one" in str(exc)
    else:
        raise AssertionError("Expected ManifestError")


def test_rejects_unsupported_only_documents():
    try:
        analyze_documents("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings")
    except ManifestError as exc:
        assert "No supported workload" in str(exc)
    else:
        raise AssertionError("Expected ManifestError")


def test_health_endpoint():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_analyze_endpoint_returns_422_for_invalid_yaml():
    response = client.post("/api/v1/analyze", json={"yaml": "kind: ["})
    assert response.status_code == 422


def test_pod_level_run_as_non_root_satisfies_container_check():
    result = analyze_documents("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pod-secure
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pod-secure
  template:
    metadata:
      labels:
        app: pod-secure
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
        - name: app
          image: example.com/app:1.0.0
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              memory: 256Mi
          readinessProbe:
            httpGet:
              path: /ready
              port: 8080
          livenessProbe:
            httpGet:
              path: /health
              port: 8080
          securityContext:
            allowPrivilegeEscalation: false
""")
    assert "RUN_AS_NON_ROOT_NOT_SET" not in {item["rule_id"] for item in result["findings"]}


def test_container_run_as_root_override_is_reported():
    result = analyze_documents("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: override
spec:
  replicas: 2
  selector:
    matchLabels:
      app: override
  template:
    metadata:
      labels:
        app: override
    spec:
      securityContext:
        runAsNonRoot: true
      containers:
        - name: app
          image: example.com/app:1.0.0
          securityContext:
            runAsNonRoot: false
""")
    finding = next(item for item in result["findings"] if item["rule_id"] == "RUN_AS_NON_ROOT_NOT_SET")
    assert finding["path"].endswith("containers[0].securityContext.runAsNonRoot")


def test_container_without_image_is_reported():
    result = analyze_documents("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: missing-image
spec:
  replicas: 2
  selector:
    matchLabels:
      app: missing-image
  template:
    metadata:
      labels:
        app: missing-image
    spec:
      containers:
        - name: app
""")
    finding = next(item for item in result["findings"] if item["rule_id"] == "MISSING_CONTAINER_IMAGE")
    assert finding["severity"] == "high"
    assert finding["path"].endswith("containers[0].image")


def test_security_posture_rules_cover_host_access_and_linux_privileges():
    result = analyze_documents("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: unsafe-host-access
spec:
  replicas: 2
  selector:
    matchLabels:
      app: unsafe-host-access
  template:
    metadata:
      labels:
        app: unsafe-host-access
    spec:
      hostPID: true
      hostIPC: true
      automountServiceAccountToken: true
      volumes:
        - name: host-logs
          hostPath:
            path: /var/log
      containers:
        - name: app
          image: example.com/app:1.0.0
          ports:
            - containerPort: 8080
              hostPort: 8080
          securityContext:
            runAsUser: 0
            allowPrivilegeEscalation: true
            capabilities:
              add:
                - ALL
""")
    rule_ids = {item["rule_id"] for item in result["findings"]}
    assert {
        "HOST_PID_ENABLED",
        "HOST_IPC_ENABLED",
        "SERVICE_ACCOUNT_TOKEN_AUTOMOUNTED",
        "HOST_PATH_VOLUME",
        "HOST_PORT_EXPOSED",
        "RUN_AS_ROOT",
        "ALL_CAPABILITIES_ADDED",
        "ALL_CAPABILITIES_NOT_DROPPED",
        "SECCOMP_PROFILE_NOT_SET",
    }.issubset(rule_ids)


def test_cronjob_security_context_is_checked():
    result = analyze_documents("""
apiVersion: batch/v1
kind: CronJob
metadata:
  name: nightly
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            seccompProfile:
              type: RuntimeDefault
          containers:
            - name: worker
              image: example.com/worker:1.0.0
              securityContext:
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                capabilities:
                  drop: [ALL]
          restartPolicy: OnFailure
""")
    assert result["summary"]["workloads_analyzed"] == 1
    assert "RUN_AS_ROOT" not in {item["rule_id"] for item in result["findings"]}



def test_rejects_input_over_one_megabyte():
    from app.analyzer import MAX_INPUT_BYTES

    with pytest.raises(ManifestError, match="byte limit"):
        analyze_documents(" " * (MAX_INPUT_BYTES + 1))


def test_rejects_more_than_one_hundred_documents():
    source = "---\nkind: ConfigMap\nmetadata:\n  name: ignored\n" * 101
    with pytest.raises(ManifestError, match="100-document"):
        analyze_documents(source)


def test_rejects_excessive_yaml_aliases():
    aliases = " ".join("*base" for _ in range(51))
    source = "base: &base value\nitems: [" + aliases + "]\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: app:1\n"
    with pytest.raises(ManifestError, match="parser safety limit"):
        analyze_documents(source)


def test_rejects_excessive_yaml_nesting():
    source = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: x\nextra: " + "[" * 60 + "0" + "]" * 60 + "\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          image: app:1\n"
    with pytest.raises(ManifestError, match="parser safety limit"):
        analyze_documents(source)
