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
