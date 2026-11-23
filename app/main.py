"""FastAPI entry point."""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.analyzer import ManifestError, analyze_documents

app = FastAPI(
    title="Deployment Dash Intelligence API",
    version="0.1.0",
    description="Read-only, deterministic Kubernetes deployment manifest analysis.",
)


class AnalyzeRequest(BaseModel):
    yaml: str = Field(min_length=1, max_length=500_000, description="One or more Kubernetes YAML documents")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/analyze")
def analyze(request: AnalyzeRequest) -> dict:
    try:
        return analyze_documents(request.yaml)
    except ManifestError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
