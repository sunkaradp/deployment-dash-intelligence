import React, { useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { loadAll } from "js-yaml";
import { Activity, AlertCircle, AlertTriangle, ArrowDownToLine, ArrowRight, CheckCircle2, Clipboard, FileCode2, Github, Gauge, Info, Layers3, LockKeyhole, Play, RotateCcw, ShieldAlert, ShieldCheck, Sparkles, Terminal, Upload, X } from "lucide-react";
import "./styles.css";

type Severity = "critical" | "high" | "medium" | "low";
type Finding = { rule_id: string; severity: Severity; title: string; message: string; path: string; recommendation: string; help_uri?: string; resource?: string; container?: string; namespace?: string; points: number };
type Analysis = { source: "yaml" | "sarif"; scanner_name?: string; risk_score: number; risk_level: Severity; summary: { workloads_analyzed: number; documents_ignored: number; findings: number; by_severity: Record<Severity, number> }; findings: Finding[]; disclaimer: string };

const SAMPLE = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: payments-api\n  namespace: production\nspec:\n  replicas: 1\n  selector:\n    matchLabels:\n      app: payments-api\n  template:\n    metadata:\n      labels:\n        app: payments-api\n    spec:\n      hostNetwork: true\n      containers:\n        - name: api\n          image: example.com/payments-api:latest\n          ports:\n            - containerPort: 8080\n          resources:\n            requests:\n              cpu: \"100m\"\n            limits:\n              cpu: \"500m\"\n          securityContext:\n            privileged: true\n            allowPrivilegeEscalation: true\n";
const CLEAN_SAMPLE = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: storefront\n  namespace: production\nspec:\n  replicas: 3\n  selector:\n    matchLabels:\n      app: storefront\n  template:\n    metadata:\n      labels:\n        app: storefront\n    spec:\n      containers:\n        - name: web\n          image: ghcr.io/acme/storefront:2.4.1\n          ports:\n            - containerPort: 8080\n          resources:\n            requests:\n              cpu: \"200m\"\n              memory: \"256Mi\"\n            limits:\n              cpu: \"1\"\n              memory: \"512Mi\"\n          readinessProbe:\n            httpGet:\n              path: /ready\n              port: 8080\n          livenessProbe:\n            httpGet:\n              path: /health\n              port: 8080\n          securityContext:\n            runAsNonRoot: true\n            allowPrivilegeEscalation: false\n";
const WEIGHTS = { WORKLOAD_NO_CONTAINERS: 25, SINGLE_REPLICA: 10, MISSING_RESOURCE_REQUESTS: 8, MISSING_MEMORY_LIMIT: 8, MUTABLE_IMAGE_TAG: 7, MISSING_READINESSPROBE: 4, MISSING_LIVENESSPROBE: 4, PRIVILEGED_CONTAINER: 25, PRIVILEGE_ESCALATION_ALLOWED: 15, RUN_AS_NON_ROOT_NOT_SET: 8, HOST_NETWORK_ENABLED: 15 };
function obj(value: unknown): Record<string, any> { return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, any> : {}; }
function pathObject(value: unknown, path: string): Record<string, any> { let current: unknown = value; path.split(".").forEach((part) => { current = obj(current)[part]; }); return obj(current); }
function makeFinding(rule: keyof typeof WEIGHTS, severity: Severity, title: string, message: string, path: string, recommendation: string): Finding { return { rule_id: rule, severity, title, message, path, recommendation, points: WEIGHTS[rule] }; }

function analyzeYaml(source: string): Analysis {
  if (!source.trim()) throw new Error("Paste or upload at least one Kubernetes YAML manifest.");
  let docs: unknown[];
  try { docs = loadAll(source) as unknown[]; } catch { throw new Error("The YAML could not be parsed. Check indentation, quotes and document separators."); }
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
    const base = "documents[" + index + "]";
    const podPath = kind === "CronJob" ? "spec.jobTemplate.spec.template.spec" : "spec.template.spec";
    const pod = pathObject(resource, podPath);
    const containers = Array.isArray(pod.containers) ? pod.containers.map(obj) : [];
    if (!containers.length) {
      findings.push(makeFinding("WORKLOAD_NO_CONTAINERS", "high", "No containers defined", "The workload pod template has no valid containers.", base, "Define at least one container in the pod template."));
      return;
    }
    if (kind === "Deployment" || kind === "StatefulSet") {
      const replicas = obj(resource.spec).replicas ?? 1;
      if (typeof replicas === "number" && replicas < 2) findings.push(makeFinding("SINGLE_REPLICA", "medium", "Single replica configured", "Only one replica is configured, so a pod disruption may cause downtime.", base + ".spec.replicas", "Consider at least two replicas when the application and budget support it."));
    }
    containers.forEach((container, containerIndex) => {
      const path = base + "." + podPath + ".containers[" + containerIndex + "]";
      const resources = obj(container.resources);
      const requests = obj(resources.requests);
      const limits = obj(resources.limits);
      if (!requests.cpu || !requests.memory) findings.push(makeFinding("MISSING_RESOURCE_REQUESTS", "medium", "Resource requests incomplete", "CPU and memory requests help the scheduler place workloads predictably.", path + ".resources.requests", "Set realistic CPU and memory requests based on observed usage."));
      if (!limits.memory) findings.push(makeFinding("MISSING_MEMORY_LIMIT", "medium", "Memory limit missing", "Without a memory limit, this container can consume node memory without a per-container cap.", path + ".resources.limits", "Set a memory limit appropriate to the workload; validate it under representative load."));
      if (typeof container.image === "string") {
        const image = container.image.split("/").pop() || "";
        if (image.indexOf(":") === -1 || image.endsWith(":latest")) findings.push(makeFinding("MUTABLE_IMAGE_TAG", "medium", "Image tag may be mutable", "The image reference does not pin a specific version or digest.", path + ".image", "Use an explicit version tag or immutable image digest."));
      }
      (["readinessProbe", "livenessProbe"] as const).forEach((probe) => {
        if (!Object.keys(obj(container[probe])).length) {
          const rule = probe === "readinessProbe" ? "MISSING_READINESSPROBE" : "MISSING_LIVENESSPROBE";
          findings.push(makeFinding(rule, "low", probe + " missing", "No " + probe + " is configured for this container.", path + "." + probe, "Add an appropriate probe if the application exposes a reliable health signal."));
        }
      });
      const security = obj(container.securityContext);
      if (security.privileged === true) findings.push(makeFinding("PRIVILEGED_CONTAINER", "critical", "Privileged container", "Privileged containers receive extended host-level capabilities.", path + ".securityContext.privileged", "Remove privileged mode unless a documented, reviewed requirement exists."));
      if (security.allowPrivilegeEscalation === true) findings.push(makeFinding("PRIVILEGE_ESCALATION_ALLOWED", "high", "Privilege escalation allowed", "The container explicitly allows processes to gain more privileges.", path + ".securityContext.allowPrivilegeEscalation", "Set allowPrivilegeEscalation to false where compatible."));
      if (security.runAsNonRoot !== true) findings.push(makeFinding("RUN_AS_NON_ROOT_NOT_SET", "medium", "Non-root execution not enforced", "The container security context does not enforce a non-root user.", path + ".securityContext.runAsNonRoot", "Set runAsNonRoot to true and configure a non-zero runAsUser if needed."));
    });
    if (pod.hostNetwork === true) findings.push(makeFinding("HOST_NETWORK_ENABLED", "high", "Host networking enabled", "The pod shares the host network namespace.", base + "." + podPath + ".hostNetwork", "Disable host networking unless the workload has a reviewed need for it."));
  });
  if (!analyzed) throw new Error("No supported workload found. Supported kinds: Deployment, StatefulSet, DaemonSet, Job and CronJob.");
  const score = Math.min(100, findings.reduce((sum, item) => sum + item.points, 0));
  const risk: Severity = score >= 60 ? "critical" : score >= 35 ? "high" : score >= 15 ? "medium" : "low";
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((item) => { bySeverity[item.severity] += 1; });
  return { source: "yaml", risk_score: score, risk_level: risk, summary: { workloads_analyzed: analyzed, documents_ignored: ignored, findings: findings.length, by_severity: bySeverity }, findings, disclaimer: "Advisory analysis only; this tool does not validate cluster state or apply changes." };
}

function analysisFromSarif(raw: unknown): Analysis {
  const report = obj(raw);
  const runs = Array.isArray(report.runs) ? report.runs : [];
  if (!runs.length) throw new Error("This file does not contain a SARIF runs array.");

  const findings: Finding[] = [];
  const seen = new Set<string>();
  const manifestsWithFindings = new Set<string>();

  for (const runValue of runs) {
    const run = obj(runValue);
    const driver = obj(obj(run.tool).driver);
    const rules = Array.isArray(driver.rules) ? driver.rules.map(obj) : [];
    const results = Array.isArray(run.results) ? run.results : [];

    for (const item of results) {
      const result = obj(item);
      const ruleId = String(result.ruleId || "KUBESCAPE_FINDING");
      const ruleIndex = Number.isInteger(result.ruleIndex) ? Number(result.ruleIndex) : -1;
      const descriptor = rules.find((rule) => String(rule.id || "") === ruleId) || rules[ruleIndex] || {};
      const resultProperties = obj(result.properties);
      const ruleProperties = obj(descriptor.properties);
      const level = String(result.level || obj(descriptor.defaultConfiguration).level || "warning").toLowerCase();
      const severityText = String(
        resultProperties.severity || resultProperties.controlSeverity ||
        ruleProperties.severity || ruleProperties.controlSeverity || ""
      ).toLowerCase();
      const securitySeverity = Number(
        resultProperties["security-severity"] || ruleProperties["security-severity"] || 0
      );
      const severity: Severity = /critical/.test(severityText) || securitySeverity >= 9 ? "critical"
        : /high/.test(severityText) || securitySeverity >= 7 || level === "error" ? "high"
        : /low|info/.test(severityText) || level === "note" ? "low" : "medium";

      const firstLocation = Array.isArray(result.locations) ? obj(result.locations[0]) : {};
      const physicalLocation = obj(firstLocation.physicalLocation);
      const artifact = obj(physicalLocation.artifactLocation);
      const region = obj(physicalLocation.region);
      const uri = String(artifact.uri || "manifest");
      const line = region.startLine ? ":" + region.startLine : "";
      const path = uri + line;
      const message = String(
        obj(result.message).text ||
        obj(descriptor.shortDescription).text ||
        ruleId
      );
      const key = ruleId + "|" + path + "|" + message;
      if (seen.has(key)) continue;
      seen.add(key);
      manifestsWithFindings.add(uri);

      const affectedText = message + "\\n" + String(resultProperties.affectedResources || resultProperties.affectedFields || "");
      const containerMatch = affectedText.match(/\\(([^()]+)\\)/);
      const container = containerMatch?.[1];
      const resourceFromProps = String(resultProperties.resourceName || resultProperties.resource || resultProperties.workload || "");
      const resource = resourceFromProps || (container ? "Container: " + container : "Workload not specified");
      const namespace = String(resultProperties.namespace || "");
      const title = String(
        obj(descriptor.shortDescription).text ||
        obj(result.message).text ||
        ruleId.replace(/[-_]/g, " ")
      );
      const helpText = String(
        obj(resultProperties).remediation ||
        obj(resultProperties).recommendation ||
        obj(descriptor.help).text ||
        "Review the Kubescape control details and remediate the configuration before deployment."
      );
      findings.push({
        rule_id: ruleId,
        severity,
        title,
        message,
        path,
        recommendation: helpText,
        help_uri: typeof descriptor.helpUri === "string" ? descriptor.helpUri : undefined,
        resource,
        container,
        namespace: namespace || undefined,
        points: severity === "critical" ? 25 : severity === "high" ? 15 : severity === "medium" ? 8 : 4,
      });
    }
  }

  const score = Math.min(100, findings.reduce((sum, item) => sum + item.points, 0));
  const risk: Severity = score >= 60 ? "critical" : score >= 35 ? "high" : score >= 15 ? "medium" : "low";
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((item) => { bySeverity[item.severity] += 1; });

  return {
    source: "sarif",
    scanner_name: String(obj(obj(runs[0]).tool).driver ? obj(obj(obj(runs[0]).tool).driver).name || "External scanner" : "External scanner"),
    risk_score: score,
    risk_level: risk,
    summary: { workloads_analyzed: manifestsWithFindings.size, documents_ignored: 0, findings: findings.length, by_severity: bySeverity },
    findings,
    disclaimer: "Imported SARIF results. The count represents manifest files with findings; severity is mapped for display and the score is a local heuristic, not the scanner's compliance score.",
  };
}

function App() {
  const [yaml, setYaml] = useState(SAMPLE);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState<Severity | "all">("all");
  const [search, setSearch] = useState("");
  const [resourceFilter, setResourceFilter] = useState("all");
  const [ruleFilter, setRuleFilter] = useState("all");
  const [selected, setSelected] = useState("");
  const [fileName, setFileName] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);
  const visible = useMemo(() => analysis ? analysis.findings.filter((item) => (filter === "all" || item.severity === filter) && (resourceFilter === "all" || item.resource === resourceFilter) && (ruleFilter === "all" || item.rule_id === ruleFilter) && (!search.trim() || [item.title,item.message,item.path,item.rule_id,item.resource,item.container,item.namespace].join(" ").toLowerCase().includes(search.trim().toLowerCase()))) : [], [analysis, filter, resourceFilter, ruleFilter, search]);
  const resources = useMemo(() => analysis ? Array.from(new Set(analysis.findings.map((item) => item.resource || "Workload not specified"))) : [], [analysis]);
  const rules = useMemo(() => analysis ? Array.from(new Set(analysis.findings.map((item) => item.rule_id))) : [], [analysis]);
  const selectedFinding = visible.find((item) => item.rule_id + item.path === selected) || visible[0];
  function run() {
    try { const result = analyzeYaml(yaml); setAnalysis(result); setError(""); setFilter("all"); setSelected(result.findings[0] ? result.findings[0].rule_id + result.findings[0].path : ""); }
    catch (err) { setAnalysis(null); setError(err instanceof Error ? err.message : "Analysis failed."); }
  }
  function loadFile(file?: File) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const content = String(reader.result || "");
      if (content.includes("\u0000")) {
        setError("This looks like a ZIP or binary file. Extract it first, then choose a YAML or SARIF report.");
        return;
      }
      try {
        if (/\.(sarif|json)$/i.test(file.name)) {
          const imported = analysisFromSarif(JSON.parse(content));
          setAnalysis(imported);
          setFilter("all");
          setSelected(imported.findings[0] ? imported.findings[0].rule_id + imported.findings[0].path : "");
        } else {
          setYaml(content);
          setAnalysis(null);
        }
        setFileName(file.name || "uploaded-manifest.yaml");
        setError("");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Could not read this report. Choose a Kubernetes YAML or SARIF JSON file.");
      }
    };
    reader.onerror = () => setError("The selected file could not be read.");
    reader.readAsText(file);
  }
  function exportReport() {
    if (!analysis) return;
    const blob = new Blob([JSON.stringify({ generated_at: new Date().toISOString(), ...analysis }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob); const a = document.createElement("a");
    a.href = url; a.download = "deployment-readiness-report.json"; a.click(); URL.revokeObjectURL(url);
  }
  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#"><span className="brand-mark"><Layers3 size={19}/></span><span><strong>deploy<span>dash</span></strong><small>INTELLIGENCE</small></span></a>
      <div className="side-label">WORKSPACE</div>
      <div className="side-item active"><Gauge size={17}/> Readiness analysis <i/></div>
      <div className="side-item muted"><Activity size={17}/> Analysis history <small>SOON</small></div>
      <div className="side-label side-label-bottom">PROJECT</div>
      <a className="side-item" href="https://github.com/sunkaradp/deployment-dash-intelligence" target="_blank" rel="noreferrer"><Github size={17}/> GitHub repository <ArrowRight size={14}/></a>
      <div className="sidebar-foot"><div className="status-line"><span/> LOCAL ANALYSIS ENGINE</div><p>Manifest checks run in your browser. No cluster credentials required.</p><div className="version">MVP · v0.1.0</div></div>
    </aside>
    <main className="main-area">
      <header className="topbar"><div className="breadcrumb">Workspace <span>/</span> <strong>Readiness analysis</strong></div><div className="top-actions"><span className="privacy"><LockKeyhole size={13}/> READ-ONLY MODE</span><a href="https://github.com/sunkaradp/deployment-dash-intelligence" target="_blank" rel="noreferrer"><Github size={16}/> Source</a></div></header>
      <section className="page-intro"><div><div className="eyebrow"><span/> PRE-DEPLOYMENT CHECK</div><h1>Know the risk <em>before</em> you ship.</h1><p>Inspect Kubernetes workload manifests for configuration gaps and security risks. Get clear findings your team can act on.</p></div><div className="intro-note"><ShieldCheck size={18}/><span><strong>Safe by design</strong><small>No cluster access. No changes applied.</small></span></div></section>
      <section className="workspace-grid">
        <div className="panel editor-panel">
          <div className="panel-head"><div className="panel-title"><span className="panel-icon"><FileCode2 size={17}/></span><div><h2>Manifest input</h2><p>Paste YAML or upload a file</p></div></div><div className="file-pill"><i/> {fileName || "deployment.yaml"}</div></div>
          <div className="editor-toolbar"><span><b>Y</b> YAML</span><div className="editor-tools"><button onClick={() => { setYaml(SAMPLE); setFileName(""); setAnalysis(null); setError(""); }}><RotateCcw size={13}/> Risky sample</button><button onClick={() => { setYaml(CLEAN_SAMPLE); setFileName(""); setAnalysis(null); setError(""); }}><CheckCircle2 size={13}/> Clean sample</button><button onClick={() => { setYaml(""); setFileName(""); setAnalysis(null); setError(""); }}><X size={13}/> Clear</button></div></div>
          <div className="code-wrap"><div className="line-numbers">{yaml.split("\n").map((_, i) => <span key={i}>{i + 1}</span>)}</div><textarea spellCheck={false} aria-label="Kubernetes YAML manifest" value={yaml} onChange={(e) => { setYaml(e.target.value); setAnalysis(null); setError(""); }} placeholder={"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: my-app"}/></div>
          <div className="editor-bottom"><button onClick={() => fileRef.current?.click()}><Upload size={15}/> Upload YAML / SARIF</button><input ref={fileRef} type="file" accept=".yaml,.yml,.sarif,.json,.txt,text/yaml,application/json,text/plain,application/x-yaml" hidden onChange={(e) => { const file = e.target.files?.[0]; loadFile(file); e.currentTarget.value = ""; }}/><span>{yaml.split("\n").length} lines · {new Blob([yaml]).size.toLocaleString()} bytes</span></div>
          {error && <div className="error-banner"><AlertCircle size={16}/>{error}</div>}
          <button className="analyze-btn" onClick={run}><Play size={16} fill="currentColor"/> Analyze manifest <ArrowRight size={16}/></button>
          <div className="editor-footnote"><LockKeyhole size={12}/> Analysis runs locally in this browser. Your YAML is not uploaded.</div>
        </div>
        <div className="results-column">
          {!analysis ? <div className="empty-panel panel"><div className="empty-illustration"><div><ShieldCheck size={34}/></div><i/><b/></div><div className="empty-copy"><span className="eyebrow">WAITING FOR INPUT</span><h2>Your deployment review starts here.</h2><p>Run an analysis to see a risk score, prioritized findings and recommendations tied to exact manifest paths.</p></div><div className="empty-steps"><div><span>01</span><p><strong>Provide a manifest</strong><small>Paste YAML or upload a file</small></p></div><div><span>02</span><p><strong>Run the checks</strong><small>Deterministic rules, no AI guesswork</small></p></div><div><span>03</span><p><strong>Review the findings</strong><small>Prioritize before deployment</small></p></div></div></div> :
            <>
              <div className="score-panel panel"><div className="score-head"><div><span className="eyebrow">{analysis.source === "sarif" ? "LOCAL WEIGHTED INDICATOR" : "DEPLOYMENT RISK"}</span><h2>{analysis.source === "sarif" ? "Imported scan overview" : "Readiness overview"}</h2></div><button className="download-btn" onClick={exportReport}><ArrowDownToLine size={14}/> Export report</button></div>
                <div className="score-content"><div className={"score-ring " + analysis.risk_level} style={{ "--score": (analysis.risk_score * 3.6) + "deg" } as React.CSSProperties}><div><strong>{analysis.risk_score}</strong><small>/ 100</small></div></div><div className="score-description"><span className={"risk-label " + analysis.risk_level}>{analysis.risk_level.toUpperCase()} RISK</span><h3>{analysis.source === "sarif" ? `${analysis.scanner_name || "Scanner"} findings imported` : analysis.risk_score === 0 ? "No configured risks found" : analysis.risk_score >= 60 ? "Needs attention before release" : analysis.risk_score >= 35 ? "Review before deployment" : "Some improvements recommended"}</h3><p>{analysis.source === "sarif" ? `${analysis.summary.workloads_analyzed} manifest file(s) with findings` : `${analysis.summary.workloads_analyzed} workload(s) analyzed`} · {analysis.summary.findings} finding(s) detected</p></div></div>
                <div className="severity-row">{(["critical", "high", "medium", "low"] as Severity[]).map((level) => <button key={level} className={"severity-stat " + level + (filter === level ? " chosen" : "")} onClick={() => setFilter(filter === level ? "all" : level)}><span>{analysis.summary.by_severity[level]}</span><small>{level}</small></button>)}</div>{analysis.source === "sarif" && <p className="score-disclaimer">Scanner severities above are preserved for display. The {analysis.risk_score}/100 indicator is a local weighted heuristic, not the scanner\u2019s score or a compliance rating.</p>}
              </div>
              <div className="findings-panel panel"><div className="findings-head"><div><h2>Findings <span>{visible.length} / {analysis.findings.length}</span></h2><p>Search and filter scanner results by severity, resource or control</p></div><button className="filter-btn" onClick={() => { setFilter("all"); setResourceFilter("all"); setRuleFilter("all"); setSearch(""); }}>Reset filters <RotateCcw size={12}/></button></div><div className="finding-filters"><input aria-label="Search findings" placeholder="Search title, path, message…" value={search} onChange={(e) => setSearch(e.target.value)}/><select aria-label="Filter by resource" value={resourceFilter} onChange={(e) => setResourceFilter(e.target.value)}><option value="all">All resources</option>{resources.map((item) => <option key={item} value={item}>{item}</option>)}</select><select aria-label="Filter by control" value={ruleFilter} onChange={(e) => setRuleFilter(e.target.value)}><option value="all">All controls</option>{rules.map((item) => <option key={item} value={item}>{item}</option>)}</select></div>
                {visible.length === 0 ? <div className="no-findings"><CheckCircle2 size={22}/><strong>No findings in this category</strong><span>Nothing to review here.</span></div> :
                  <div className="finding-list">{visible.map((item) => <button key={item.rule_id + item.path} className={"finding-item " + (selectedFinding === item ? "selected" : "")} onClick={() => setSelected(item.rule_id + item.path)}><span className={"finding-symbol " + item.severity}>{item.severity === "critical" || item.severity === "high" ? <AlertTriangle size={15}/> : <Info size={15}/>}</span><span className="finding-main"><strong>{item.title}</strong><small>{item.resource || "Resource not specified"}{item.container ? " · " + item.container : ""} · {item.path}</small></span><span className={"severity-tag " + item.severity}>{item.severity}</span><ArrowRight size={14} className="finding-arrow"/></button>)}</div>}
                {selectedFinding && <div className="finding-detail"><div className="detail-top"><span>SELECTED FINDING</span><code>{selectedFinding.rule_id}</code></div><h3>{selectedFinding.title}</h3><p>{selectedFinding.message}</p><div className="resource-meta"><span><b>Resource</b>{selectedFinding.resource || "Not provided by scanner"}</span>{selectedFinding.container && <span><b>Container</b>{selectedFinding.container}</span>}<span><b>Namespace</b>{selectedFinding.namespace || "Not provided by scanner"}</span></div><div className="detail-path"><Terminal size={13}/><code>{selectedFinding.path}</code><button title="Copy path" onClick={() => navigator.clipboard?.writeText(selectedFinding.path)}><Clipboard size={13}/></button></div><div className="recommendation"><span><Sparkles size={14}/> RECOMMENDATION</span><p>{selectedFinding.recommendation}</p>{selectedFinding.help_uri && <a className="control-link" href={selectedFinding.help_uri} target="_blank" rel="noreferrer">Open scanner control documentation <ArrowRight size={12}/></a>}</div></div>}
              </div>
            </>}
        </div>
      </section>
      <footer className="page-footer"><span><ShieldAlert size={13}/> Advisory checks only — validate findings against workload requirements.</span><span>Built for engineers who ship to Kubernetes.</span></footer>
    </main>
  </div>;
}
createRoot(document.getElementById("root")!).render(<React.StrictMode><App/></React.StrictMode>);
