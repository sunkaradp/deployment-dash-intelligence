import React, { useMemo, useRef, useState } from "react";
import { analyzeYaml, proposedFix, type Analysis, type Finding, type Severity } from "./analyzer";
import { createRoot } from "react-dom/client";
import { AlertCircle, AlertTriangle, ArrowDownToLine, ArrowRight, CheckCircle2, Clipboard, FileCode2, GitBranch, Gauge, Info, Layers3, LockKeyhole, Play, RotateCcw, ShieldAlert, ShieldCheck, Sparkles, Terminal, Upload, X } from "lucide-react";
import "./styles.css";

function obj(value: unknown): Record<string, any> { return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, any> : {}; }
function boundedText(value: unknown, field: string, maxLength: number): string {
  if (value == null) return "";
  if (typeof value !== "string") throw new Error("SARIF " + field + " must be a string.");
  if (value.length > maxLength) throw new Error("SARIF " + field + " exceeds the " + maxLength + " character safety limit.");
  return value;
}

const MAX_INPUT_BYTES = 1_000_000;
const MAX_FINDINGS = 5_000;
const SAMPLE = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  namespace: production
spec:
  replicas: 1
  selector:
    matchLabels:
      app: payments-api
  template:
    metadata:
      labels:
        app: payments-api
    spec:
      hostNetwork: true
      containers:
        - name: api
          image: example.com/payments-api:latest
          ports:
            - containerPort: 8080
          resources:
            requests:
              cpu: "100m"
            limits:
              cpu: "500m"
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
`;
const CLEAN_SAMPLE = `apiVersion: apps/v1
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
`;
function safeHelpUri(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length > 2_048) return undefined;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" ? parsed.href : undefined;
  } catch {
    return undefined;
  }
}

function analysisFromSarif(raw: unknown): Analysis {
  const report = obj(raw);
  const runs = Array.isArray(report.runs) ? report.runs : [];
  if (!runs.length) throw new Error("This file does not contain a SARIF runs array.");
  if (runs.length > 50) throw new Error("SARIF report exceeds the 50-run safety limit.");

  const findings: Finding[] = [];
  const seen = new Set<string>();
  const manifestsWithFindings = new Set<string>();

  let importedResultCount = 0;
  let importedRuleCount = 0;
  for (const runValue of runs) {
    const run = obj(runValue);
    const driver = obj(obj(run.tool).driver);
    const rules = Array.isArray(driver.rules) ? driver.rules.map(obj) : [];
    importedRuleCount += rules.length;
    if (importedRuleCount > 10_000) throw new Error("SARIF report exceeds the 10,000-rule safety limit.");
    const results = Array.isArray(run.results) ? run.results : [];
    if (results.length > MAX_FINDINGS - importedResultCount) throw new Error("SARIF report exceeds the 5,000-result safety limit.");

    for (const item of results) {
      importedResultCount += 1;
      if (importedResultCount > MAX_FINDINGS) throw new Error("SARIF report exceeds the 5,000-result safety limit.");
      const result = obj(item);
      const ruleId = boundedText(result.ruleId, "rule ID", 256) || "KUBESCAPE_FINDING";
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
      const uri = boundedText(artifact.uri || "manifest", "artifact URI", 2_048);
      const line = region.startLine ? ":" + region.startLine : "";
      const path = uri + line;
      const message = boundedText(
        obj(result.message).text || obj(descriptor.shortDescription).text || ruleId,
        "result message", 4_096
      );
      const key = ruleId + "|" + path + "|" + message;
      if (seen.has(key)) continue;
      seen.add(key);
      manifestsWithFindings.add(uri);

      const affectedText = message + "\n" + String(resultProperties.affectedResources || resultProperties.affectedFields || "");
      const containerMatch = affectedText.match(/\(([^()]+)\)/);
      const container = containerMatch?.[1];
      const resourceFromProps = String(resultProperties.resourceName || resultProperties.resource || resultProperties.workload || "");
      const resource = resourceFromProps || (container ? "Container: " + container : "Workload not specified");
      const namespace = String(resultProperties.namespace || "");
      const title = boundedText(
        obj(descriptor.shortDescription).text || obj(result.message).text || ruleId.replace(/[-_]/g, " "),
        "rule title", 1_024
      );
      const helpText = boundedText(
        obj(resultProperties).remediation || obj(resultProperties).recommendation || obj(descriptor.help).text ||
        "Review the Kubescape control details and remediate the configuration before deployment.",
        "recommendation", 4_096
      );
      findings.push({
        rule_id: ruleId,
        severity,
        title,
        message,
        path,
        recommendation: helpText,
        help_uri: safeHelpUri(descriptor.helpUri),
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
  const [view, setView] = useState<"home" | "workspace">("home");
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
  const activeFilterCount = Number(filter !== "all") + Number(resourceFilter !== "all") + Number(ruleFilter !== "all") + Number(Boolean(search.trim()));
  function resetFilters() { setFilter("all"); setResourceFilter("all"); setRuleFilter("all"); setSearch(""); }
  const selectedFinding = visible.find((item) => item.rule_id + item.path === selected) || visible[0];
  function run() {
    try { const result = analyzeYaml(yaml); setAnalysis(result); setError(""); setFilter("all"); setSearch(""); setResourceFilter("all"); setRuleFilter("all"); setSelected(result.findings[0] ? result.findings[0].rule_id + result.findings[0].path : ""); }
    catch (err) { setAnalysis(null); setError(err instanceof Error ? err.message : "Analysis failed."); }
  }
  function loadFile(file?: File) {
    if (!file) return;
    if (file.size > MAX_INPUT_BYTES) {
      setError("File exceeds the 1 MB safety limit. Split the report or use a smaller sample.");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const content = String(reader.result || "");
      if (content.includes("\u0000")) {
        setError("This looks like a ZIP or binary file. Extract it first, then choose a YAML or SARIF report.");
        return;
      }
      try {
        if (/\.(sarif|json)$/i.test(file.name)) {
          const parsed = JSON.parse(content);
          if (/\.sarif$/i.test(file.name) || Array.isArray(obj(parsed).runs)) {
            const imported = analysisFromSarif(parsed);
            setAnalysis(imported);
            setFilter("all");
            setSearch(""); setResourceFilter("all"); setRuleFilter("all");
            setSelected(imported.findings[0] ? imported.findings[0].rule_id + imported.findings[0].path : "");
          } else {
            // JSON is valid YAML syntax too; allow Kubernetes JSON manifests.
            setYaml(content);
            setAnalysis(null); setFilter("all"); setSearch(""); setResourceFilter("all"); setRuleFilter("all");
          }
        } else {
          setYaml(content);
          setAnalysis(null); setFilter("all"); setSearch(""); setResourceFilter("all"); setRuleFilter("all");
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
  if (view === "home") return <div className="marketing-shell">
    <header className="marketing-nav">
      <a className="marketing-brand" href="#top" onClick={(e) => { e.preventDefault(); window.scrollTo({top:0,behavior:"smooth"}); }}><span className="marketing-mark"><Layers3 size={19}/></span><span>deploy<span>dash</span></span></a>
      <nav className="marketing-links"><a href="#platform">Platform</a><a href="#how-it-works">How it works</a><a href="#trust">Security model</a></nav>
      <div className="marketing-nav-actions"><a className="nav-github" href="https://github.com/sunkaradp/deployment-dash-intelligence" target="_blank" rel="noreferrer"><GitBranch size={15}/> GitHub</a><button className="nav-cta" onClick={() => { setView("workspace"); window.scrollTo(0,0); }}>Open analyzer <ArrowRight size={15}/></button></div>
    </header>
    <main id="top">
      <section className="marketing-hero">
        <div className="hero-copy"><div className="hero-kicker"><span/> KUBERNETES DEPLOYMENT INTELLIGENCE</div>
          <h1>Ship with<br/><em>fewer unknowns.</em></h1>
          <p className="hero-lede">Understand what your Kubernetes manifests are telling you before they reach production. Clear, actionable deployment and security signals — without handing over your cluster.</p>
          <div className="hero-actions"><button className="hero-primary" onClick={() => { setView("workspace"); window.scrollTo(0,0); }}>Analyze a manifest <ArrowRight size={17}/></button><a className="hero-secondary" href="#platform">Explore the platform <ArrowDownToLine size={15}/></a></div>
          <div className="hero-proof"><span><LockKeyhole size={14}/> Local browser analysis</span><i/><span><ShieldCheck size={14}/> Read-only by design</span><i/><span><FileCode2 size={14}/> YAML · JSON · SARIF</span></div>
        </div>
        <div className="hero-visual" aria-label="Illustrative Deployment Dash analysis interface">
          <div className="visual-orbit orbit-one"/><div className="visual-orbit orbit-two"/>
          <div className="preview-window">
            <div className="preview-top"><div className="preview-dots"><i/><i/><i/></div><span>DEPLOYMENT REVIEW / LOCAL</span><span className="preview-live"><b/> READY</span></div>
            <div className="preview-body">
              <div className="preview-heading"><div><small>WORKLOAD ANALYSIS</small><strong>payments-api</strong><span>Deployment · production</span></div><div className="preview-score"><strong>68</strong><small>/ 100</small></div></div>
              <div className="preview-meter"><i/></div>
              <div className="preview-stats"><div><strong>03</strong><span>Findings</span></div><div><strong>02</strong><span>Security</span></div><div><strong>01</strong><span>Reliability</span></div></div>
              <div className="preview-divider"/>
              <div className="preview-section-label">PRIORITY FINDINGS <span>ILLUSTRATIVE PREVIEW</span></div>
              <div className="preview-finding"><span className="finding-dot critical-dot"/><div><strong>Privileged container</strong><small>spec.containers[0].securityContext</small></div><b>CRITICAL</b></div>
              <div className="preview-finding"><span className="finding-dot high-dot"/><div><strong>Host networking enabled</strong><small>spec.template.spec.hostNetwork</small></div><b>HIGH</b></div>
              <div className="preview-finding"><span className="finding-dot medium-dot"/><div><strong>Resource requests incomplete</strong><small>spec.containers[0].resources</small></div><b>MEDIUM</b></div>
              <div className="preview-bottom"><ShieldCheck size={14}/> Findings are advisory. No cluster changes are made.</div>
            </div>
          </div>
          <div className="visual-caption"><span>01 / MANIFEST INSPECTION</span><span>BUILT FOR THE RELEASE PATH</span></div>
        </div>
        <div className="hero-index"><span>01</span><i/> PRE-DEPLOYMENT VISIBILITY</div>
      </section>
      <section className="marquee-strip"><span>MANIFEST FIRST</span><i/><span>ENGINEER EXPLAINABLE</span><i/><span>READ-ONLY BY DEFAULT</span><i/><span>KUBERNETES NATIVE</span></section>
      <section className="platform-section" id="platform">
        <div className="section-intro"><div className="section-kicker">01 — THE PLATFORM</div><div><h2>Clarity at the point<br/>where risk begins.</h2><p>Deployment Dash reviews the configuration you intend to ship, highlights what deserves attention, and gives engineers a practical next step.</p></div></div>
        <div className="feature-grid">
          <article className="feature-card feature-large"><div className="feature-number">01 / CONFIGURATION</div><div className="feature-art config-art"><div className="config-line"><span>spec:</span><b>template</b></div><div className="config-line indent"><span>securityContext:</span></div><div className="config-line indent-two"><span>runAsNonRoot:</span><b className="code-good">true</b></div><div className="config-line indent-two"><span>allowPrivilegeEscalation:</span><b className="code-bad">true</b></div><div className="config-warning"><AlertTriangle size={13}/> Review privilege escalation setting</div></div><h3>See beyond valid YAML.</h3><p>Surface configuration gaps across workload reliability and container security — with evidence linked to the exact manifest path.</p></article>
          <article className="feature-card"><div className="feature-number">02 / PRIORITIZATION</div><div className="feature-art priority-art"><div className="priority-row"><i className="p-critical"/> Critical <b>01</b></div><div className="priority-row"><i className="p-high"/> High <b>02</b></div><div className="priority-row"><i className="p-medium"/> Medium <b>04</b></div><div className="priority-row"><i className="p-low"/> Low <b>03</b></div></div><h3>Know what to fix first.</h3><p>Review findings by severity, resource and control. Keep the signal focused on actionable work.</p></article>
          <article className="feature-card"><div className="feature-number">03 / WORKFLOW</div><div className="feature-art workflow-art"><div><FileCode2 size={17}/><span>manifest.yaml</span><b>01</b></div><i/><div><ShieldCheck size={17}/><span>analysis</span><b>02</b></div><i/><div><CheckCircle2 size={17}/><span>review</span><b>03</b></div></div><h3>Fit into the way teams ship.</h3><p>Start with a local review. Import Kubescape SARIF reports from your existing GitHub Actions workflow.</p></article>
        </div>
      </section>
      <section className="manifest-section" id="how-it-works"><div className="manifest-copy"><div className="section-kicker">02 — A PRACTICAL WORKFLOW</div><h2>From manifest<br/>to meaningful<br/><em>next steps.</em></h2><p>No platform migration. No cluster credentials. Bring a Kubernetes manifest or an existing SARIF report and inspect it in your browser.</p><button className="manifest-cta" onClick={() => { setView("workspace"); window.scrollTo(0,0); }}>Try the analyzer <ArrowRight size={16}/></button></div><div className="workflow-steps"><div className="workflow-step"><span>01</span><div><h3>Provide the configuration</h3><p>Paste YAML or upload YAML, JSON, or a SARIF report generated by your scanner.</p></div><b>INPUT</b></div><div className="workflow-step"><span>02</span><div><h3>Run deterministic checks</h3><p>Review explicit rules for workload configuration, reliability signals and container security posture.</p></div><b>ANALYZE</b></div><div className="workflow-step"><span>03</span><div><h3>Prioritize the review</h3><p>Inspect severity, affected resources, evidence paths and remediation guidance. Export a JSON report.</p></div><b>REVIEW</b></div></div></section>
      <section className="trust-section" id="trust"><div className="trust-top"><div className="section-kicker">03 — TRUST IS AN ENGINEERING REQUIREMENT</div><h2>Useful insight.<br/><em>Without taking control.</em></h2></div><div className="trust-grid"><div><LockKeyhole size={20}/><h3>Your manifest stays local</h3><p>Browser analysis runs on the device. The static demo does not upload your YAML to a hosted analysis service.</p></div><div><ShieldCheck size={20}/><h3>Read-only by design</h3><p>No cluster connection, deployment, patch, restart or automatic remediation is performed.</p></div><div><Info size={20}/><h3>Honest about its scope</h3><p>Rules are advisory configuration checks — not a compliance certification or proof of runtime safety.</p></div></div></section>
      <section className="closing-section"><div className="section-kicker">DEPLOYMENT DASH INTELLIGENCE</div><h2>Make the next deployment<br/>a more informed one.</h2><button onClick={() => { setView("workspace"); window.scrollTo(0,0); }}>Open the analyzer <ArrowRight size={17}/></button><span>MANIFEST IN. CLEARER SIGNAL OUT.</span></section>
    </main>
    <footer className="marketing-footer"><a className="marketing-brand" href="#top"><span className="marketing-mark"><Layers3 size={17}/></span><span>deploy<span>dash</span></span></a><span>Independent Kubernetes deployment analysis.</span><a href="https://github.com/sunkaradp/deployment-dash-intelligence" target="_blank" rel="noreferrer">Open source on GitHub <ArrowRight size={13}/></a></footer>
  </div>;
  return <div className="app-shell">
    <aside className="sidebar">
      <a className="brand" href="#overview" onClick={(e) => { e.preventDefault(); setView("home"); window.scrollTo(0,0); }}><span className="brand-mark"><Layers3 size={19}/></span><span><strong>deploy<span>dash</span></strong><small>DEPLOYMENT REVIEW</small></span></a>
      <div className="side-label">WORKSPACE</div>
      <div className="side-item active"><Gauge size={17}/> Readiness analysis <i/></div>
      
      <div className="side-label side-label-bottom">PROJECT</div>
      <a className="side-item" href="https://github.com/sunkaradp/deployment-dash-intelligence" target="_blank" rel="noreferrer"><GitBranch size={17}/> GitHub repository <ArrowRight size={14}/></a>
      <div className="sidebar-foot"><div className="status-line"><span/> LOCAL ANALYSIS ENGINE</div><p>Manifest checks run in your browser. No cluster credentials required.</p><div className="version">LOCAL · READ ONLY</div></div>
    </aside>
    <main className="main-area">
      <header className="topbar"><div className="breadcrumb"><button className="breadcrumb-home" onClick={() => { setView("home"); window.scrollTo(0,0); }}>deploydash</button> <span>/</span> <strong>Readiness analysis</strong></div><div className="top-actions"><span className="privacy"><LockKeyhole size={13}/> READ-ONLY MODE</span><a href="https://github.com/sunkaradp/deployment-dash-intelligence" target="_blank" rel="noreferrer"><GitBranch size={16}/> Source</a></div></header>
      <section className="page-intro"><div><div className="eyebrow"><span/> PRE-DEPLOYMENT CHECK</div><h1>Know the risk <em>before</em> you ship.</h1><p>Inspect Kubernetes workload manifests for configuration gaps and security risks. Get clear findings your team can act on.</p></div><div className="intro-note"><ShieldCheck size={18}/><span><strong>Safe by design</strong><small>No cluster access. No changes applied.</small></span></div></section>
      <section className="workspace-grid">
        <div className="panel editor-panel">
          <div className="panel-head"><div className="panel-title"><span className="panel-icon"><FileCode2 size={17}/></span><div><h2>Manifest input</h2><p>Paste YAML or upload a file</p></div></div><div className="file-pill"><i/> {fileName || "deployment.yaml"}</div></div>
          <div className="editor-toolbar"><span><b>Y</b> YAML</span><div className="editor-tools"><button onClick={() => { setYaml(SAMPLE); setFileName(""); setAnalysis(null); setError(""); }}><RotateCcw size={13}/> Risky sample</button><button onClick={() => { setYaml(CLEAN_SAMPLE); setFileName(""); setAnalysis(null); setError(""); }}><CheckCircle2 size={13}/> Clean sample</button><button onClick={() => { setYaml(""); setFileName(""); setAnalysis(null); setError(""); }}><X size={13}/> Clear</button></div></div>
          <div className="code-wrap"><div className="line-numbers">{yaml.split("\n").map((_, i) => <span key={i}>{i + 1}</span>)}</div><textarea spellCheck={false} aria-label="Kubernetes YAML manifest" value={yaml} onChange={(e) => { setYaml(e.target.value); setAnalysis(null); setError(""); }} placeholder={"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: my-app"}/></div>
          <div className="editor-bottom"><button onClick={() => fileRef.current?.click()}><Upload size={15}/> Upload YAML / JSON / SARIF</button><input ref={fileRef} type="file" accept=".yaml,.yml,.sarif,.json,.txt,text/yaml,application/json,text/plain,application/x-yaml" hidden onChange={(e) => { const file = e.target.files?.[0]; loadFile(file); e.currentTarget.value = ""; }}/><span>{yaml.split("\n").length} lines · {new Blob([yaml]).size.toLocaleString()} bytes</span></div>
          {error && <div className="error-banner"><AlertCircle size={16}/>{error}</div>}
          <button className="analyze-btn" onClick={run}><Play size={16} fill="currentColor"/> Analyze manifest <ArrowRight size={16}/></button>
          <div className="editor-footnote"><LockKeyhole size={12}/> Analysis runs locally in this browser. Your YAML is not uploaded.</div>
        </div>
        <div className="results-column">
          {!analysis ? <div className="empty-panel panel"><div className="empty-illustration"><div><ShieldCheck size={34}/></div><i/><b/></div><div className="empty-copy"><span className="eyebrow">WAITING FOR INPUT</span><h2>Your deployment review starts here.</h2><p>Run an analysis to see a risk score, prioritized findings and recommendations tied to exact manifest paths.</p></div><div className="empty-steps"><div><span>01</span><p><strong>Provide a manifest</strong><small>Paste YAML or upload a file</small></p></div><div><span>02</span><p><strong>Run the checks</strong><small>Deterministic rules, no AI guesswork</small></p></div><div><span>03</span><p><strong>Review the findings</strong><small>Prioritize before deployment</small></p></div></div></div> :
            <>
              <div className="score-panel panel"><div className="score-head"><div><span className="eyebrow">{analysis.source === "sarif" ? "LOCAL WEIGHTED INDICATOR" : "DEPLOYMENT RISK"}</span><h2>{analysis.source === "sarif" ? "Imported scan overview" : "Readiness overview"}</h2></div><button className="download-btn" onClick={exportReport}><ArrowDownToLine size={14}/> Export report</button></div>
                <div className="score-content"><div className={"score-ring " + analysis.risk_level} style={{ "--score": (analysis.risk_score * 3.6) + "deg" } as React.CSSProperties}><div><strong>{analysis.risk_score}</strong><small>/ 100</small></div></div><div className="score-description"><span className={"risk-label " + analysis.risk_level}>{analysis.risk_level.toUpperCase()} RISK</span><h3>{analysis.source === "sarif" ? `${analysis.scanner_name || "Scanner"} findings imported` : analysis.risk_score === 0 ? "No configured risks found" : analysis.risk_score >= 60 ? "Needs attention before release" : analysis.risk_score >= 35 ? "Review before deployment" : "Some improvements recommended"}</h3><p>{analysis.source === "sarif" ? `${analysis.summary.workloads_analyzed} manifest file(s) with findings` : `${analysis.summary.workloads_analyzed} workload(s) analyzed`} · {analysis.summary.findings} finding(s) detected</p></div></div>
                <div className="severity-row"><button className={"severity-stat all " + (filter === "all" ? "chosen" : "")} onClick={resetFilters}><span>{analysis.summary.findings}</span><small>All</small></button>{(["critical", "high", "medium", "low"] as Severity[]).map((level) => <button key={level} className={"severity-stat " + level + (filter === level ? " chosen" : "")} onClick={() => setFilter(filter === level ? "all" : level)}><span>{analysis.summary.by_severity[level]}</span><small>{level}</small></button>)}</div>{analysis.source === "sarif" && <p className="score-disclaimer">Scanner severities above are preserved for display. The {analysis.risk_score}/100 indicator is a local weighted heuristic, not the scanner\u2019s score or a compliance rating.</p>}
              </div>
              <div className="findings-panel panel"><div className="findings-head"><div><h2>Findings <span>{visible.length === analysis.findings.length ? "All " + analysis.findings.length : visible.length + " of " + analysis.findings.length}</span></h2><p>{activeFilterCount ? activeFilterCount + " active filter" + (activeFilterCount === 1 ? "" : "s") + " · " : ""}Search and filter scanner results by severity, resource or control</p></div><button className="filter-btn" disabled={activeFilterCount === 0} onClick={resetFilters}>Reset filters <RotateCcw size={12}/></button></div><div className="finding-filters"><input aria-label="Search findings" placeholder="Search title, path, message…" value={search} onChange={(e) => setSearch(e.target.value)}/><select aria-label="Filter by resource" value={resourceFilter} onChange={(e) => setResourceFilter(e.target.value)}><option value="all">All resources</option>{resources.map((item) => <option key={item} value={item}>{item}</option>)}</select><select aria-label="Filter by control" value={ruleFilter} onChange={(e) => setRuleFilter(e.target.value)}><option value="all">All controls</option>{rules.map((item) => <option key={item} value={item}>{item}</option>)}</select></div>{activeFilterCount > 0 && <div className="active-filter-bar"><span className="active-filter-label">ACTIVE FILTERS</span>{filter !== "all" && <button className="filter-chip" onClick={() => setFilter("all")}>Severity: {filter} <X size={11}/></button>}{resourceFilter !== "all" && <button className="filter-chip" onClick={() => setResourceFilter("all")}>Resource: {resourceFilter} <X size={11}/></button>}{ruleFilter !== "all" && <button className="filter-chip" onClick={() => setRuleFilter("all")}>Control: {ruleFilter} <X size={11}/></button>}{search.trim() && <button className="filter-chip" onClick={() => setSearch("")}>Search: “{search.trim()}” <X size={11}/></button>}<button className="clear-filter-link" onClick={resetFilters}>Clear all</button></div>}
                {visible.length === 0 ? <div className="no-findings"><CheckCircle2 size={22}/><strong>No findings in this category</strong><span>Nothing to review here.</span></div> :
                  <div className="finding-list">{visible.map((item) => <button key={item.rule_id + item.path} className={"finding-item " + (selectedFinding === item ? "selected" : "")} onClick={() => setSelected(item.rule_id + item.path)}><span className={"finding-symbol " + item.severity}>{item.severity === "critical" || item.severity === "high" ? <AlertTriangle size={15}/> : <Info size={15}/>}</span><span className="finding-main"><strong>{item.title}</strong><small>{item.resource || "Resource not specified"}{item.container ? " · " + item.container : ""} · {item.path}</small></span><span className={"severity-tag " + item.severity}>{item.severity}</span><ArrowRight size={14} className="finding-arrow"/></button>)}</div>}
                {selectedFinding && <div className="finding-detail"><div className="detail-top"><span>SELECTED FINDING</span><code>{selectedFinding.rule_id}</code></div><h3>{selectedFinding.title}</h3><p>{selectedFinding.message}</p><div className="resource-meta"><span><b>Resource</b>{selectedFinding.resource || "Not provided by scanner"}</span>{selectedFinding.container && <span><b>Container</b>{selectedFinding.container}</span>}<span><b>Namespace</b>{selectedFinding.namespace || "Not provided by scanner"}</span></div><div className="detail-path"><Terminal size={13}/><code>{selectedFinding.path}</code><button title="Copy path" onClick={() => navigator.clipboard?.writeText(selectedFinding.path)}><Clipboard size={13}/></button></div><div className="recommendation"><span><Sparkles size={14}/> RECOMMENDATION</span><p>{selectedFinding.recommendation}</p>{selectedFinding.help_uri && <a className="control-link" href={selectedFinding.help_uri} target="_blank" rel="noreferrer">Open scanner control documentation <ArrowRight size={12}/></a>}</div>{analysis.source === "yaml" && proposedFix(selectedFinding) && <div className="fix-preview"><div className="fix-preview-head"><span><FileCode2 size={14}/> PROPOSED YAML PATCH</span><button onClick={() => navigator.clipboard?.writeText(proposedFix(selectedFinding)!.yaml)}><Clipboard size={13}/> Copy snippet</button></div><pre><code>{proposedFix(selectedFinding)!.yaml}</code></pre><p>{proposedFix(selectedFinding)!.note}</p><small>This is a context snippet, not an automatic edit to your manifest. Merge it into the existing field and review before deployment.</small></div>}</div>}
              </div>
            </>}
        </div>
      </section>
      <footer className="page-footer"><span><ShieldAlert size={13}/> Advisory checks only — validate findings against workload requirements.</span><span>Built for engineers who ship to Kubernetes.</span></footer>
    </main>
  </div>;
}
createRoot(document.getElementById("root")!).render(<React.StrictMode><App/></React.StrictMode>);
