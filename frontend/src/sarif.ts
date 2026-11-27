import type { Analysis, Finding, Severity } from "./analyzer.js";
const MAX_FINDINGS = 5_000;
function obj(value: unknown): Record<string, any> { return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, any> : {}; }
function boundedText(value: unknown, field: string, maxLength: number): string { if (value == null) return ""; if (typeof value !== "string") throw new Error("SARIF " + field + " must be a string."); if (value.length > maxLength) throw new Error("SARIF " + field + " exceeds the " + maxLength + " character safety limit."); return value; }
function safeHelpUri(value: unknown): string | undefined { if (typeof value !== "string" || value.length > 2_048) return undefined; try { const parsed = new URL(value); return parsed.protocol === "https:" ? parsed.href : undefined; } catch { return undefined; } }
export function analysisFromSarif(raw: unknown): Analysis {
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
    const rulesById = new Map<string, Record<string, any>>();
    for (const rule of rules) { if (typeof rule.id === "string" && !rulesById.has(rule.id)) rulesById.set(rule.id, rule); }
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
      const descriptor = rulesById.get(ruleId) || (ruleIndex >= 0 && ruleIndex < rules.length ? rules[ruleIndex] : undefined) || {};
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
