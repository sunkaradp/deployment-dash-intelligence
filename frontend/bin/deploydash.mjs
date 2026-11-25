#!/usr/bin/env node
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { analyzeYaml } from "../.cli-build/analyzer.js";

const MAX_FILES = 200;
const MAX_FILE_BYTES = 1_000_000;

function usage() {
  process.stdout.write("Deploy Dash CLI\n\nUsage: npm run deploydash -- <file-or-directory> [--json]\n\nScans YAML/JSON Kubernetes manifests. Read-only; no cluster access.\n");
}

async function collect(target, files) {
  const info = await stat(target);
  if (info.isFile()) {
    if (/\.(ya?ml|json)$/i.test(target)) files.push(target);
    return;
  }
  if (!info.isDirectory()) return;
  const entries = await readdir(target, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith(".") || entry.name === "node_modules") continue;
    const child = path.join(target, entry.name);
    if (entry.isDirectory()) await collect(child, files);
    else if (entry.isFile() && /\.(ya?ml|json)$/i.test(entry.name)) files.push(child);
    if (files.length > MAX_FILES) throw new Error(`Input contains more than ${MAX_FILES} manifest files.`);
  }
}

const args = process.argv.slice(2);
if (args.includes("--help") || args.length === 0) {
  usage();
  process.exit(args.length === 0 ? 2 : 0);
}
const jsonOutput = args.includes("--json");
const targets = args.filter((arg) => arg !== "--json");
const files = [];
try {
  for (const value of targets) {
    const target = path.resolve(process.cwd(), value);
    await collect(target, files);
  }
  const uniqueFiles = [...new Set(files)].sort();
  if (!uniqueFiles.length) throw new Error("No .yaml, .yml or .json manifest files found.");
  const reports = [];
  for (const file of uniqueFiles) {
    const info = await stat(file);
    if (info.size > MAX_FILE_BYTES) {
      reports.push({ file: path.relative(process.cwd(), file), error: "File exceeds the 1 MB safety limit." });
      continue;
    }
    const source = await readFile(file, "utf8");
    try {
      reports.push({ file: path.relative(process.cwd(), file), ...analyzeYaml(source) });
    } catch (error) {
      reports.push({ file: path.relative(process.cwd(), file), error: error instanceof Error ? error.message : "Analysis failed." });
    }
  }
  if (jsonOutput) {
    process.stdout.write(JSON.stringify({ scanner: "Deploy Dash", version: "0.1.0", reports }, null, 2) + "\n");
  } else {
    for (const report of reports) {
      process.stdout.write(`\n${report.file}\n`);
      if (report.error) {
        process.stdout.write(`  ERROR  ${report.error}\n`);
        continue;
      }
      process.stdout.write(`  Risk: ${report.risk_level.toUpperCase()} (${report.risk_score}/100) · ${report.summary.findings} findings\n`);
      for (const finding of report.findings) {
        process.stdout.write(`  [${finding.severity.toUpperCase()}] ${finding.rule_id} — ${finding.title}\n    ${finding.path}\n    ${finding.recommendation}\n`);
      }
    }
  }
  const hasErrors = reports.some((report) => report.error);
  const hasFindings = reports.some((report) => report.findings?.length);
  process.exitCode = hasErrors ? 2 : hasFindings ? 1 : 0;
} catch (error) {
  process.stderr.write((error instanceof Error ? error.message : "Scan failed.") + "\n");
  process.exitCode = 2;
}
