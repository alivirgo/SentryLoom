#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";

const blockedExtensions = new Set([
  ".der", ".enc", ".jks", ".key", ".keystore", ".p12", ".pem", ".pfx"
]);
const blockedNames = new Set([".env", "master.key"]);
const patterns = [
  ["private key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ["GitHub token", /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/],
  ["AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
  ["Slack token", /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/],
  ["Stripe live key", /\bsk_live_[A-Za-z0-9]{20,}\b/],
  ["JWT bearer token", /\bBearer\s+eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\./i]
];

const files = execFileSync("git", [
  "ls-files", "--cached", "--others", "--exclude-standard"
], { encoding: "utf8" }).split(/\r?\n/).filter(Boolean);

const findings = [];
for (const relative of files) {
  const normalized = relative.replaceAll("\\", "/");
  const extension = path.extname(normalized).toLowerCase();
  const name = path.basename(normalized).toLowerCase();
  if (blockedExtensions.has(extension) || blockedNames.has(name)) {
    findings.push(`${normalized}: sensitive file type must not be committed`);
    continue;
  }
  const stat = fs.statSync(relative);
  if (!stat.isFile() || stat.size > 5 * 1024 * 1024) continue;
  const buffer = fs.readFileSync(relative);
  if (buffer.includes(0)) continue;
  const text = buffer.toString("utf8");
  for (const [label, pattern] of patterns) {
    if (pattern.test(text)) findings.push(`${normalized}: possible ${label}`);
  }
}

if (findings.length) {
  console.error("Secret audit failed:\n" + findings.map((item) => `- ${item}`).join("\n"));
  process.exitCode = 1;
} else {
  console.log(`Secret audit passed for ${files.length} source files.`);
}
