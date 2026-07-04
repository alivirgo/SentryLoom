#!/usr/bin/env node
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const historyFile = path.join(root, "docs", "community-metrics.json");
const chartFile = path.join(root, "docs", "community-metrics.svg");
const repository = process.env.GITHUB_REPOSITORY || "alivirgo/SentryLoom";
const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN || "";

async function github(route) {
  const response = await fetch(`https://api.github.com${route}`, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "SentryLoom-community-metrics",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    }
  });
  if (!response.ok) throw new Error(`GitHub API ${route} failed (${response.status})`);
  return response.json();
}

async function contributorCount() {
  let page = 1;
  let total = 0;
  while (page <= 100) {
    const contributors = await github(`/repos/${repository}/contributors?anon=1&per_page=100&page=${page}`);
    total += contributors.length;
    if (contributors.length < 100) break;
    page += 1;
  }
  return total;
}

function escapeXml(value) {
  return String(value).replace(/[<>&"']/g, (character) => ({
    "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&apos;"
  })[character]);
}

function render(samples) {
  const width = 960;
  const height = 440;
  const left = 72;
  const right = 28;
  const top = 54;
  const bottom = 72;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const maximum = Math.max(1, ...samples.flatMap((sample) => [sample.stars, sample.contributors]));
  const roundedMaximum = Math.max(5, Math.ceil(maximum / 5) * 5);
  const x = (index) => samples.length === 1
    ? left + plotWidth / 2
    : left + (index / (samples.length - 1)) * plotWidth;
  const y = (value) => top + plotHeight - (value / roundedMaximum) * plotHeight;
  const points = (key) => samples.map((sample, index) =>
    `${x(index).toFixed(1)},${y(sample[key]).toFixed(1)}`
  ).join(" ");
  const yTicks = Array.from({ length: 6 }, (_, index) => {
    const value = Math.round((roundedMaximum / 5) * index);
    const position = y(value);
    return `<line x1="${left}" y1="${position}" x2="${width - right}" y2="${position}" class="grid"/>
      <text x="${left - 12}" y="${position + 4}" text-anchor="end" class="tick">${value}</text>`;
  }).join("\n");
  const dateIndexes = [...new Set([0, Math.floor((samples.length - 1) / 2), samples.length - 1])];
  const xTicks = dateIndexes.map((index) =>
    `<text x="${x(index)}" y="${height - 32}" text-anchor="middle" class="tick">${escapeXml(samples[index].date)}</text>`
  ).join("\n");
  const latest = samples.at(-1);

  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="title desc">
  <title id="title">SentryLoom GitHub community growth</title>
  <desc id="desc">Time-series lines for GitHub stars and current contributors. Latest values: ${latest.stars} stars and ${latest.contributors} contributors.</desc>
  <style>
    .background{fill:#0d1117}.plot{fill:#161b22;stroke:#30363d}.grid{stroke:#30363d;stroke-width:1}.axis{stroke:#8b949e;stroke-width:1.2}
    .title{fill:#f0f6fc;font:700 22px "Segoe UI",Arial,sans-serif}.subtitle{fill:#8b949e;font:13px "Segoe UI",Arial,sans-serif}
    .tick{fill:#8b949e;font:11px "Segoe UI",Arial,sans-serif}.legend{fill:#c9d1d9;font:13px "Segoe UI",Arial,sans-serif}
    .stars{fill:none;stroke:#f2cc60;stroke-width:3;stroke-linejoin:round;stroke-linecap:round}
    .contributors{fill:none;stroke:#2f81f7;stroke-width:3;stroke-linejoin:round;stroke-linecap:round}
    .star-dot{fill:#f2cc60}.contributor-dot{fill:#2f81f7}
  </style>
  <rect width="100%" height="100%" rx="12" class="background"/>
  <text x="${left}" y="30" class="title">SentryLoom community growth</text>
  <text x="${width - right}" y="30" text-anchor="end" class="subtitle">Updated ${escapeXml(latest.date)}</text>
  <rect x="${left}" y="${top}" width="${plotWidth}" height="${plotHeight}" rx="6" class="plot"/>
  ${yTicks}
  <line x1="${left}" y1="${top + plotHeight}" x2="${width - right}" y2="${top + plotHeight}" class="axis"/>
  <polyline points="${points("stars")}" class="stars"/>
  <polyline points="${points("contributors")}" class="contributors"/>
  ${samples.map((sample, index) => `<circle cx="${x(index)}" cy="${y(sample.stars)}" r="3.5" class="star-dot"/>`).join("\n  ")}
  ${samples.map((sample, index) => `<circle cx="${x(index)}" cy="${y(sample.contributors)}" r="3.5" class="contributor-dot"/>`).join("\n  ")}
  ${xTicks}
  <circle cx="${left}" cy="${height - 10}" r="5" class="star-dot"/>
  <text x="${left + 12}" y="${height - 6}" class="legend">GitHub stars (${latest.stars})</text>
  <circle cx="${left + 175}" cy="${height - 10}" r="5" class="contributor-dot"/>
  <text x="${left + 187}" y="${height - 6}" class="legend">Current contributors (${latest.contributors})</text>
</svg>
`;
}

let history;
try {
  history = JSON.parse(await fs.readFile(historyFile, "utf8"));
} catch {
  history = { schemaVersion: 1, repository, samples: [] };
}

if (token) {
  const [repo, contributors] = await Promise.all([
    github(`/repos/${repository}`),
    contributorCount()
  ]);
  const sample = {
    date: new Date().toISOString().slice(0, 10),
    stars: Number(repo.stargazers_count) || 0,
    contributors
  };
  const existing = history.samples.findIndex((item) => item.date === sample.date);
  if (existing === -1) history.samples.push(sample);
  else history.samples[existing] = sample;
}

history.repository = repository;
history.samples = history.samples
  .sort((left, right) => left.date.localeCompare(right.date))
  .slice(-730);
if (!history.samples.length) {
  history.samples.push({
    date: new Date().toISOString().slice(0, 10),
    stars: 0,
    contributors: 1
  });
}

await fs.mkdir(path.dirname(historyFile), { recursive: true });
await fs.writeFile(historyFile, `${JSON.stringify(history, null, 2)}\n`);
await fs.writeFile(chartFile, render(history.samples));
console.log(`Rendered ${history.samples.length} community metric sample(s) for ${repository}.`);
