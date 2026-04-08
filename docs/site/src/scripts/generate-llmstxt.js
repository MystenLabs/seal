// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

const fs = require("fs");
const path = require("path");

// ── CLI args ─────────────────────────────────────────────────────────────────
const args = process.argv.slice(2);
const flags = {};
const positional = [];

for (let i = 0; i < args.length; i++) {
  if (args[i].startsWith("--")) {
    flags[args[i].slice(2)] = args[i + 1];
    i++;
  } else {
    positional.push(args[i]);
  }
}

const scriptDir = __dirname;
const markdownDir = path.resolve(positional[0] ?? path.join(scriptDir, "../../../content"));
const outputFile = flags["output"] ?? path.join(scriptDir, "../../static/llms.txt");
const baseUrl = flags["base-url"] ?? "https://seal-docs.wal.app";

// ── Constants ────────────────────────────────────────────────────────────────
const TARGET_CHARS = 100_000;

// ── Helpers ──────────────────────────────────────────────────────────────────

const IGNORE_DIRS = new Set([
  "snippets",
]);

const IGNORE_PATHS = new Set([
]);

const IGNORE_FILES = new Set([
  "index.mdx",
  "index.md",
]);

function walk(dir, results = []) {
  if (!fs.existsSync(dir)) return results;

  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(markdownDir, full).replace(/\\/g, "/");

    if (entry.isDirectory()) {
      if (IGNORE_DIRS.has(entry.name)) continue;
      if (IGNORE_PATHS.has(rel)) continue;
      walk(full, results);
    } else if (entry.name.endsWith(".md") || entry.name.endsWith(".mdx")) {
      if (IGNORE_FILES.has(rel)) continue;
      // Skip Docusaurus partials (underscore-prefixed files)
      if (entry.name.startsWith("_")) continue;
      results.push(full);
    }
  }

  return results;
}

function isDraft(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  const head = content.slice(0, 1024);
  if (!head.startsWith("---")) return false;
  const end = head.indexOf("\n---", 3);
  if (end === -1) return false;
  const frontmatter = head.slice(0, end);
  return /draft:\s*true/i.test(frontmatter);
}

function joinUrl(base, p) {
  if (!base) return "/" + p.replace(/^\//, "");
  return base.replace(/\/$/, "") + "/" + p.replace(/^\//, "");
}

function formatTitle(str) {
  return str
    .replace(/[-_]/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function wrapLine(line, indent = 0) {
  if (line.length <= 100) return [line];
  const pad = " ".repeat(indent);
  const words = line.split(" ");
  const out = [];
  let cur = pad;

  for (const w of words) {
    if (cur.length + w.length + 1 > 100) {
      out.push(cur.trimEnd());
      cur = pad + "    " + w + " ";
    } else {
      cur += w + " ";
    }
  }
  if (cur.trim()) out.push(cur.trimEnd());
  return out;
}

// ── Hierarchy logic ──────────────────────────────────────────────────────────

function getHierarchy(relPath) {
  const parts = relPath.replace(/\.mdx?$/, "").split("/");

  const isIndex = parts[parts.length - 1] === "index";
  if (isIndex) parts.pop();

  const section = formatTitle(parts[0] || "General");

  const subsection = parts.length >= 3 ? parts.slice(0, 3).join("/") : null;

  return { section, subsection, isIndex, parts };
}

// ── Collect pages ────────────────────────────────────────────────────────────

const files = walk(markdownDir);
const grouped = {};

// ── Markdown pages ───────────────────────────────────────────────────────────

for (const file of files) {
  if (isDraft(file)) continue;

  const rel = path.relative(markdownDir, file).replace(/\\/g, "/");

  const { section, subsection, isIndex, parts } = getHierarchy(rel);

  let title;
  if (isIndex) {
    const parent = parts[parts.length - 1] || section;
    title = `${formatTitle(parent)} Index`;
  } else {
    title = formatTitle(path.basename(file, path.extname(file)));
  }

  const cleanPath = rel.replace(/\.mdx?$/, ".md");
  const url = joinUrl(baseUrl, cleanPath);

  if (!grouped[section]) grouped[section] = [];

  grouped[section].push({
    title,
    url,
    subsection
  });
}

// ── Merge single-entry sections into Top Level Navigation ────────────────────

const topLevel = [];

for (const section of Object.keys(grouped)) {
  const pages = grouped[section];

  if (pages.length === 1) {
    topLevel.push({
      ...pages[0],
      title: `${formatTitle(section)} — ${pages[0].title}`,
      subsection: null
    });
    delete grouped[section];
    continue;
  }

  const subCounts = {};
  for (const page of pages) {
    if (page.subsection) {
      subCounts[page.subsection] = (subCounts[page.subsection] ?? 0) + 1;
    }
  }

  for (const page of pages) {
    if (page.subsection && subCounts[page.subsection] === 1) {
      page.subsection = null;
    }
  }
}

if (topLevel.length) {
  grouped["Top Level Navigation"] = topLevel;
}

// ── Sorting ──────────────────────────────────────────────────────────────────

function sortSections(sections) {
  return sections.sort();
}

function sortPages(pages) {
  return pages.sort((a, b) => {
    if (a.subsection && b.subsection && a.subsection !== b.subsection) {
      return a.subsection.localeCompare(b.subsection);
    }
    return a.url.localeCompare(b.url);
  });
}

// ── Build output ─────────────────────────────────────────────────────────────

function build(ratio = 1) {
  const lines = [];

  lines.push("# Seal Documentation for LLMs", "");
  lines.push(
    "> Seal is a decentralized secrets management protocol on the Sui blockchain. " +
    "It enables secure encryption and access control for onchain data using threshold cryptography.",
    ""
  );

  const sections = sortSections(Object.keys(grouped));

  for (const section of sections) {
    lines.push(`## ${section}`);

    const pages = sortPages(grouped[section]);

    const keep = Math.max(1, Math.floor(pages.length * ratio));

    let currentSub = null;
    let firstPage = true;

    for (const page of pages.slice(0, keep)) {
      if (page.subsection && page.subsection !== currentSub) {
        currentSub = page.subsection;
        lines.push("", `### ${formatTitle(currentSub)}`);
      } else if (firstPage) {
        lines.push("");
      }
      firstPage = false;

      lines.push(...wrapLine(`- [${page.title}](${page.url})`, 0));
      if (page.description) {
        lines.push(...wrapLine(`  ${page.description}`, 2));
      }
    }

    lines.push("");
  }

  return lines.join("\n");
}

// ── Trim passes ──────────────────────────────────────────────────────────────

let output = build(1);

if (output.length > TARGET_CHARS) {
  const ratio = TARGET_CHARS / output.length;
  output = build(ratio);
}

if (output.length > TARGET_CHARS) {
  output = output.slice(0, TARGET_CHARS);
}

// ── Write file ───────────────────────────────────────────────────────────────

fs.mkdirSync(path.dirname(outputFile), { recursive: true });
fs.writeFileSync(outputFile, output, "utf8");

console.log(`✓ Generated ${outputFile} (${output.length.toLocaleString()} chars)`);
