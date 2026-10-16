#!/usr/bin/env node
/**
 * Vendor high-quality secret rules from gitleaks' default config into
 * src/vendored-rules.ts (committed, zero runtime dependencies).
 *
 * Gitleaks' TOML config is MIT licensed; the generated file keeps attribution.
 * Betterleaks maintains a compatible rule format, but gitleaks' single-file
 * default config is the more stable vendoring source.
 *
 * Usage: node scripts/vendor-rules.mjs [--ref v8.30.1] [--out src/vendored-rules.ts]
 */
import { writeFileSync } from "node:fs";
import { parse as parseToml } from "smol-toml";

const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(name);
  return i !== -1 && args[i + 1] ? args[i + 1] : fallback;
};
const REF = opt("--ref", "v8.30.1");
const OUT = opt("--out", "src/vendored-rules.ts");
const URL = `https://raw.githubusercontent.com/gitleaks/gitleaks/${REF}/config/gitleaks.toml`;

const POSIX_CLASSES = {
  alnum: "A-Za-z0-9",
  alpha: "A-Za-z",
  digit: "0-9",
  space: "\\s",
  blank: " \\t",
  upper: "A-Z",
  lower: "a-z",
  xdigit: "A-Fa-f0-9",
  cntrl: "\\x00-\\x1f\\x7f",
  print: "\\x20-\\x7e",
  punct: "!-/:-@\\[-`{-~",
  graph: "\\x21-\\x7e",
};

/** Convert a Go RE2 source to an approximately equivalent JS RegExp source. */
function convertSource(input) {
  let src = input;
  for (const [name, cls] of Object.entries(POSIX_CLASSES)) {
    src = src.split(`[[:${name}:]]`).join(`[${cls}]`);
  }
  // Python-style named groups -> JS named groups.
  src = src.replace(/\(\?P</g, "(?<");
  // RE2 anchors with no JS equivalent.
  src = src.replace(/\\A/g, "^").replace(/\\z/g, "$");
  let insensitive = /\(\?i(?::|\))/.test(src);
  let dotAll = /\(\?s(?::|\))/.test(src);
  src = src.replace(/\(\?-i:/g, "(?:");
  src = src.replace(/\(\?i:/g, "(?:");
  src = src.replace(/\(\?s:/g, "(?:");
  src = src.replace(/\(\?[is]\)/g, "");
  src = src.replace(/\(\?-i\)/g, "");
  return { src, insensitive, dotAll };
}

function countCapturingGroups(src) {
  let count = 0;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (ch === "\\") {
      i++;
      continue;
    }
    if (ch === "[") {
      i++;
      if (src[i] === "^") i++;
      if (src[i] === "]") i++;
      while (i < src.length && src[i] !== "]") {
        if (src[i] === "\\") i++;
        i++;
      }
      continue;
    }
    if (ch !== "(") continue;
    if (src[i + 1] !== "?") {
      count++;
      continue;
    }
    const rest = src.slice(i, i + 4);
    if (rest === "(?<=" || rest === "(?<!") continue; // lookbehind
    if (src[i + 2] === "<") count++; // named group (?<name>)
    // (?: (?= (?!) (?<!
  }
  return count;
}

function flagsOf(conv, global) {
  return `${global ? "g" : ""}${conv.insensitive ? "i" : ""}${conv.dotAll ? "s" : ""}`;
}

const res = await fetch(URL);
if (!res.ok) throw new Error(`fetch ${URL}: ${res.status}`);
const toml = parseToml(await res.text());

const rules = Array.isArray(toml.rules) ? toml.rules : [];
// Global allowlist: [allowlist] (singular, current) or [[allowlists]] (legacy/plural).
const globalAllow = [];
for (const key of ["allowlist", "allowlists"]) {
  const entry = toml[key];
  if (!entry) continue;
  const list = Array.isArray(entry) ? entry : [entry];
  for (const item of list) {
    for (const r of item?.regexes ?? []) globalAllow.push(r);
  }
}

const kept = [];
const dropped = [];
const lineTargetSkipped = { count: 0 };

for (const rule of rules) {
  const id = rule?.id;
  if (typeof id !== "string" || typeof rule?.regex !== "string") {
    dropped.push(`${id ?? "?"}: missing id/regex`);
    continue;
  }
  let conv;
  try {
    conv = convertSource(rule.regex);
    new RegExp(conv.src, flagsOf(conv, true));
  } catch (err) {
    dropped.push(`${id}: main regex: ${err.message}`);
    continue;
  }
  const groups = countCapturingGroups(conv.src);
  const allow = [];
  const allowBlocks = [];
  for (const key of ["allowlists", "allowlist"]) {
    const v = rule[key];
    if (!v) continue;
    allowBlocks.push(...(Array.isArray(v) ? v : [v]));
  }
  let ruleOk = true;
  const blockStopwords = [];
  for (const block of allowBlocks) {
    for (const s of block?.stopwords ?? []) {
      if (typeof s === "string") blockStopwords.push(s);
    }
    const target = block?.regexTarget ?? "secret";
    if (target === "line") {
      lineTargetSkipped.count++; // needs line context; evaluated rules stay fail-closed without it
      continue;
    }
    if (target !== "secret" && target !== "match") continue;
    for (const r of block?.regexes ?? []) {
      try {
        const c = convertSource(r);
        new RegExp(c.src, flagsOf(c, false));
        allow.push({ source: c.src, flags: flagsOf(c, false), target });
      } catch (err) {
        dropped.push(`${id}: allowlist regex: ${err.message}`);
        ruleOk = false;
      }
    }
  }
  if (!ruleOk) continue;
  const ruleStopwords = [
    ...(Array.isArray(rule.stopwords) ? rule.stopwords.filter((s) => typeof s === "string") : []),
    ...blockStopwords,
  ];
  kept.push({
    id,
    source: conv.src,
    flags: flagsOf(conv, true),
    group: groups === 1 ? 1 : 0,
    keywords: Array.isArray(rule.keywords) ? rule.keywords.filter((k) => typeof k === "string") : [],
    stopwords: ruleStopwords,
    allow,
  });
}

const globalConverted = [];
for (const r of globalAllow) {
  try {
    const c = convertSource(r);
    new RegExp(c.src, flagsOf(c, false));
    globalConverted.push({ source: c.src, flags: flagsOf(c, false) });
  } catch (err) {
    dropped.push(`global allowlist: ${err.message}`);
  }
}

const header = `// AUTO-GENERATED by scripts/vendor-rules.mjs -- do not edit.
// Source: https://github.com/gitleaks/gitleaks/blob/${REF}/config/gitleaks.toml
// Gitleaks default config, MIT License (c) gitleaks authors.
// Generated: ${new Date().toISOString()}. Rules: ${kept.length} kept, ${dropped.length} dropped.
`;
const body = `export interface VendoredAllow {
  source: string;
  flags: string;
  target: "secret" | "match";
}

export interface VendoredRule {
  id: string;
  /** Sanitized type label used in placeholders. */
  type: string;
  source: string;
  flags: string;
  /** 1 when the pattern has exactly one capture group holding the secret. */
  group: 0 | 1;
  keywords: string[];
  stopwords: string[];
  allow: VendoredAllow[];
}

export const VENDOR_INFO = ${JSON.stringify({ source: "gitleaks", ref: REF, rules: kept.length }, null, 2)};

export const GLOBAL_ALLOWLISTS: { source: string; flags: string }[] = ${JSON.stringify(globalConverted, null, 2)};

export const VENDORED_RULES: VendoredRule[] = ${JSON.stringify(
  kept.map((r) => ({
    ...r,
    type: `VND_${r.id.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "")}`,
  })),
  null,
  2,
)};
`;
writeFileSync(OUT, `${header}${body}`);
console.log(`vendored ${kept.length} rules -> ${OUT} (dropped ${dropped.length}, line-target allowlists skipped in ${lineTargetSkipped.count} blocks)`);
for (const d of dropped.slice(0, 20)) console.log(`  drop: ${d}`);
if (dropped.length > 20) console.log(`  ... and ${dropped.length - 20} more`);
