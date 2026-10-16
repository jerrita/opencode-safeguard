import * as fs from "node:fs";
import * as path from "node:path";

export interface SafeguardOptions {
  /** Master switch. Default true. */
  enabled?: boolean;
  /** .env files (relative to project root) whose values are matched literally. */
  envFiles?: string[];
  /** Extra literal secrets to always redact (e.g. injected via config). */
  extraValues?: string[];
  /** Minimum length for literal (.env / extra) values. Default 6. */
  minValueLength?: number;
  /** Shannon entropy threshold for the high-entropy fallback. Default 4.5. */
  minEntropy?: number;
  /** Minimum token length for the high-entropy fallback. Default 20. */
  minTokenLength?: number;
  /** Strings longer than this are truncated before scanning (perf guard). Default 200_000. */
  maxStringLength?: number;
  /** Placeholder namespace, e.g. "__SG_SECRET_1__". Default "SG". */
  placeholderPrefix?: string;
  /** Log redaction counts (never values). Default true. */
  audit?: boolean;
}

export interface ResolvedConfig {
  enabled: boolean;
  envFiles: string[];
  extraValues: string[];
  minValueLength: number;
  minEntropy: number;
  minTokenLength: number;
  maxStringLength: number;
  placeholderPrefix: string;
  audit: boolean;
}

const DEFAULTS: ResolvedConfig = {
  enabled: true,
  envFiles: [".env", ".env.local", ".env.production"],
  extraValues: [],
  minValueLength: 6,
  minEntropy: 4.5,
  minTokenLength: 20,
  maxStringLength: 200_000,
  placeholderPrefix: "SG",
  audit: true,
};

/** Parse OPENCODE_SAFEGUARD_ENABLED: returns true/false/undefined (unset or unparsable). */
export function parseEnabledEnv(env: NodeJS.ProcessEnv = process.env): boolean | undefined {
  const raw = env["OPENCODE_SAFEGUARD_ENABLED"];
  if (raw === undefined) return undefined;
  const v = raw.trim().toLowerCase();
  if (["1", "true", "on", "yes", "enable", "enabled"].includes(v)) return true;
  if (["0", "false", "off", "no", "disable", "disabled"].includes(v)) return false;
  return undefined;
}

export function resolveConfig(raw: SafeguardOptions | undefined, env: NodeJS.ProcessEnv = process.env): ResolvedConfig {
  const envEnabled = parseEnabledEnv(env);
  return {
    enabled: envEnabled ?? raw?.enabled ?? DEFAULTS.enabled,
    envFiles: raw?.envFiles ?? DEFAULTS.envFiles,
    extraValues: raw?.extraValues ?? DEFAULTS.extraValues,
    minValueLength: raw?.minValueLength ?? DEFAULTS.minValueLength,
    minEntropy: raw?.minEntropy ?? DEFAULTS.minEntropy,
    minTokenLength: raw?.minTokenLength ?? DEFAULTS.minTokenLength,
    maxStringLength: raw?.maxStringLength ?? DEFAULTS.maxStringLength,
    placeholderPrefix: raw?.placeholderPrefix ?? DEFAULTS.placeholderPrefix,
    audit: raw?.audit ?? DEFAULTS.audit,
  };
}

/** Parse KEY=VALUE lines (dotenv subset: ignores blanks/comments/exports, strips quotes). */
export function parseDotenv(text: string): string[] {
  const values: string[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const withoutExport = trimmed.startsWith("export ") ? trimmed.slice(7).trim() : trimmed;
    const eq = withoutExport.indexOf("=");
    if (eq <= 0) continue;
    let value = withoutExport.slice(eq + 1).trim();
    if (value.length >= 2 && ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'")))) {
      value = value.slice(1, -1);
    }
    // Strip trailing inline comments for unquoted values.
    if (!value.startsWith('"') && !value.startsWith("'")) {
      const hash = value.indexOf(" #");
      if (hash !== -1) value = value.slice(0, hash).trim();
    }
    if (value) values.push(value);
  }
  return values;
}

/** Load literal secret values from env files under projectDir. Never throws. */
export function loadEnvValues(projectDir: string, envFiles: string[], minLength: number): string[] {
  const out: string[] = [];
  for (const file of envFiles) {
    try {
      const abs = path.isAbsolute(file) ? file : path.join(projectDir, file);
      const text = fs.readFileSync(abs, "utf8");
      for (const v of parseDotenv(text)) {
        if (v.length >= minLength) out.push(v);
      }
    } catch {
      // Missing/unreadable env file is normal; ignore.
    }
  }
  return [...new Set(out)];
}
