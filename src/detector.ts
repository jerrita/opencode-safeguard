export interface Detection {
  value: string;
  type: string;
}

interface Pattern {
  type: string;
  /** Global regex. If `group` is set, only that capture group is the secret. */
  regex: RegExp;
  group?: number;
}

const PATTERNS: Pattern[] = [
  { type: "AWS_ACCESS_KEY", regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { type: "GITHUB_TOKEN", regex: /\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}\b/g },
  { type: "STRIPE_KEY", regex: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { type: "OPENAI_KEY", regex: /\bsk-[A-Za-z0-9]{20,}\b/g },
  { type: "ANTHROPIC_KEY", regex: /\bsk-ant-[A-Za-z0-9\-_]{20,}\b/g },
  { type: "SLACK_TOKEN", regex: /\bxox[baprs]-[A-Za-z0-9\-]{10,}\b/g },
  { type: "JWT", regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  {
    type: "PRIVATE_KEY",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
  },
  { type: "BEARER_TOKEN", regex: /\bBearer\s+([A-Za-z0-9\-._~+/=]{20,})/g, group: 1 },
  {
    type: "CONNECTION_STRING",
    regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s'"`,;]+/g,
  },
  // key = value / key: value assignments; only the value is secret.
  {
    type: "ASSIGNED_SECRET",
    regex: /\b(?:password|passwd|pwd|secret|token|api[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)\s*[:=]\s*['"]?([^\s'"`;,\}]{8,})/gi,
    group: 1,
  },
];

const TOKEN_RE = /[A-Za-z0-9_\-+./=:$!#@%^&*?]{8,}/g;

export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function charClasses(s: string): number {
  let classes = 0;
  if (/[a-z]/.test(s)) classes++;
  if (/[A-Z]/.test(s)) classes++;
  if (/[0-9]/.test(s)) classes++;
  if (/[^A-Za-z0-9]/.test(s)) classes++;
  return classes;
}

export interface ScanOptions {
  minEntropy: number;
  minTokenLength: number;
  maxStringLength: number;
  literalValues: string[];
}

/** Find secrets in text. Returns detections sorted longest-first, deduplicated. */
export function findSecretsInText(text: string, opts: ScanOptions): Detection[] {
  const found = new Map<string, string>(); // value -> type
  const haystack = text.length > opts.maxStringLength ? text.slice(0, opts.maxStringLength) : text;

  // 1. Literal values (.env + extra config) — exact substring match.
  for (const literal of opts.literalValues) {
    if (literal.length === 0) continue;
    if (haystack.includes(literal) && !found.has(literal)) {
      found.set(literal, "ENV_VALUE");
    }
  }

  // 2. High-confidence patterns.
  for (const pattern of PATTERNS) {
    pattern.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = pattern.regex.exec(haystack)) !== null && guard++ < 1000) {
      const value = pattern.group !== undefined ? (m[pattern.group] ?? "") : m[0];
      if (!value || value.length < 4) continue;
      // Skip if already covered as substring of a longer detection.
      let covered = false;
      for (const existing of found.keys()) {
        if (existing.includes(value)) {
          covered = true;
          break;
        }
      }
      if (!covered && !found.has(value)) found.set(value, pattern.type);
      // Avoid infinite loop on zero-length matches.
      if (m[0].length === 0) pattern.regex.lastIndex++;
    }
  }

  // 3. High-entropy fallback on remaining tokens.
  TOKEN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = TOKEN_RE.exec(haystack)) !== null && guard++ < 5000) {
    const token = m[0];
    if (token.length < opts.minTokenLength) continue;
    if (found.has(token)) continue;
    let covered = false;
    for (const existing of found.keys()) {
      if (existing.includes(token)) {
        covered = true;
        break;
      }
    }
    if (covered) continue;
    // Skip file paths, URLs, and low-variety strings.
    if (token.includes("://") || token.startsWith("/") || token.includes("..")) continue;
    if (/^[0-9]+$/.test(token) || /^[a-z]+$/.test(token) || /^[A-Z]+$/.test(token)) continue;
    if (charClasses(token) < 2) continue;
    if (shannonEntropy(token) >= opts.minEntropy) {
      found.set(token, "HIGH_ENTROPY");
    }
    if (m[0].length === 0) TOKEN_RE.lastIndex++;
  }

  return [...found.entries()]
    .map(([value, type]) => ({ value, type }))
    .sort((a, b) => b.value.length - a.value.length);
}
