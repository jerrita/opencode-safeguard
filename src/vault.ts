/**
 * Per-session secret vault.
 *
 * The LLM only ever sees placeholders. Before a tool executes locally,
 * placeholders are swapped back to real values so operations continue
 * with full fidelity. Mappings live in memory for the process lifetime
 * and never leave the device.
 */
export class Vault {
  // Global sequence: placeholders must be unique across sessions so that
  // identical counters in different sessions can never collide on distinct values.
  private next = 1;
  private forward = new Map<string, Map<string, string>>(); // sessionID -> value -> placeholder
  private reverse = new Map<string, Map<string, string>>(); // sessionID -> placeholder -> value

  constructor(private prefix = "SG") {}

  private sessionMaps(sessionID: string): { fwd: Map<string, string>; rev: Map<string, string> } {
    let fwd = this.forward.get(sessionID);
    let rev = this.reverse.get(sessionID);
    if (!fwd || !rev) {
      fwd = new Map();
      rev = new Map();
      this.forward.set(sessionID, fwd);
      this.reverse.set(sessionID, rev);
    }
    return { fwd, rev };
  }

  register(sessionID: string, value: string, type: string): string {
    if (!value) return value;
    const { fwd, rev } = this.sessionMaps(sessionID);
    const existing = fwd.get(value);
    if (existing) return existing;
    const placeholder = `__${this.prefix}_${type}_${this.next++}__`;
    fwd.set(value, placeholder);
    rev.set(placeholder, value);
    return placeholder;
  }

  placeholderFor(sessionID: string, value: string): string | undefined {
    return this.forward.get(sessionID)?.get(value);
  }

  /** Replace every known secret occurrence (longest first). Returns transformed text + count. */
  redactText(sessionID: string, text: string, detections: { value: string; type: string }[]): { text: string; count: number } {
    let out = text;
    let count = 0;
    for (const { value, type } of detections) {
      const placeholder = this.register(sessionID, value, type);
      if (out.includes(value)) {
        out = out.split(value).join(placeholder);
        count++;
      }
    }
    return { text: out, count };
  }

  /** Restore placeholders to real values (longest placeholder first). */
  restoreText(sessionID: string, text: string): { text: string; count: number } {
    const rev = this.reverse.get(sessionID);
    if (!rev || rev.size === 0 || !text.includes(`__${this.prefix}_`)) return { text, count: 0 };
    const entries = [...rev.entries()].sort((a, b) => b[0].length - a[0].length);
    let out = text;
    let count = 0;
    for (const [placeholder, value] of entries) {
      if (out.includes(placeholder)) {
        out = out.split(placeholder).join(value);
        count++;
      }
    }
    return { text: out, count };
  }

  hasSession(sessionID: string): boolean {
    return this.forward.has(sessionID);
  }

  size(sessionID: string): number {
    return this.forward.get(sessionID)?.size ?? 0;
  }

  clear(sessionID: string): void {
    this.forward.delete(sessionID);
    this.reverse.delete(sessionID);
  }
}

/** Recursively apply fn to every string in a JSON-like value (in place for objects/arrays). */
export function deepMapStrings(value: unknown, fn: (s: string) => string): unknown {
  if (typeof value === "string") return fn(value);
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) value[i] = deepMapStrings(value[i], fn);
    return value;
  }
  if (value !== null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    for (const key of Object.keys(obj)) obj[key] = deepMapStrings(obj[key], fn);
    return obj;
  }
  return value;
}
