import { findSecretsInText } from "./detector.js";
import { deepMapStrings, Vault } from "./vault.js";

export interface RedactContext {
  vault: Vault;
  sessionID: string;
  literalValues: string[];
  minEntropy: number;
  minTokenLength: number;
  maxStringLength: number;
}

function redactString(ctx: RedactContext, text: string): string {
  if (!text || text.length < 4) return text;
  const detections = findSecretsInText(text, {
    minEntropy: ctx.minEntropy,
    minTokenLength: ctx.minTokenLength,
    maxStringLength: ctx.maxStringLength,
    literalValues: ctx.literalValues,
  });
  if (detections.length === 0) return text;
  return ctx.vault.redactText(ctx.sessionID, text, detections).text;
}

/**
 * Redact secrets in an LLM-bound request event (mutates in place).
 * Covers `system` and `messages`; tool schemas (`tools`) are left intact
 * so model tool-use keeps working.
 * Returns the number of distinct secrets redacted.
 */
export function redactRequestEvent(ctx: RedactContext, event: { system?: unknown; messages?: unknown }): number {
  let distinct = 0;
  const seen = new Set<string>();
  const countDistinct = (before: string, after: string): void => {
    if (before !== after) {
      // Approximate: each changed string contributes its new placeholders.
      for (const m of after.matchAll(/__[A-Z]+_[A-Z_]+_\d+__/g)) {
        if (!seen.has(m[0])) {
          seen.add(m[0]);
          distinct++;
        }
      }
    }
  };
  if (Array.isArray(event.system)) {
    deepMapStrings(event.system, (s) => {
      const out = redactString(ctx, s);
      countDistinct(s, out);
      return out;
    });
  }
  if (Array.isArray(event.messages)) {
    deepMapStrings(event.messages, (s) => {
      const out = redactString(ctx, s);
      countDistinct(s, out);
      return out;
    });
  } else if (event.messages !== undefined) {
    deepMapStrings(event.messages, (s) => {
      const out = redactString(ctx, s);
      countDistinct(s, out);
      return out;
    });
  }
  return distinct;
}

/** Restore placeholders in tool input before local execution (mutates in place). */
export function restoreToolInput(vault: Vault, sessionID: string, input: unknown): number {
  let count = 0;
  deepMapStrings(input, (s) => {
    if (!s.includes("__")) return s;
    const { text, count: c } = vault.restoreText(sessionID, s);
    count += c;
    return text;
  });
  return count;
}
