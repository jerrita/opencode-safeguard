import { describe, expect, it } from "vitest";
import { findSecretsInText } from "../src/detector.js";
import { VENDORED_RULES } from "../src/vendored-rules.js";

const opts = { minEntropy: 4.5, minTokenLength: 20, maxStringLength: 200_000, literalValues: [] as string[] };

describe("vendored rules", () => {
  it("ships a broad rule set", () => {
    expect(VENDORED_RULES.length).toBeGreaterThan(150);
  });

  it("detects stripe live key", () => {
    const hits = findSecretsInText("charge with sk_live_4eC39HqLyjWDarjtT1zdp7dc now", opts);
    // Builtin fast path claims it first; vendored dedups to a single entry.
    const matches = hits.filter((h) => h.value === "sk_live_4eC39HqLyjWDarjtT1zdp7dc");
    expect(matches.length).toBe(1);
  });

  it("detects gcp api key", () => {
    const key = `AIza${"x".repeat(35)}`;
    const hits = findSecretsInText(`gcp key ${key} end`, opts);
    expect(hits.some((h) => h.type === "VND_GCP_API_KEY" && h.value === key)).toBe(true);
  });

  it("detects generic assignment via vendored rule", () => {
    // Gitleaks-format assignment the builtin also covers; assert single deduped hit.
    const hits = findSecretsInText('api_key = "wJalrXUtnFEMI7MDENGbPxRfiCYQZK3Y9mN4vB7"', opts);
    expect(hits.filter((h) => h.value === "wJalrXUtnFEMI7MDENGbPxRfiCYQZK3Y9mN4vB7").length).toBe(1);
  });

  it("detects vendored-only provider key", () => {
    // SendGrid-style key not covered by builtins.
    const hits = findSecretsInText("sendgrid SG.abc123XYZ456def789GHI012jkl345mno678pqr", opts);
    expect(hits.length).toBeGreaterThan(0);
  });

  it("respects stopwords for generic assignments", () => {
    // "aaaaaaaaaa" is allowlisted (chars-only) for generic-api-key.
    expect(findSecretsInText('secret = "aaaaaaaaaa"', opts).filter((h) => h.type === "VND_GENERIC_API_KEY")).toEqual(
      [],
    );
  });

  it("does not flag documentation placeholders", () => {
    // gitleaks EXAMPLE allowlist: AKIA...EXAMPLE must not match aws rule.
    const hits = findSecretsInText("example AKIAIOSFODNN7EXAMPLE here", opts);
    expect(hits.filter((h) => h.type === "VND_AWS_ACCESS_TOKEN")).toEqual([]);
  });

  it("scans 200KB in reasonable time", () => {
    const big = `${"lorem ipsum dolor sit amet ".repeat(7000)}\nsk_live_4eC39HqLyjWDarjtT1zdp7dc\n${"tail ".repeat(1000)}`;
    const start = Date.now();
    const hits = findSecretsInText(big, opts);
    expect(Date.now() - start).toBeLessThan(3000);
    expect(hits.some((h) => h.value === "sk_live_4eC39HqLyjWDarjtT1zdp7dc")).toBe(true);
  });
});
