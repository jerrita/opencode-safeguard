import { describe, expect, it } from "vitest";
import { findSecretsInText, shannonEntropy } from "../src/detector.js";

const opts = { minEntropy: 4.5, minTokenLength: 20, maxStringLength: 200_000, literalValues: [] as string[] };

describe("patterns", () => {
  it("detects AWS access key", () => {
    const hits = findSecretsInText("key AKIAIOSFODNN7EXAMPLE here", opts);
    expect(hits.some((h) => h.value === "AKIAIOSFODNN7EXAMPLE")).toBe(true);
  });

  it("detects github token", () => {
    const hits = findSecretsInText("token ghp_abcdefghij1234567890abcdefghij1234 end", opts);
    expect(hits.some((h) => h.type === "GITHUB_TOKEN")).toBe(true);
  });

  it("detects JWT", () => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c";
    expect(findSecretsInText(`auth ${jwt}`, opts).some((h) => h.type === "JWT")).toBe(true);
  });

  it("detects PEM block", () => {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKabc\n-----END RSA PRIVATE KEY-----";
    expect(findSecretsInText(pem, opts).some((h) => h.type === "PRIVATE_KEY")).toBe(true);
  });

  it("detects assigned secret value only", () => {
    const hits = findSecretsInText('password="s3cr3t-value-123"', opts);
    expect(hits.some((h) => h.value === "s3cr3t-value-123")).toBe(true);
    expect(hits.every((h) => !h.value.includes("password"))).toBe(true);
  });

  it("detects bearer token", () => {
    const hits = findSecretsInText("Authorization: Bearer abcdefghij1234567890XYZ", opts);
    expect(hits.some((h) => h.type === "BEARER_TOKEN" && h.value === "abcdefghij1234567890XYZ")).toBe(true);
  });
});

describe("literals", () => {
  it("matches .env values literally", () => {
    const hits = findSecretsInText("connect with mydbpass123!", { ...opts, literalValues: ["mydbpass123"] });
    expect(hits.some((h) => h.type === "ENV_VALUE")).toBe(true);
  });
});

describe("entropy", () => {
  it("flags high-entropy tokens", () => {
    expect(shannonEntropy("K7$g9!mQ2#vX8@pL4zR6&wN1")).toBeGreaterThan(4.0);
    const hits = findSecretsInText("deploy K7$g9!mQ2#vX8@pL4zR6&wN1xYz0qWe token", opts);
    expect(hits.some((h) => h.type === "HIGH_ENTROPY")).toBe(true);
  });

  it("ignores plain words", () => {
    expect(findSecretsInText("hello world this is a normal sentence about code", opts)).toEqual([]);
  });

  it("ignores file paths", () => {
    expect(findSecretsInText("read /home/user/project/src/index.ts now", opts)).toEqual([]);
  });
});
