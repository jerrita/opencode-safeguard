import { describe, expect, it } from "vitest";
import { parseEnabledEnv, resolveConfig } from "../src/config.js";
import { redactRequestEvent, restoreToolInput } from "../src/redact.js";
import { Vault } from "../src/vault.js";

function ctx(sessionID: string, vault: Vault, literalValues: string[] = []) {
  return { vault, sessionID, literalValues, minEntropy: 4.5, minTokenLength: 20, maxStringLength: 200_000 };
}

describe("vault", () => {
  it("maps stably and isolates sessions", () => {
    const v = new Vault();
    const a1 = v.register("s1", "secret-A", "ENV_VALUE");
    expect(v.register("s1", "secret-A", "ENV_VALUE")).toBe(a1);
    expect(v.register("s2", "secret-A", "ENV_VALUE")).not.toBe(a1);
    expect(v.restoreText("s1", `x ${a1}`).text).toBe("x secret-A");
    expect(v.restoreText("s2", `x ${a1}`).text).toBe(`x ${a1}`);
  });

  it("roundtrips through redact + restore", () => {
    const v = new Vault();
    const c = ctx("s1", v, ["mydbpass123"]);
    const event = {
      system: [{ type: "text", text: "you are helpful" }],
      messages: [
        {
          role: "user",
          parts: [{ type: "text", text: "db password is mydbpass123, use it" }],
        },
        {
          role: "assistant",
          parts: [{ type: "tool-call", name: "bash", input: { command: "export P=mydbpass123" } }],
        },
      ],
    };
    const n = redactRequestEvent(c, event as any);
    expect(n).toBeGreaterThan(0);
    const json = JSON.stringify(event);
    expect(json).not.toContain("mydbpass123");
    // Tool executes with restored values.
    const toolInput: any = (event.messages[1] as any).parts[0].input;
    const restored = v.restoreText("s1", toolInput.command);
    expect(restored.text).toBe("export P=mydbpass123");
  });

  it("restores nested tool input", () => {
    const v = new Vault();
    const ph = v.register("s9", "tok-abc-123", "GITHUB_TOKEN");
    const input = { command: `run ${ph}`, nested: { args: [ph, "plain"] } };
    restoreToolInput(v, "s9", input);
    expect(input).toEqual({ command: "run tok-abc-123", nested: { args: ["tok-abc-123", "plain"] } });
  });

  it("accumulates round counters until the next user prompt", () => {
    const v = new Vault();
    v.startRound("s1");
    v.addRedacted("s1", 2);
    v.addRestored("s1", 1, "tool:bash");
    expect(v.round("s1")).toEqual({ redacted: 2, restored: 1, restoreKind: "tool:bash" });
    v.addRestored("s1", 3, "tool:edit");
    expect(v.round("s1")).toEqual({ redacted: 2, restored: 4, restoreKind: "tool:edit" });
    v.startRound("s1");
    expect(v.round("s1")).toEqual({ redacted: 0, restored: 0, restoreKind: "" });
  });
});

describe("toggle config", () => {
  it("env var overrides options", () => {
    expect(parseEnabledEnv({ OPENCODE_SAFEGUARD_ENABLED: "0" } as any)).toBe(false);
    expect(parseEnabledEnv({ OPENCODE_SAFEGUARD_ENABLED: "false" } as any)).toBe(false);
    expect(parseEnabledEnv({ OPENCODE_SAFEGUARD_ENABLED: "1" } as any)).toBe(true);
    expect(parseEnabledEnv({} as any)).toBe(undefined);
    expect(resolveConfig({ enabled: true }, { OPENCODE_SAFEGUARD_ENABLED: "0" } as any).enabled).toBe(false);
    expect(resolveConfig(undefined, {} as any).enabled).toBe(true);
  });
});
