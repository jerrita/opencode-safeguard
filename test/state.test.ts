import { describe, expect, it } from "vitest";
import { resolveConfig } from "../src/config.js";
import { Safeguard } from "../src/rpc.js";
import { applyStored, initialState, presetOf } from "../src/state.js";

describe("state", () => {
  it("starts from resolved config", () => {
    const s = initialState(resolveConfig({ enabled: false }, {} as any));
    expect(s).toMatchObject({ enabled: false, audit: true, minEntropy: 4.5, minTokenLength: 20 });
  });

  it("applies stored overrides selectively", () => {
    const s = initialState(resolveConfig(undefined, {} as any));
    applyStored(s, { enabled: false, minEntropy: 4.0 });
    expect(s.enabled).toBe(false);
    expect(s.minEntropy).toBe(4.0);
    expect(s.minTokenLength).toBe(20);
    applyStored(s, "garbage");
    expect(s.enabled).toBe(false);
  });

  it("maps thresholds to sensitivity presets", () => {
    expect(presetOf(4.5, 20)).toBe("balanced");
    expect(presetOf(4.0, 16)).toBe("strict");
    expect(presetOf(5.0, 28)).toBe("relaxed");
    expect(presetOf(4.2, 20)).toBe("custom");
  });
});

describe("rpc contract", () => {
  it("exposes the expected methods and events", () => {
    expect(Safeguard.id).toBe("safeguard");
    expect(Object.keys(Safeguard.methods).sort()).toEqual(["getState", "setAudit", "setEnabled", "setSensitivity"]);
    expect(Object.keys(Safeguard.events)).toEqual(["updated"]);
  });
});
