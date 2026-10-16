import type { ResolvedConfig } from "./config.js";

/** Live safeguard settings. Owned by the server plugin, mutated via RPC. */
export interface SafeguardState {
  enabled: boolean;
  audit: boolean;
  minEntropy: number;
  minTokenLength: number;
}

export function initialState(cfg: ResolvedConfig): SafeguardState {
  return {
    enabled: cfg.enabled,
    audit: cfg.audit,
    minEntropy: cfg.minEntropy,
    minTokenLength: cfg.minTokenLength,
  };
}

/** Apply a persisted state object (storage) over the startup state. */
export function applyStored(state: SafeguardState, stored: unknown): void {
  if (typeof stored !== "object" || stored === null) return;
  const s = stored as Record<string, unknown>;
  if (typeof s.enabled === "boolean") state.enabled = s.enabled;
  if (typeof s.audit === "boolean") state.audit = s.audit;
  if (typeof s.minEntropy === "number" && Number.isFinite(s.minEntropy)) state.minEntropy = s.minEntropy;
  if (typeof s.minTokenLength === "number" && Number.isFinite(s.minTokenLength)) state.minTokenLength = s.minTokenLength;
}

export const SENSITIVITY_PRESETS = {
  strict: { minEntropy: 4.0, minTokenLength: 16 },
  balanced: { minEntropy: 4.5, minTokenLength: 20 },
  relaxed: { minEntropy: 5.0, minTokenLength: 28 },
} as const;

export type SensitivityName = keyof typeof SENSITIVITY_PRESETS;

export function presetOf(minEntropy: number, minTokenLength: number): SensitivityName | "custom" {
  for (const [name, p] of Object.entries(SENSITIVITY_PRESETS)) {
    if (p.minEntropy === minEntropy && p.minTokenLength === minTokenLength) return name as SensitivityName;
  }
  return "custom";
}
