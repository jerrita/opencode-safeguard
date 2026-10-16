import { Plugin } from "@opencode/plugin";
import { loadEnvValues, resolveConfig, type SafeguardOptions } from "./config.js";
import { redactRequestEvent, restoreToolInput } from "./redact.js";
import { Safeguard } from "./rpc.js";
import { applyStored, initialState } from "./state.js";
import { Vault } from "./vault.js";

import { VENDORED_RULES } from "./vendored-rules.js";

const STORAGE_KEY = "safeguard.state";
const LEGACY_STORAGE_KEY = "safeguard.enabled";
const RULE_COUNT = VENDORED_RULES.length + 11; // vendored + builtin patterns

interface Ctx {
  location: { directory?: string; project?: { canonical?: string } };
  options: SafeguardOptions;
  storage: { get(key: string): Promise<unknown>; set(key: string, value: unknown): Promise<void> };
  session: {
    hook(name: string, cb: (event: any) => void | Promise<void>): Promise<unknown>;
  };
  tool: { hook(name: string, cb: (event: any) => void | Promise<void>): Promise<unknown> };
  rpc: {
    register(
      def: unknown,
      handlers: Record<string, (input: any, context: any) => Promise<unknown>>,
    ): Promise<{
      events: { emit(name: string, data: unknown): Promise<void> };
    }>;
  };
}

function projectDir(ctx: Ctx): string {
  return ctx.location.project?.canonical ?? ctx.location.directory ?? process.cwd();
}

function narrowStateShape(v: unknown): {
  enabled?: boolean;
  audit?: boolean;
  minEntropy?: number;
  minTokenLength?: number;
} {
  if (typeof v !== "object" || v === null) return {};
  const o = v as Record<string, unknown>;
  const out: { enabled?: boolean; audit?: boolean; minEntropy?: number; minTokenLength?: number } = {};
  if (typeof o.enabled === "boolean") out.enabled = o.enabled;
  if (typeof o.audit === "boolean") out.audit = o.audit;
  if (typeof o.minEntropy === "number") out.minEntropy = o.minEntropy;
  if (typeof o.minTokenLength === "number") out.minTokenLength = o.minTokenLength;
  return out;
}

export default Plugin.define({
  id: "opencode-safeguard",
  async setup(ctx) {
    const c = ctx as unknown as Ctx;
    const cfg = resolveConfig(c.options);
    const vault = new Vault(cfg.placeholderPrefix);
    const literals: string[] = [...cfg.extraValues];
    for (const v of loadEnvValues(projectDir(c), cfg.envFiles, cfg.minValueLength)) {
      if (!literals.includes(v)) literals.push(v);
    }

    // Live state: startup config (folds env var) < persisted storage < RPC mutations.
    const state = initialState(cfg);
    try {
      const stored = await c.storage.get(STORAGE_KEY);
      if (stored !== undefined) {
        applyStored(state, stored);
      } else {
        // Migrate the pre-RPC boolean toggle.
        const legacy = await c.storage.get(LEGACY_STORAGE_KEY);
        if (typeof legacy === "boolean") {
          state.enabled = legacy;
          await c.storage.set(STORAGE_KEY, { ...state });
        }
      }
    } catch {
      // Storage unavailable; keep startup values.
    }
    const persist = async (): Promise<void> => {
      try {
        await c.storage.set(STORAGE_KEY, { ...state });
      } catch {
        // Best effort persistence.
      }
    };

    let emitRound: (
      sessionID: string,
      redacted: number,
      restored: number,
      kind: string,
    ) => Promise<void> = async () => {};

    const registration = await c.rpc.register(Safeguard, {
      getState: async () => ({ ...state, literals: literals.length, rules: RULE_COUNT }),
      getSession: async (input) => {
        const { sessionID } = input as { sessionID?: unknown };
        if (typeof sessionID !== "string") throw new Error("getSession requires { sessionID: string }");
        const r = vault.round(sessionID);
        return {
          entries: vault.size(sessionID),
          totalEntries: vault.totalSize(),
          roundRedacted: r.redacted,
          roundRestored: r.restored,
          roundRestoreKind: r.restoreKind,
        };
      },
      setEnabled: async (input) => {
        const { enabled } = narrowStateShape(input);
        if (typeof enabled !== "boolean") throw new Error("setEnabled requires { enabled: boolean }");
        state.enabled = enabled;
        await persist();
        await registration.events.emit("updated", { enabled: state.enabled, audit: state.audit });
        return { enabled: state.enabled };
      },
      setAudit: async (input) => {
        const { audit } = narrowStateShape(input);
        if (typeof audit !== "boolean") throw new Error("setAudit requires { audit: boolean }");
        state.audit = audit;
        await persist();
        await registration.events.emit("updated", { enabled: state.enabled, audit: state.audit });
        return { audit: state.audit };
      },
      setSensitivity: async (input) => {
        const { minEntropy, minTokenLength } = narrowStateShape(input);
        if (typeof minEntropy !== "number" || typeof minTokenLength !== "number") {
          throw new Error("setSensitivity requires { minEntropy: number, minTokenLength: number }");
        }
        state.minEntropy = minEntropy;
        state.minTokenLength = minTokenLength;
        await persist();
        return { minEntropy: state.minEntropy, minTokenLength: state.minTokenLength };
      },
    });

    const redactCtx = (sessionID: string) => ({
      vault,
      sessionID,
      literalValues: literals,
      minEntropy: state.minEntropy,
      minTokenLength: state.minTokenLength,
      maxStringLength: cfg.maxStringLength,
    });

    emitRound = async (sessionID, redacted, restored, kind) => {
      try {
        await registration.events.emit("updated", {
          enabled: state.enabled,
          audit: state.audit,
          sessionID,
          entries: vault.size(sessionID),
          totalEntries: vault.totalSize(),
          roundRedacted: redacted,
          roundRestored: restored,
          roundRestoreKind: kind,
        });
      } catch {
        // Best effort: a failed emit must not break the agent loop.
      }
    };

    // --- LLM boundary: redact everything bound for the model ---
    const redactHook = (label: string) => async (event: any) => {
      if (!state.enabled) return;
      try {
        const sid = event.sessionID as string;
        const n = redactRequestEvent(redactCtx(sid), event);
        if (n === 0) return;
        if (state.audit) console.log(`[opencode-safeguard] ${label}: redacted ${n} secret(s) (session ${sid})`);
        vault.addRedacted(sid, n);
        const r = vault.round(sid);
        await emitRound(sid, r.redacted, r.restored, r.restoreKind);
      } catch (err) {
        // Fail open with a warning: never break the agent loop.
        console.error(`[opencode-safeguard] ${label} redaction failed:`, err);
      }
    };
    await c.session.hook("context", redactHook("context"));
    await c.session.hook("compaction", redactHook("compaction"));
    await c.session.hook("generate", redactHook("generate"));
    await c.session.hook("title", redactHook("title"));

    // A user prompt starts a new round: reset the counters the sidebar shows.
    // Content is untouched here; redaction happens at the LLM boundary.
    await c.session.hook("prompt", async (event: any) => {
      if (!state.enabled) return;
      try {
        const sid = event.sessionID as string;
        vault.startRound(sid);
        await emitRound(sid, 0, 0, "");
      } catch (err) {
        console.error("[opencode-safeguard] prompt round reset failed:", err);
      }
    });

    // --- Local boundary: restore placeholders before tool execution ---
    await c.tool.hook("execute.before", async (event: any) => {
      if (!state.enabled) return;
      try {
        const sid = event.sessionID as string;
        const count = restoreToolInput(vault, sid, event.input);
        if (count === 0) return;
        if (state.audit)
          console.log(`[opencode-safeguard] execute.before: restored ${count} secret(s) for ${event.tool}`);
        vault.addRestored(sid, count, `tool:${event.tool as string}`);
        const r = vault.round(sid);
        await emitRound(sid, r.redacted, r.restored, r.restoreKind);
      } catch (err) {
        console.error("[opencode-safeguard] restore failed:", err);
      }
    });

    // tool.execute.after is intentionally a no-op for content: persisted tool
    // output keeps real values locally; the next context hook redacts them
    // again before they reach the model. Here we only audit.
    await c.tool.hook("execute.after", async (event: any) => {
      if (!state.enabled || !state.audit) return;
      if (event.status !== "completed") return;
    });

    console.log(
      `[opencode-safeguard] loaded (${state.enabled ? "enabled" : "disabled"}, ${literals.length} literals). ` +
        `Configure: /safeguard (TUI) or OPENCODE_SAFEGUARD_ENABLED=0/1.`,
    );
  },
});
