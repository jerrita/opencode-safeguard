import { Plugin } from "@opencode/plugin";
import { loadEnvValues, resolveConfig, type SafeguardOptions } from "./config.js";
import { redactRequestEvent, restoreToolInput } from "./redact.js";
import { Vault } from "./vault.js";

const STORAGE_KEY = "safeguard.enabled";

interface Ctx {
  location: { directory?: string; project?: { canonical?: string } };
  options: SafeguardOptions;
  storage: { get(key: string): Promise<unknown>; set(key: string, value: unknown): Promise<void> };
  session: {
    hook(name: string, cb: (event: any) => void | Promise<void>): Promise<unknown>;
    synthetic?(input: { sessionID: string; text: string }): Promise<unknown>;
  };
  tool: { hook(name: string, cb: (event: any) => void | Promise<void>): Promise<unknown> };
  command: { transform(cb: (editor: { add(def: unknown): void }) => void): Promise<unknown> };
}

function projectDir(ctx: Ctx): string {
  return ctx.location.project?.canonical ?? ctx.location.directory ?? process.cwd();
}

async function announce(ctx: Ctx, sessionID: string, text: string): Promise<void> {
  try {
    if (typeof ctx.session.synthetic === "function") {
      await ctx.session.synthetic({ sessionID, text });
      return;
    }
  } catch {
    // Fall through to console.
  }
  console.log(`[opencode-safeguard] ${text}`);
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

    // Toggle state: storage override > startup config (which already folds env var).
    const state = { enabled: cfg.enabled };
    try {
      const stored = await c.storage.get(STORAGE_KEY);
      if (typeof stored === "boolean") state.enabled = stored;
    } catch {
      // Storage unavailable; keep startup value.
    }
    const setEnabled = async (enabled: boolean): Promise<void> => {
      state.enabled = enabled;
      try {
        await c.storage.set(STORAGE_KEY, enabled);
      } catch {
        // Best effort persistence.
      }
    };
    const redactCtx = (sessionID: string) => ({
      vault,
      sessionID,
      literalValues: literals,
      minEntropy: cfg.minEntropy,
      minTokenLength: cfg.minTokenLength,
      maxStringLength: cfg.maxStringLength,
    });

    // --- Convenient on/off commands ---
    await c.command.transform((editor) => {
      const ed = editor as unknown as {
        add(def: { name: string; description?: string; execute: (input: { sessionID: string }) => Promise<void> }): void;
      };
      ed.add({
        name: "safeguard-on",
        description: "Enable opencode-safeguard secret redaction",
        execute: async (input) => {
          await setEnabled(true);
          await announce(c, input.sessionID, "Safeguard enabled: secrets will be redacted before reaching the LLM.");
        },
      });
      ed.add({
        name: "safeguard-off",
        description: "Disable opencode-safeguard secret redaction",
        execute: async (input) => {
          await setEnabled(false);
          await announce(c, input.sessionID, "Safeguard disabled: content will be sent to the LLM unredacted.");
        },
      });
      ed.add({
        name: "safeguard-status",
        description: "Show opencode-safeguard status",
        execute: async (input) => {
          await announce(
            c,
            input.sessionID,
            `Safeguard ${state.enabled ? "enabled" : "disabled"} (${vault.size(input.sessionID)} secrets mapped in this session, ${literals.length} literal values loaded).`,
          );
        },
      });
    });

    // --- LLM boundary: redact everything bound for the model ---
    const redactHook = (label: string) => async (event: any) => {
      if (!state.enabled) return;
      try {
        const n = redactRequestEvent(redactCtx(event.sessionID as string), event);
        if (cfg.audit && n > 0) console.log(`[opencode-safeguard] ${label}: redacted ${n} secret(s) (session ${event.sessionID})`);
      } catch (err) {
        // Fail open with a warning: never break the agent loop.
        console.error(`[opencode-safeguard] ${label} redaction failed:`, err);
      }
    };
    await c.session.hook("context", redactHook("context"));
    await c.session.hook("compaction", redactHook("compaction"));
    await c.session.hook("generate", redactHook("generate"));
    await c.session.hook("title", redactHook("title"));

    // --- Local boundary: restore placeholders before tool execution ---
    await c.tool.hook("execute.before", async (event: any) => {
      if (!state.enabled) return;
      try {
        const count = restoreToolInput(vault, event.sessionID as string, event.input);
        if (cfg.audit && count > 0) console.log(`[opencode-safeguard] execute.before: restored ${count} secret(s) for ${event.tool}`);
      } catch (err) {
        console.error("[opencode-safeguard] restore failed:", err);
      }
    });

    // tool.execute.after is intentionally a no-op for content: persisted tool
    // output keeps real values locally; the next context hook redacts them
    // again before they reach the model. Here we only audit.
    await c.tool.hook("execute.after", async (event: any) => {
      if (!state.enabled || !cfg.audit) return;
      if (event.status !== "completed") return;
    });

    console.log(
      `[opencode-safeguard] loaded (${state.enabled ? "enabled" : "disabled"}, ${literals.length} literals). ` +
        `Toggle: /safeguard-on, /safeguard-off, /safeguard-status or OPENCODE_SAFEGUARD_ENABLED=0/1.`,
    );
  },
});
