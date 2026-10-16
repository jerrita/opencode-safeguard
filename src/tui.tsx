import { Plugin, usePlugin } from "@opencode/plugin/tui";
import { createEffect, createSignal, Show } from "solid-js";
import { Safeguard } from "./rpc.js";
import { presetOf, SENSITIVITY_PRESETS, type SensitivityName } from "./state.js";

interface Snapshot {
  enabled: boolean;
  audit: boolean;
  minEntropy: number;
  minTokenLength: number;
  literals: number;
  rules: number;
}

interface SessionStats {
  entries: number;
  totalEntries: number;
  roundRedacted: number;
  roundRestored: number;
  roundRestoreKind: string;
}

function isNumber(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v);
}

function narrowSnapshot(v: unknown): Snapshot {
  const o = (v ?? {}) as Record<string, unknown>;
  for (const k of ["enabled", "audit"] as const) {
    if (typeof o[k] !== "boolean") throw new Error(`bad snapshot: ${k} not boolean`);
  }
  for (const k of ["minEntropy", "minTokenLength", "literals", "rules"] as const) {
    if (!isNumber(o[k])) throw new Error(`bad snapshot: ${k} not number`);
  }
  return o as unknown as Snapshot;
}

function narrowSession(v: unknown): SessionStats {
  const o = (v ?? {}) as Record<string, unknown>;
  for (const k of ["entries", "totalEntries", "roundRedacted", "roundRestored"] as const) {
    if (!isNumber(o[k])) throw new Error(`bad session stats: ${k} not number`);
  }
  if (typeof o.roundRestoreKind !== "string") throw new Error("bad session stats: roundRestoreKind not string");
  return o as unknown as SessionStats;
}

function roundLabel(s: SessionStats): string {
  if (s.roundRedacted === 0 && s.roundRestored === 0) return "clean this round";
  const parts: string[] = [];
  if (s.roundRedacted > 0) parts.push(`redacted ${s.roundRedacted}`);
  if (s.roundRestored > 0) parts.push(`restored ${s.roundRestored}${s.roundRestoreKind ? ` (${s.roundRestoreKind})` : ""}`);
  return parts.join(" · ");
}

const SENSITIVITY_ORDER: SensitivityName[] = ["strict", "balanced", "relaxed"];
const SENSITIVITY_HINT: Record<SensitivityName, string> = {
  strict: "Catches more (entropy 4.0, tokens from 16 chars)",
  balanced: "Default (entropy 4.5, tokens from 20 chars)",
  relaxed: "Fewer false positives (entropy 5.0, tokens from 28 chars)",
};

export default Plugin.define({
  id: "opencode-safeguard-tui",
  async setup(context) {
    const rpc = context.client.rpc(Safeguard);
    const [enabled, setEnabled] = createSignal<boolean | undefined>(undefined);
    const [tick, setTick] = createSignal(0);

    const refreshState = async (): Promise<Snapshot | undefined> => {
      try {
        const s = narrowSnapshot(await rpc.getState({}));
        setEnabled(s.enabled);
        return s;
      } catch {
        setEnabled(undefined);
        return undefined;
      }
    };
    const fetchSession = async (sessionID: string): Promise<SessionStats | undefined> => {
      try {
        return narrowSession(await rpc.getSession({ sessionID }));
      } catch {
        return undefined;
      }
    };
    await refreshState();

    const offUpdated = rpc.events.on("updated", (event) => {
      const data = (event.data ?? {}) as Record<string, unknown>;
      if (typeof data.enabled === "boolean") setEnabled(data.enabled);
      // Any update may change the stats of the session shown in the sidebar.
      setTick((n) => n + 1);
    });

    const toast = (message: string, variant: "success" | "error" | "info" = "success"): void => {
      context.ui.toast.show({ title: "Safeguard", message, variant });
    };
    const unavailable = (): void => toast("Server plugin unavailable (is opencode-safeguard loaded?)", "error");

    const pickSensitivity = async (s: Snapshot): Promise<void> => {
      const current = presetOf(s.minEntropy, s.minTokenLength);
      const choice = await context.ui.dialog.select<SensitivityName | "back">({
        title: "Detection sensitivity",
        current,
        options: [
          ...SENSITIVITY_ORDER.map((name) => ({
            title: `${name}${name === current ? " (current)" : ""}`,
            value: name as SensitivityName | "back",
            description: SENSITIVITY_HINT[name],
          })),
          { title: "Back", value: "back" as const, description: "Return without changing" },
        ],
      });
      if (choice === undefined || choice === "back") return;
      try {
        await rpc.setSensitivity({ ...SENSITIVITY_PRESETS[choice] });
        toast(`Sensitivity: ${choice}`);
      } catch {
        unavailable();
      }
    };

    const openMenu = async (): Promise<void> => {
      for (;;) {
        const s = await refreshState();
        if (!s) {
          unavailable();
          return;
        }
        const preset = presetOf(s.minEntropy, s.minTokenLength);
        const choice = await context.ui.dialog.select<"toggle" | "audit" | "sensitivity">({
          title: `Safeguard ${s.enabled ? "on" : "off"} — ${s.rules} detection rules, ${s.literals} known secrets`,
          current: "toggle",
          options: [
            {
              title: s.enabled ? "Disable" : "Enable",
              value: "toggle",
              description: s.enabled ? "Send content to the LLM unredacted" : "Redact secrets before they reach the LLM",
            },
            {
              title: `Audit logging ${s.audit ? "on" : "off"}`,
              value: "audit",
              description: "Log redaction counts, never values",
            },
            {
              title: `Sensitivity: ${preset}`,
              value: "sensitivity",
              description: "High-entropy fallback thresholds",
            },
          ],
        });
        if (choice === undefined) return;
        try {
          if (choice === "toggle") {
            const r = (await rpc.setEnabled({ enabled: !s.enabled })) as { enabled: boolean };
            setEnabled(r.enabled);
            toast(`Safeguard ${r.enabled ? "enabled" : "disabled"}`);
          } else if (choice === "audit") {
            await rpc.setAudit({ audit: !s.audit });
            toast(`Audit logging ${!s.audit ? "enabled" : "disabled"}`);
          } else {
            await pickSensitivity(s);
          }
        } catch {
          unavailable();
          return;
        }
      }
    };

    context.keymap.layer(() => ({
      mode: "global",
      commands: [
        {
          id: "safeguard.configure",
          title: "Configure safeguard",
          group: "Safeguard",
          palette: true,
          slash: { name: "safeguard" },
          run: () => void openMenu(),
        },
      ],
    }));

    const disposeSlot = context.ui.slot({
      append: "sidebar.footer",
      render: (input) => {
        const ctx = usePlugin();
        const [loaded, setLoaded] = createSignal(false);
        const [stats, setStats] = createSignal<SessionStats | undefined>(undefined);
        // Refetch on mount and after every server update (new round, redaction, restore).
        createEffect(() => {
          tick();
          const sessionID = input.sessionID;
          void (async () => {
            const s = await fetchSession(sessionID);
            if (s) setStats(s);
            setLoaded(true);
          })();
        });
        const on = enabled();
        const dim = ctx.theme.text.muted;
        return (
          <box flexDirection="column">
            <text fg={ctx.theme.text.base}>{on === undefined ? "safeguard ?" : on ? "safeguard on" : "safeguard off"}</text>
            <Show when={loaded()}>
              <Show when={stats()} fallback={<text fg={dim}>safeguard: server unreachable</text>}>
                {(st) => (
                  <box flexDirection="column">
                    <text fg={dim}>{`${st().entries} secrets mapped (${st().totalEntries} total)`}</text>
                    <text fg={dim}>{roundLabel(st())}</text>
                  </box>
                )}
              </Show>
            </Show>
          </box>
        );
      },
    });

    return () => {
      offUpdated();
      disposeSlot();
    };
  },
});
