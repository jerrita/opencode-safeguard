import { Plugin, usePlugin } from "@opencode/plugin/tui";
import { createSignal } from "solid-js";
import { Safeguard } from "./rpc.js";
import { presetOf, SENSITIVITY_PRESETS, type SensitivityName } from "./state.js";

interface Snapshot {
  enabled: boolean;
  audit: boolean;
  minEntropy: number;
  minTokenLength: number;
  literals: number;
}

function narrowSnapshot(v: unknown): Snapshot {
  const o = (v ?? {}) as Record<string, unknown>;
  for (const k of ["enabled", "audit"] as const) {
    if (typeof o[k] !== "boolean") throw new Error(`bad snapshot: ${k} not boolean`);
  }
  for (const k of ["minEntropy", "minTokenLength", "literals"] as const) {
    if (typeof o[k] !== "number") throw new Error(`bad snapshot: ${k} not number`);
  }
  return o as unknown as Snapshot;
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

    const refresh = async (): Promise<Snapshot | undefined> => {
      try {
        const s = narrowSnapshot(await rpc.getState({}));
        setEnabled(s.enabled);
        return s;
      } catch {
        setEnabled(undefined);
        return undefined;
      }
    };
    await refresh();
    const offUpdated = rpc.events.on("updated", (event) => {
      const data = (event.data ?? {}) as { enabled?: unknown };
      if (typeof data.enabled === "boolean") setEnabled(data.enabled);
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
        const s = await refresh();
        if (!s) {
          unavailable();
          return;
        }
        const preset = presetOf(s.minEntropy, s.minTokenLength);
        const choice = await context.ui.dialog.select<"toggle" | "audit" | "sensitivity">({
          title: `Safeguard ${s.enabled ? "on" : "off"} — ${s.literals} known secrets`,
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
      render: () => {
        const ctx = usePlugin();
        const on = enabled();
        return <text fg={ctx.theme.text.base}>{on === undefined ? "safeguard ?" : on ? "safeguard on" : "safeguard off"}</text>;
      },
    });

    return () => {
      offUpdated();
      disposeSlot();
    };
  },
});
