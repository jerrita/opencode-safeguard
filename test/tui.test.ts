import { afterEach, describe, expect, it, vi } from "vitest";

const { effects, cleanups } = vi.hoisted(() => ({
  effects: [] as (() => void)[],
  cleanups: [] as (() => void)[],
}));

vi.mock("@opencode/plugin/tui", () => ({
  Plugin: { define: (plugin: unknown) => plugin },
  usePlugin: () => ({ theme: { text: { base: "white", muted: "gray" } } }),
}));
vi.mock("solid-js", async (original) => ({
  ...(await original<typeof import("solid-js")>()),
  createEffect: (effect: () => void) => {
    effects.push(effect);
    effect();
  },
  onCleanup: (cleanup: () => void) => cleanups.push(cleanup),
}));

import plugin from "../src/tui.js";

function harness() {
  vi.stubGlobal("React", { createElement: () => null });
  const sessionLocation = { directory: "/projects/example" };
  const rpc = {
    getState: vi.fn().mockResolvedValue({
      enabled: true,
      audit: true,
      minEntropy: 4.5,
      minTokenLength: 20,
      literals: 0,
      rules: 1,
    }),
    getSession: vi.fn().mockResolvedValue({
      entries: 2,
      totalEntries: 3,
      roundRedacted: 1,
      roundRestored: 0,
      roundRestoreKind: "",
    }),
    setEnabled: vi.fn().mockResolvedValue({ enabled: false }),
    events: { on: vi.fn().mockReturnValue(vi.fn()) },
  };
  const context = {
    client: { rpc: () => rpc },
    location: { directory: "/projects/other" },
    data: {
      session: { get: vi.fn().mockReturnValue({ location: sessionLocation }) },
      location: { default: () => ({ directory: "/server/default" }) },
    },
    keymap: { layer: vi.fn() },
    ui: {
      slot: vi.fn().mockReturnValue(vi.fn()),
      router: { current: () => ({ type: "session", sessionID: "session-example" }) },
      dialog: { select: vi.fn().mockResolvedValueOnce("toggle").mockResolvedValue(undefined) },
      toast: { show: vi.fn() },
    },
  };
  return { rpc, context, sessionLocation };
}

afterEach(() => {
  cleanups.splice(0).forEach((cleanup) => cleanup());
  effects.length = 0;
  vi.unstubAllGlobals();
});

describe("TUI RPC location", () => {
  it("reads sidebar state and statistics from the session location", async () => {
    const { rpc, context, sessionLocation } = harness();
    await plugin.setup(context as any);
    const slot = context.ui.slot.mock.calls[0][0];
    slot.render({ sessionID: "session-example" });
    expect(rpc.getSession).toHaveBeenCalledWith({ sessionID: "session-example" }, { location: sessionLocation });
    expect(rpc.getState).toHaveBeenCalledWith({}, { location: sessionLocation });
  });

  it("resolves the location again after the session moves", async () => {
    const { rpc, context } = harness();
    await plugin.setup(context as any);
    context.ui.slot.mock.calls[0][0].render({ sessionID: "session-example" });
    const moved = { directory: "/projects/moved" };
    context.data.session.get.mockReturnValue({ location: moved });
    cleanups.splice(0).forEach((cleanup) => cleanup());
    effects[0]();
    expect(rpc.getSession).toHaveBeenLastCalledWith({ sessionID: "session-example" }, { location: moved });
  });

  it("uses the same session location for menu reads and changes", async () => {
    const { rpc, context, sessionLocation } = harness();
    await plugin.setup(context as any);
    const layer = context.keymap.layer.mock.calls[0][0]();
    layer.commands[0].run();
    await vi.waitFor(() => expect(rpc.setEnabled).toHaveBeenCalled());
    expect(rpc.getState).toHaveBeenCalledWith({}, { location: sessionLocation });
    expect(rpc.setEnabled).toHaveBeenCalledWith({ enabled: false }, { location: sessionLocation });
  });
});
