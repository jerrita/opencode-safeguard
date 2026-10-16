import { Rpc } from "@opencode/plugin/rpc";

/**
 * Shared RPC contract between the server plugin (src/index.ts, registers the
 * implementation) and the TUI plugin (src/tui.tsx, calls it). Exported via
 * the package "./rpc" subpath.
 */
export const Safeguard = Rpc.define({
  id: "safeguard",
  methods: {
    getState: {
      input: { type: "object", additionalProperties: false },
      output: {
        type: "object",
        properties: {
          enabled: { type: "boolean" },
          audit: { type: "boolean" },
          minEntropy: { type: "number" },
          minTokenLength: { type: "number" },
          literals: { type: "number" },
        },
        required: ["enabled", "audit", "minEntropy", "minTokenLength", "literals"],
        additionalProperties: false,
      },
    },
    setEnabled: {
      input: {
        type: "object",
        properties: { enabled: { type: "boolean" } },
        required: ["enabled"],
        additionalProperties: false,
      },
      output: {
        type: "object",
        properties: { enabled: { type: "boolean" } },
        required: ["enabled"],
        additionalProperties: false,
      },
    },
    setAudit: {
      input: {
        type: "object",
        properties: { audit: { type: "boolean" } },
        required: ["audit"],
        additionalProperties: false,
      },
      output: {
        type: "object",
        properties: { audit: { type: "boolean" } },
        required: ["audit"],
        additionalProperties: false,
      },
    },
    setSensitivity: {
      input: {
        type: "object",
        properties: { minEntropy: { type: "number" }, minTokenLength: { type: "number" } },
        required: ["minEntropy", "minTokenLength"],
        additionalProperties: false,
      },
      output: {
        type: "object",
        properties: { minEntropy: { type: "number" }, minTokenLength: { type: "number" } },
        required: ["minEntropy", "minTokenLength"],
        additionalProperties: false,
      },
    },
  },
  events: {
    updated: {
      schema: {
        type: "object",
        properties: { enabled: { type: "boolean" }, audit: { type: "boolean" } },
        required: ["enabled", "audit"],
        additionalProperties: false,
      },
    },
  },
});
