import { transformFileAsync } from "@babel/core";
import typescript from "@babel/preset-typescript";
import solid from "babel-preset-solid";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const result = await transformFileAsync(fileURLToPath(new URL("../src/tui.tsx", import.meta.url)), {
  configFile: false,
  babelrc: false,
  presets: [[solid, { moduleName: "@opentui/solid", generate: "universal" }], typescript],
});

if (!result?.code) throw new Error("TUI compilation produced no output");

const outDir = new URL("../dist/", import.meta.url);
await mkdir(outDir, { recursive: true });
await writeFile(new URL("tui.js", outDir), `${result.code}\n`);
