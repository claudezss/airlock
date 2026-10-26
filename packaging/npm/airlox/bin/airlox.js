#!/usr/bin/env node
"use strict";
// Runs the airlox binary from the platform package installed with this one.
// The platform packages are optional dependencies limited by `os` and `cpu`,
// so npm installs only the one for this machine and nothing runs at install.

const { spawn } = require("node:child_process");

const PLATFORMS = {
  "darwin-arm64": "@airlox/darwin-arm64",
  "darwin-x64": "@airlox/darwin-x64",
  "linux-arm64": "@airlox/linux-arm64",
  "linux-x64": "@airlox/linux-x64",
  "win32-x64": "@airlox/win32-x64",
};

const key = `${process.platform}-${process.arch}`;
const pkg = PLATFORMS[key];
if (!pkg) {
  console.error(`airlox: there is no airlox binary for ${key}; see https://github.com/claudezss/airlox#install`);
  process.exit(1);
}
let bin;
try {
  bin = require.resolve(`${pkg}/bin/airlox${process.platform === "win32" ? ".exe" : ""}`);
} catch {
  console.error(`airlox: ${pkg} is not installed; reinstall airlox with optional dependencies enabled`);
  process.exit(1);
}

const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });
// A terminal sends SIGINT and SIGHUP to the binary too, so those only keep
// this process waiting for it; SIGTERM (an MCP client stopping its server)
// reaches only this process and is passed on.
process.on("SIGINT", () => {});
process.on("SIGHUP", () => {});
process.on("SIGTERM", () => child.kill("SIGTERM"));
child.on("error", (e) => {
  console.error(`airlox: ${e.message}`);
  process.exit(1);
});
child.on("exit", (code, signal) => {
  if (signal) {
    process.removeAllListeners(signal);
    process.kill(process.pid, signal);
  } else {
    process.exit(code);
  }
});
