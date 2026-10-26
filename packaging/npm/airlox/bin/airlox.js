#!/usr/bin/env node
"use strict";
// Runs the airlox binary from the platform package installed with this one.
// The platform packages are optional dependencies limited by `os` and `cpu`,
// so npm installs only the one for this machine and nothing runs at install.

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const PLATFORMS = {
  "darwin-arm64": "@airlox/darwin-arm64",
  "darwin-x64": "@airlox/darwin-x64",
  "linux-arm64": "@airlox/linux-arm64",
  "linux-x64": "@airlox/linux-x64",
  "win32-x64": "@airlox/win32-x64",
};

function fail(msg) {
  console.error(`airlox: ${msg}`);
  process.exit(1);
}

const key = `${process.platform}-${process.arch}`;
const pkg = PLATFORMS[key];
if (!pkg) fail(`there is no airlox binary for ${key}; see https://github.com/claudezss/airlox#install`);

// Only where npm, pnpm and bun install this package's dependencies: nested in
// its own node_modules, or next to it. Node's own resolution would also walk
// up through every parent node_modules and NODE_PATH, where anyone able to
// write a directory could plant a package of that name. Yarn PnP keeps no
// node_modules, so there it is left to PnP's resolver.
const own = path.join(__dirname, "..");
const candidates = [path.join(own, "node_modules", pkg), path.join(own, "..", pkg)];
let dir = candidates.find((d) => fs.existsSync(path.join(d, "package.json")));
if (!dir && process.versions.pnp) {
  try {
    dir = path.dirname(require.resolve(`${pkg}/package.json`));
  } catch {}
}
if (!dir) fail(`${pkg} is not installed; reinstall airlox with optional dependencies enabled`);
const want = require(path.join(own, "package.json")).version;
const got = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8")).version;
if (got !== want) fail(`${pkg} is version ${got}, not ${want}; reinstall airlox`);
const bin = path.join(dir, "bin", process.platform === "win32" ? "airlox.exe" : "airlox");

const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });
// Pass signals on: a client may signal only this process. A terminal's ^C
// reaches the binary twice, which is harmless.
for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(sig, () => child.kill(sig));
}
child.on("error", (e) => fail(e.message));
child.on("exit", (code, signal) => {
  if (signal) {
    process.removeAllListeners(signal);
    process.kill(process.pid, signal);
  } else {
    process.exit(code);
  }
});
