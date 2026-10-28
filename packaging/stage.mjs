#!/usr/bin/env node
// Lays out the release packages around the built `airlox` binaries. Run by
// .github/workflows/build.yml and release.yml; the binaries come from the
// build job as <bins>/bin-<target>/airlox[.exe].
//
//   node packaging/stage.mjs npm <version> <bins> <out>    npm packages, one directory each
//   node packaging/stage.mjs mcpb <version> <bins> <out>   the MCPB bundle's directory
//   node packaging/stage.mjs server-json <version> <mcpb> <out>   the MCP registry entry

import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

// Rust target → npm platform package. Linux binaries are static (musl), so one
// per architecture runs on any distribution.
export const TARGETS = {
  "aarch64-apple-darwin": { os: "darwin", cpu: "arm64", label: "macOS arm64" },
  "x86_64-apple-darwin": { os: "darwin", cpu: "x64", label: "macOS x64" },
  "aarch64-unknown-linux-musl": { os: "linux", cpu: "arm64", label: "Linux arm64" },
  "x86_64-unknown-linux-musl": { os: "linux", cpu: "x64", label: "Linux x64" },
  "x86_64-pc-windows-msvc": { os: "win32", cpu: "x64", label: "Windows x64" },
};

const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
const writeJson = (p, v) => writeFileSync(p, JSON.stringify(v, null, 2) + "\n");
const exe = (t) => (TARGETS[t].os === "win32" ? "airlox.exe" : "airlox");

function copyBinary(from, to) {
  mkdirSync(dirname(to), { recursive: true });
  copyFileSync(from, to);
  chmodSync(to, 0o755);
}

function copyLicenses(dir) {
  for (const f of ["LICENSE-MIT", "LICENSE-APACHE"]) copyFileSync(join(root, f), join(dir, f));
}

function npm(version, bins, out) {
  const wrapper = readJson(join(here, "npm/airlox/package.json"));
  const common = { license: wrapper.license, homepage: wrapper.homepage, repository: wrapper.repository };
  wrapper.version = version;
  wrapper.optionalDependencies = {};
  for (const [target, { os, cpu, label }] of Object.entries(TARGETS)) {
    const name = `@airlox/${os}-${cpu}`;
    const dir = join(out, `${os}-${cpu}`);
    copyBinary(join(bins, `bin-${target}`, exe(target)), join(dir, "bin", exe(target)));
    copyLicenses(dir);
    writeJson(join(dir, "package.json"), {
      name,
      version,
      description: `The airlox binary for ${label}; install the airlox package instead`,
      ...common,
      os: [os],
      cpu: [cpu],
      files: ["bin", "LICENSE-*"],
      preferUnplugged: true,
    });
    wrapper.optionalDependencies[name] = version;
  }
  const dir = join(out, "airlox");
  mkdirSync(join(dir, "bin"), { recursive: true });
  copyBinary(join(here, "npm/airlox/bin/airlox.js"), join(dir, "bin/airlox.js"));
  copyFileSync(join(here, "npm/airlox/README.md"), join(dir, "README.md"));
  copyLicenses(dir);
  writeJson(join(dir, "package.json"), wrapper);
}

// One bundle for Claude Desktop's platforms: a universal macOS binary (made
// with lipo by the workflow, as bin-universal-apple-darwin) and Windows x64.
function mcpb(version, bins, out) {
  const manifest = readJson(join(here, "mcpb/manifest.json"));
  manifest.version = version;
  mkdirSync(out, { recursive: true });
  writeJson(join(out, "manifest.json"), manifest);
  copyFileSync(join(here, "mcpb/icon.png"), join(out, "icon.png"));
  copyBinary(join(bins, "bin-universal-apple-darwin/airlox"), join(out, "server/airlox"));
  copyBinary(join(bins, "bin-x86_64-pc-windows-msvc/airlox.exe"), join(out, "server/airlox.exe"));
  copyLicenses(out);
}

// The PyPI package runs the same binary, so it takes the same arguments.
function serverJson(version, bundle, out) {
  const s = readJson(join(here, "server.json"));
  // The registry refuses a longer one, and only at publish time.
  if (s.description.length > 100) {
    console.error(`stage.mjs: server.json description is ${s.description.length} characters; the MCP registry allows 100`);
    process.exit(1);
  }
  s.version = version;
  const [npmPkg, pypiPkg, mcpbPkg] = s.packages;
  npmPkg.version = pypiPkg.version = version;
  pypiPkg.packageArguments = npmPkg.packageArguments;
  pypiPkg.environmentVariables = npmPkg.environmentVariables;
  const file = bundle.split(/[\\/]/).pop();
  mcpbPkg.identifier = `https://github.com/claudezss/airlox/releases/download/v${version}/${file}`;
  mcpbPkg.fileSha256 = createHash("sha256").update(readFileSync(bundle)).digest("hex");
  writeJson(out, s);
}

const [cmd, version, ...rest] = process.argv.slice(2);
if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version ?? "")) {
  console.error(`stage.mjs: ${JSON.stringify(version)} is not a version`);
  process.exit(2);
}
const commands = { npm, mcpb, "server-json": serverJson };
if (!commands[cmd] || rest.length !== 2) {
  console.error("usage: stage.mjs npm|mcpb|server-json <version> <input> <out>");
  process.exit(2);
}
commands[cmd](version, ...rest);
