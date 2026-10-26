# Releasing

Releases are built and published by CI, never from a workstation.
`.github/workflows/build.yml` builds and smoke-tests every package (it also
runs on pull requests that could change one); `release.yml` runs it for a tag
and publishes the result. Every package's version is
`workspace.package.version` in `Cargo.toml`.

1. Bump `workspace.package.version` in `Cargo.toml` and merge the change to
   `main`.
2. Tag that commit and push the tag (only repository admins may create `v*`
   tags):

   ```bash
   git tag v0.1.0 && git push origin v0.1.0
   ```

The workflow refuses a tag whose commit is not on `main` or whose version does
not match the workspace version. It builds the `airlox` binary for macOS
(arm64, x64), Linux (arm64, x64; static musl) and Windows (x64), and from them:

| Where | What |
|---|---|
| PyPI | `airlox`: abi3 wheels for each platform, with the Rust core as `airlox._core` and the binary as a script, and an sdist (no binary) |
| npm | `airlox`, a wrapper whose `bin` runs the binary from `@airlox/<os>-<cpu>`, one package per platform |
| GitHub release | each binary archived with the licenses, the MCPB bundle `airlox-<version>.mcpb`, and `SHA256SUMS` |
| MCP registry | `io.github.claudezss/airlox`, naming the npm and PyPI packages and the bundle |

Nothing is published unless every build succeeded. PyPI, npm and the GitHub
release go out in parallel, then the registry entry, since the registry checks
that each package exists and names the server (`mcpName` in the npm wrapper's
`package.json`, `mcp-name:` in the PyPI README, `mcp` in the bundle's URL).

If a release fails partway, use **Re-run failed jobs**: the builds' artifacts
are kept, and each publish step skips what is already published. A full
re-run rebuilds the files, which then differ from those already out, so the
GitHub release step refuses to replace them. Fix forward with a new version
instead.

## Setup (once)

- A GitHub environment `release` (Settings → Environments) limited to `v*`
  tags, with required reviewers if more than one person can push tags, and a
  tag ruleset that limits who may create `v*` tags. The publish jobs run in
  it.
- PyPI: `PYPI_TOKEN`, a PyPI API token scoped to the `airlox` project, as a
  secret of the `release` environment. (PyPI trusted publishing can replace
  it.)
- npm: trusted publishing, with no token. npm can no longer publish with tokens
  that skip two-factor authentication (from early 2027), and it can trust a
  workflow only for packages that already exist, so:
  1. Join or create the npm organization `airlox`, which owns the `@airlox`
     scope, with two-factor authentication on.
  2. `sh packaging/npm/bootstrap.sh claim` publishes a 0.0.1 placeholder of
     `airlox` and each `@airlox/<os>-<cpu>`, holding the names.
  3. Just before tagging the first release (a new trust lapses unless it
     publishes within two days), `sh packaging/npm/bootstrap.sh trust` lets
     `release.yml` in the `release` environment publish all six.
- The MCP registry needs no secret: the workflow logs in with the repository's
  GitHub OIDC token, which grants the `io.github.claudezss/*` namespace.

The hosted relay is deployed separately, on every relevant merge to `main`;
see [deploy.md](deploy.md).
