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
Each step skips what is already published, so a failed release can be re-run
from the Actions page.

## Setup (once)

- `PYPI_TOKEN`: a PyPI API token for the `airlox` project, as a repository
  secret.
- `NPM_TOKEN`: an npm automation (or granular, publish-only) token for a
  member of the `airlox` npm organization, which owns the `@airlox` scope, as a
  repository secret. The first release creates the packages; after it, npm
  trusted publishing can replace the token.
- The MCP registry needs no secret: the workflow logs in with the repository's
  GitHub OIDC token, which grants the `io.github.claudezss/*` namespace.

The hosted relay is deployed separately, on every relevant merge to `main`;
see [deploy.md](deploy.md).
