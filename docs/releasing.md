# Releasing

Releases are built and published by CI (`.github/workflows/release.yml`),
never from a workstation.

PyPI receives one package, `airlox`: the Python SDK with the Rust protocol core
compiled in as `airlox._core`. Its version is `workspace.package.version` in
`Cargo.toml`.

1. Bump `workspace.package.version` in `Cargo.toml` and merge the change to
   `main`.
2. Tag that commit and push the tag (only repository admins may create `v*`
   tags):

   ```bash
   git tag v0.1.0 && git push origin v0.1.0
   ```

The workflow refuses a tag whose commit is not on `main` or whose version does
not match the workspace version. It builds abi3 wheels for Linux (x86_64,
aarch64), macOS (x86_64, arm64) and Windows (x64), installs and imports each
native wheel, builds an sdist, and uploads them with the `PYPI_TOKEN` secret
only if every build succeeded.

The hosted relay is deployed separately, on every relevant merge to `main`;
see [deploy.md](deploy.md).
