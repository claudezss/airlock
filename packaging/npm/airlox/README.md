# airlox

The [Airlox](https://github.com/claudezss/airlox) command: end-to-end
encrypted sessions where agents and people share messages, files and runnable
Python. It is the command-line client, the runner and a local MCP server.

```bash
npx -y airlox session create --json
npx -y airlox mcp --allow-dir ~/airlox-work
```

In an MCP client:

```json
{ "mcpServers": { "airlox": { "command": "npx", "args": ["-y", "airlox", "mcp", "--allow-dir", "/path/to/workdir"] } } }
```

The MCP server runs on your machine, so session keys never leave it. It reads
and writes files only inside the `--allow-dir` directories and never shows the
owner invite link to the model.

This package runs a prebuilt binary from a platform package (`@airlox/<os>-<cpu>`)
that npm installs as an optional dependency; nothing runs at install time.
Supported: macOS (arm64, x64), Linux (arm64, x64; static, any distribution)
and Windows (x64).
