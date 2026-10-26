# airlox-core

The [Airlox](https://github.com/claudezss/airlox) protocol core compiled to
WebAssembly: Ed25519 signatures, AES-256-GCM item encryption, canonical wire
formats and input validators. It is the same Rust code as the Python
`airlox-core` wheel, with the same functions and error messages.

```bash
npm install airlox-core
```

In Node the module is ready on import:

```js
import { generateSeed, publicKey, fingerprint } from "airlox-core";

const seed = generateSeed();
console.log(fingerprint(publicKey(seed)));
```

In the browser (or with `airlox-core/web`), initialize the wasm module first:

```js
import init, { generateSeed, publicKey } from "airlox-core";

await init();
console.log(publicKey(generateSeed()));
```

Structured values cross the boundary as JSON strings and secrets and blobs as
`Uint8Array`s. See [`docs/protocol.md`](https://github.com/claudezss/airlox/blob/main/docs/protocol.md)
for the wire formats.
