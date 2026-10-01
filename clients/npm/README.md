# banbo (npm)

npm wrapper for [**banbo**](https://github.com/Eselase-Noble/banbo), a layered
security scanner written in Go. This package does **not** reimplement scanning —
on install it downloads the prebuilt `banbo` binary for your platform and runs
it, both as a CLI and as a programmatic library.

## Install

```sh
npm install banbo
```

The `postinstall` step downloads the matching `banbo` binary for your OS/arch
into the package (`vendor/banbo`), verifies its sha256 against the release
`checksums.txt`, and makes it executable. Supported platforms:

| OS      | Arch          |
| ------- | ------------- |
| Linux   | x64, arm64    |
| macOS   | x64, arm64    |
| Windows | x64, arm64    |

## CLI

Run it with `npx` (or add it to an npm script):

```sh
# Scan code in the current directory
npx banbo code .

# Scan a host (active scanning requires explicit authorization)
npx banbo scan example.com --i-am-authorized --ports 80,443

# Version
npx banbo version
```

All arguments and the process exit code are passed straight through to the
underlying binary. See `banbo --help` for the full set of flags.

Exit codes: `0` clean/info, `1` low/medium findings, `2` high/critical
findings (all three mean the scan ran successfully). Any other code is an error.

## Library

```js
const { scan, code, run, version } = require('banbo');
// or:  import { scan, code } from 'banbo';

// Code review of the current directory -> parsed ScanResult
const result = await code('.', { noAi: true });
console.log(result.summary); // { critical, high, medium, low, info, total }

// Host scan with explicit authorization
const netResult = await scan('example.com', {
  authorized: true,
  ports: [80, 443],
  timeout: '5s',
});

for (const f of netResult.findings) {
  console.log(`[${f.severity}] ${f.title} — ${f.asset}`);
}

// Low-level escape hatch: raw args, raw stdout/stderr/exit
const { exitCode, stdout } = await run(['scan', 'example.com', '-o', 'json']);
```

`scan` and `code` request `-o json` and resolve to a parsed `ScanResult`. They
treat exit codes `0`, `1`, and `2` as success (findings present) and throw on
any other exit code. TypeScript types (`ScanResult`, `Finding`, `Severity`,
`Counts`, `ModuleError`, option interfaces) ship in `index.d.ts`.

### AI enrichment

banbo can enrich findings with an LLM. Pass an API key to the child process:

```js
await code('.', { anthropicApiKey: process.env.ANTHROPIC_API_KEY });
await scan('example.com', { authorized: true, openaiApiKey: process.env.OPENAI_API_KEY });
```

These are injected as `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`. Use `{ noAi: true }`
to disable enrichment entirely.

## Using a custom binary (`BANBO_BINARY`)

Set `BANBO_BINARY` to an absolute path to skip the download and use a locally
built binary. It takes precedence everywhere (postinstall, CLI, and library):

```sh
export BANBO_BINARY=/path/to/banbo
npx banbo version
```

This is handy on unsupported platforms or when developing banbo itself.

## Publishing (maintainers)

This package is published by the
[`publish-npm.yml`](../../.github/workflows/publish-npm.yml) workflow when a
`v*` tag is pushed. The version is derived from the tag (leading `v` stripped).

To enable publishing you must configure **one repository secret**:

- **`NPM_TOKEN`** — an npm **Automation** access token for an account/org that
  owns the `banbo` package name on the public npm registry.

Until `NPM_TOKEN` is present the publish job is skipped (it stays dormant and
harmless). You also need an npm account that has published, or been granted
publish rights to, the `banbo` package name.
