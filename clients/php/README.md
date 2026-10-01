# banbo (PHP client)

PHP client wrapper for [**banbo**](https://github.com/Eselase-Noble/banbo), a
layered security scanner. This package does **not** reimplement scanning: it
downloads the prebuilt `banbo` CLI binary for your platform, runs it, and parses
its JSON output into typed value objects.

- Layers: DNS, network, transport (TLS), application, and source code (SAST).
- Works on Linux, macOS and Windows (amd64 / arm64).
- Requires **PHP >= 8.0** and the `json` extension (plus `zip` on Windows and
  `phar`/`zlib` on Linux/macOS for archive extraction).

## Installation

```bash
composer require eselase-noble/banbo
```

No binary is bundled in the package. The first time you run a scan, the matching
`banbo` release binary is downloaded from GitHub, checksum-verified, extracted,
and cached under `sys_get_temp_dir()/banbo/<version>/` for reuse.

## Usage

### Scan a host

```php
<?php

require 'vendor/autoload.php';

use EselaseNoble\Banbo\Banbo;
use EselaseNoble\Banbo\Severity;

$result = Banbo::scan('example.com')
    ->authorized()        // -y / --i-am-authorized (you own / may scan the target)
    ->ports('80,443')     // --ports 80,443
    ->timeout('5s')       // --timeout 5s
    ->active()            // --active (enable active checks)
    // ->noAi()           // --no-ai (skip the AI explanation layer)
    ->run();              // -> EselaseNoble\Banbo\ScanResult

echo "Target: {$result->target} ({$result->host})\n";
echo "Total findings: {$result->summary->total}\n";
echo "Critical: {$result->summary->critical}, High: {$result->summary->high}\n";

foreach ($result->findings as $finding) {
    printf(
        "[%s] %s — %s (%s)\n",
        strtoupper($finding->severity->value),
        $finding->title,
        $finding->asset,
        $finding->layer
    );
}

// Convenience helpers
if ($result->hasHighOrCritical()) {
    fwrite(STDERR, "High/critical findings present!\n");
}

$criticals = $result->findingsBySeverity(Severity::Critical);
```

### Review source code (SAST)

```php
<?php

use EselaseNoble\Banbo\Banbo;

$result = Banbo::code('./src')   // defaults to '.' if omitted
    ->full()                     // --full (deeper review)
    ->noAi()                     // --no-ai
    ->run();

foreach ($result->findings as $finding) {
    echo $finding->severity->value, ' ', $finding->title, "\n";
    if ($finding->remediation !== null) {
        echo '  fix: ', $finding->remediation, "\n";
    }
}
```

### Raw output and exit codes

Use `runRaw()` to get the exit code and raw streams without JSON parsing:

```php
$raw = Banbo::scan('example.com')->authorized()->runRaw();
// $raw->exitCode, $raw->stdout, $raw->stderr
// exit 0 = clean/info, 1 = low/medium, 2 = high/critical  (all "ran OK")
```

Any exit code other than `0`, `1` or `2` is an error and throws a
`EselaseNoble\Banbo\BanboException`.

### Arbitrary commands and version

```php
use EselaseNoble\Banbo\Banbo;

echo Banbo::version(), "\n";          // runs `banbo version`
$raw = Banbo::exec(['version']);      // raw Result for any arg list
$path = Banbo::binaryPath();          // resolved binary path
```

## `BANBO_BINARY` override

To use a locally built binary (for development, air-gapped environments, or an
unsupported platform) set the `BANBO_BINARY` environment variable to its path.
When set and pointing at an existing file, it takes precedence over the download:

```bash
export BANBO_BINARY=/path/to/banbo
```

```php
putenv('BANBO_BINARY=/path/to/banbo');  // from within PHP, before the first run
```

## API surface

| Class | Purpose |
| --- | --- |
| `Banbo` | Facade: `scan()`, `code()`, `exec()`, `version()`, `binaryPath()`. |
| `Command` | Fluent builder: `authorized()`, `full()`, `noAi()`, `active()`, `ports()`, `timeout()`, `noColor()`, `withEnv()`, `run()`, `runRaw()`, `toArgs()`. |
| `ScanResult` | Parsed result: `$target`, `$host`, `$startedAt`, `$durationMs`, `$findings`, `$summary`, `$errors`, plus `hasHighOrCritical()` / `findingsBySeverity()`. |
| `Finding` | One finding (id, title, layer, severity, asset, optional evidence/description/remediation/references/cvss/compliance/AI fields). |
| `Severity` | Enum: `Info`, `Low`, `Medium`, `High`, `Critical` (string-backed) with `rank()`. |
| `Counts` | Summary breakdown (`critical`, `high`, `medium`, `low`, `info`, `total`). |
| `ModuleError` | A non-fatal per-module error (`module`, `error`). |
| `Result` | Raw run: `exitCode`, `stdout`, `stderr`, `ok()`, `toScanResult()`. |
| `BanboException` | Thrown on any wrapper/process/parse error. |

---

## Publishing to Packagist (one-time maintainer setup)

Packagist reads `composer.json` from the **root** of the Git repository it is
given. This package lives in the `clients/php/` subtree of the main `banbo`
repo, so it **cannot** be published directly from `Eselase-Noble/banbo` — the
root of that repo is a Go project, not a Composer package.

### Recommended approach: split `clients/php/` into its own repository

Publish the PHP client from a dedicated repository whose root **is** this
package (for example `Eselase-Noble/banbo-php`). Keep developing inside the
monorepo and push the subtree to the dedicated repo on each release.

1. **Create the dedicated repo** on GitHub, e.g. `Eselase-Noble/banbo-php`.

2. **Split the subtree and push it** (run from the monorepo root). `git subtree`
   rewrites `clients/php/` so it becomes the repo root:

   ```bash
   # Add the split target once:
   git remote add banbo-php git@github.com:Eselase-Noble/banbo-php.git

   # On each release, push the clients/php subtree to the dedicated repo's main:
   git subtree push --prefix=clients/php banbo-php main
   ```

   (Equivalently: `git subtree split --prefix=clients/php -b php-split` then
   `git push banbo-php php-split:main`.)

3. **Tag the release in the dedicated repo** so Composer has a version to resolve
   (Packagist derives versions from Git tags). Keep the tag in lock-step with the
   `BinaryResolver::VERSION` constant / the banbo binary release:

   ```bash
   git -C /path/to/banbo-php tag v0.1.3
   git -C /path/to/banbo-php push banbo-php v0.1.3
   ```

4. **Submit the package** at <https://packagist.org/packages/submit>: sign in
   with GitHub and paste the dedicated repo URL
   (`https://github.com/Eselase-Noble/banbo-php`). Packagist reads the
   root `composer.json` and registers the package as `eselase-noble/banbo`.

5. **Enable auto-update** so new tags publish automatically. Either:
   - accept the **GitHub webhook** Packagist offers during submission (it adds a
     hook at `https://packagist.org/api/github` to the dedicated repo), or
   - add the **Packagist** GitHub integration under the repo/org settings, or
   - configure it manually under *Settings → Webhooks* in the `banbo-php` repo
     with your Packagist API token.

   After this, every `git push` of a new `vX.Y.Z` tag to `banbo-php` publishes
   that version to Packagist within seconds.

### Alternative: Packagist subdirectory / path

Packagist does **not** support a per-package subdirectory setting for VCS
repositories — the `composer.json` must be at the repo root. If you prefer not
to maintain a split repo, your only options are a monorepo tool that mirrors the
subtree (e.g. `symplify/monorepo-builder`) or a private Composer repo
(e.g. Satis / Private Packagist) pointed at a VCS `url` with the package at a
path. For public distribution on packagist.org, the subtree-split approach above
is recommended.

### Release checklist

1. Cut the banbo binary release (git tag `vX.Y.Z` on `Eselase-Noble/banbo`) so
   the release assets exist at the URLs the wrapper downloads from.
2. Bump `BinaryResolver::VERSION` to `X.Y.Z` so the wrapper fetches the matching
   binary.
3. `git subtree push --prefix=clients/php banbo-php main`.
4. Tag `vX.Y.Z` in `banbo-php` and push the tag → Packagist auto-updates.

## License

MIT. See the repository `LICENSE`.
