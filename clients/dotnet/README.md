# Banbo (.NET)

Idiomatic .NET client for [**banbo**](https://github.com/Eselase-Noble/banbo), a layered
security scanner. This package does **not** reimplement scanning — it downloads the
prebuilt banbo CLI binary for your platform on first use, caches it per-user, and runs it,
returning strongly typed results.

- Targets `netstandard2.0` (broad compatibility) and `net8.0`.
- Parses banbo's JSON output with `System.Text.Json`.

## Install

```bash
dotnet add package Banbo --version 0.1.3
```

Or add a `<PackageReference>` to your `.csproj`:

```xml
<ItemGroup>
  <PackageReference Include="Banbo" Version="0.1.3" />
</ItemGroup>
```

## Usage

### Scan (synchronous)

```csharp
using Banbo;

var result = BanboClient.Scan("example.com")
    .Authorized()          // -y / --i-am-authorized
    .Ports(80, 443)        // --ports 80,443
    .Timeout("5s")         // --timeout 5s
    .NoAi()                // --no-ai
    .Run();                // -> ScanResult

Console.WriteLine($"{result.Summary?.Total} findings on {result.Host}");
foreach (var f in result.Findings)
{
    Console.WriteLine($"[{f.Severity}] {f.Layer}: {f.Title} ({f.Asset})");
}
```

### Source-code review (`code`)

```csharp
using Banbo;

var result = BanboClient.Code("./src")
    .Full()        // --full
    .Run();

foreach (var f in result.Findings)
{
    Console.WriteLine($"[{f.Severity}] {f.Title} -> {f.Remediation}");
}
```

### Async

```csharp
using Banbo;

ScanResult result = await BanboClient.Scan("example.com")
    .Authorized()
    .RunAsync();

// Code review async, too:
ScanResult code = await BanboClient.Code(".").NoAi().RunAsync();
```

### Raw output and arbitrary commands

`RunRaw()` / `RunRawAsync()` return the raw process result instead of parsing:

```csharp
BanboResult raw = BanboClient.Scan("example.com").Authorized().RunRaw();
Console.WriteLine($"exit={raw.ExitCode}");
Console.WriteLine(raw.StdOut);
Console.WriteLine(raw.StdErr);

// Run any banbo command directly:
BanboResult version = BanboClient.Exec("version");
Console.WriteLine(BanboClient.Version());
```

Exit codes **0** (clean/info), **1** (low/medium) and **2** (high/critical) all mean banbo
ran successfully. Any other exit code throws a `BanboException`.

## Binary resolution

On first use the client resolves the banbo binary in this order:

1. The `BANBO_BINARY` environment variable, if it points to an existing file.
2. A previously cached download for this version.
3. A fresh download from the matching
   [GitHub release](https://github.com/Eselase-Noble/banbo/releases), extracted and cached
   under `LocalApplicationData/banbo/<version>` (made executable on Unix).

### `BANBO_BINARY` override

To use a locally built banbo binary instead of a downloaded release (handy for development,
air-gapped environments, or CI with a pre-provisioned binary):

```bash
export BANBO_BINARY=/path/to/banbo      # banbo.exe on Windows
```

Supported platforms: `linux`, `darwin`, `windows` on `amd64` and `arm64`.

## Result model

- `ScanResult` — `Target`, `Host`, `StartedAt`, `DurationMs`, `Findings`, `Summary`, `Errors`.
- `Finding` — `Id`, `Title`, `Layer`, `Severity`, `Asset`, plus optional `Evidence`,
  `Description`, `Remediation`, `References`, `Cvss`, `Compliance`, `AiExplanation`,
  `AiRemediation`, `BusinessImpact`.
- `Severity` — enum (`Info`, `Low`, `Medium`, `High`, `Critical`), serialized lowercase.
- `Counts` — per-severity summary (`Critical`, `High`, `Medium`, `Low`, `Info`, `Total`).
- `ModuleError` — `Module`, `Error` (non-fatal per-module failures).
- `BanboException` — thrown on resolution/execution/parse failure.

## Publishing (maintainers)

Releases to [nuget.org](https://www.nuget.org/) are automated by
`.github/workflows/publish-nuget.yml`, which triggers on pushing a `v*` tag and runs
`dotnet pack` + `dotnet nuget push` from `clients/dotnet`. The workflow stays dormant
until the API key secret is present.

Add this repository secret:

| Secret           | Description                                                                 |
| ---------------- | --------------------------------------------------------------------------- |
| `NUGET_API_KEY`  | An API key from a [nuget.org](https://www.nuget.org/) account with push rights for the `Banbo` package. |

Create the key at **nuget.org → Account → API Keys** (scope: Push, glob pattern `Banbo`),
then add it under **GitHub repo → Settings → Secrets and variables → Actions**.

## License

MIT
