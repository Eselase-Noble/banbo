# Language SDKs

banbo is a single binary, and each language package is a thin wrapper that downloads that binary and exposes both a **CLI** and a small **typed API** returning banbo's JSON findings as native objects. Full per-ecosystem guides live under [`clients/`](https://github.com/Eselase-Noble/banbo/tree/production/clients) in the repo.

| Ecosystem | Install |
|-----------|---------|
| Go (import) | `go get github.com/Eselase-Noble/banbo/pkg/banbo` |
| Java / Maven | `io.github.eselase-noble:banbo` |
| JavaScript / npm | `npm install banbo` |
| Python / PyPI | `pip install banbo` |
| PHP / Composer | `composer require eselase-noble/banbo` |
| C# / NuGet | `dotnet add package Banbo` |

## Go

```go
import "github.com/Eselase-Noble/banbo/pkg/banbo"

res, err := banbo.ReviewCode(ctx, ".", nil)   // or banbo.Scan(ctx, "example.com.gh", nil)
for _, f := range res.Findings {
    fmt.Printf("[%s] %s — %s\n", f.Severity, f.Title, f.Asset)
}
```

## JavaScript

```js
import { code } from "banbo";
const res = await code(".");
console.log(res.summary, res.findings);
```

## Python

```python
import banbo
res = banbo.code(".")
print(res.summary, res.findings)
```

## Java

```java
ScanResult res = Banbo.code(Path.of(".")).run();
res.getFindings().forEach(f -> System.out.println(f.getSeverity() + " " + f.getTitle()));
```

## PHP

```php
use EselaseNoble\Banbo\Banbo;
$res = Banbo::code('.')->run();
foreach ($res->findings as $f) { echo $f->severity->value . ' ' . $f->title . "\n"; }
```

## C#

```csharp
using Banbo;
var res = BanboClient.Code(".").Run();
foreach (var f in res.Findings) Console.WriteLine($"{f.Severity} {f.Title}");
```

!!! tip "Point a wrapper at an existing binary"
    Set `BANBO_BINARY=/path/to/banbo` and the wrapper skips the download and uses that binary — handy for air-gapped or pre-provisioned environments.
