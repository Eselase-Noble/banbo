# banbo — Java client

A small, idiomatic Java wrapper around the [**banbo**](https://github.com/Eselase-Noble/banbo)
layered security scanner. It does **not** reimplement scanning: on first use it downloads the
prebuilt banbo binary for your platform (once, into a per-user cache), runs it, and parses its
JSON output into typed Java objects.

- Java 11+
- Single runtime dependency: Jackson (`jackson-databind`)

## Install

### Maven

```xml
<dependency>
    <groupId>io.github.eselase-noble</groupId>
    <artifactId>banbo</artifactId>
    <version>0.1.1</version>
</dependency>
```

### Gradle

```groovy
implementation 'io.github.eselase-noble:banbo:0.1.1'
```

## Usage

```java
import io.github.eselasenoble.banbo.Banbo;
import io.github.eselasenoble.banbo.Finding;
import io.github.eselasenoble.banbo.ScanResult;

import java.nio.file.Paths;

public class Example {
    public static void main(String[] args) {
        // Network / service scan of a host you are authorized to test.
        ScanResult scan = Banbo.scan("example.com")
                .authorized()          // -y / --i-am-authorized
                .ports(80, 443)        // --ports 80,443
                .timeout("5s")         // --timeout 5s
                .active()              // --active
                .run();                // parses banbo's -o json output

        System.out.println("Findings: " + scan.getSummary().getTotal());
        for (Finding f : scan.getFindings()) {
            System.out.println(f.getSeverity() + "  " + f.getLayer() + "  " + f.getTitle());
        }

        // Source-code review of a local path.
        ScanResult code = Banbo.code(Paths.get("src/main/java"))
                .full()                // --full
                .noAi()                // --no-ai
                .run();

        code.getFindings().forEach(System.out::println);

        // Need the raw process result (exit code + streams)?
        var raw = Banbo.scan("example.com").authorized().runRaw();
        System.out.println("exit=" + raw.getExitCode());

        // Arbitrary subcommand:
        System.out.println(Banbo.version());
    }
}
```

### Exit codes

banbo signals findings through its exit code, which this client treats as a successful run:

| Exit code | Meaning                         |
|-----------|---------------------------------|
| `0`       | clean / info-only               |
| `1`       | low / medium findings           |
| `2`       | high / critical findings        |
| other     | execution error → `BanboException` |

`BanboResult.getExitCode()` exposes the raw code. `run()` / `runRaw()` only throw on codes
outside `{0, 1, 2}`.

## Using your own banbo binary (`BANBO_BINARY`)

Set the `BANBO_BINARY` environment variable to the full path of an existing banbo executable
and the client will use it directly, skipping the download entirely. This is useful in CI,
air-gapped environments, or when testing against a locally built binary.

```bash
export BANBO_BINARY=/usr/local/bin/banbo
```

The download cache location can also be overridden with `BANBO_CACHE_DIR` (defaults to
`~/.cache/banbo/<version>/`, `$XDG_CACHE_HOME/banbo/<version>/` on Linux, or
`%LOCALAPPDATA%\banbo\cache\<version>\` on Windows).

## Supported platforms

Binaries are resolved for `{linux, darwin, windows}` × `{amd64, arm64}` from the matching
GitHub release asset (`tar.gz` for linux/darwin, `zip` for windows).

---

## Publishing (maintainers only)

Releases publish to Maven Central automatically via
[`.github/workflows/publish-maven.yml`](../../.github/workflows/publish-maven.yml), triggered
by pushing a `v*` tag (e.g. `git tag v0.1.1 && git push origin v0.1.1`). The workflow derives
the artifact version from the tag.

### Required repository secrets

Add these under **Settings → Secrets and variables → Actions**. The deploy step stays dormant
(build + test only) until all of them exist:

| Secret                   | Purpose                                                        |
|--------------------------|----------------------------------------------------------------|
| `GPG_PRIVATE_KEY`        | ASCII-armored GPG private key used to sign the artifacts       |
| `GPG_PASSPHRASE`         | Passphrase for that GPG key                                    |
| `MAVEN_CENTRAL_USERNAME` | Sonatype Central Portal **token username**                     |
| `MAVEN_CENTRAL_TOKEN`    | Sonatype Central Portal **token value**                        |

### One-time Sonatype Central namespace setup

1. Create an account at <https://central.sonatype.com/>.
2. Register and verify the namespace **`io.github.eselase-noble`** (the GitHub-based namespace
   is verified by proving ownership of the `Eselase-Noble` GitHub account, per the Central
   Portal instructions).
3. Generate a **publishing token** (username + token) from your Central account and store it
   as `MAVEN_CENTRAL_USERNAME` / `MAVEN_CENTRAL_TOKEN`.
4. Generate a GPG key, publish its public key to a keyserver, and store the private key and its
   passphrase as `GPG_PRIVATE_KEY` / `GPG_PASSPHRASE`.

Once the namespace is verified and the four secrets exist, pushing a `v*` tag signs and
publishes the release to Maven Central automatically.
