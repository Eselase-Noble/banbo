package io.github.eselasenoble.banbo;

import java.nio.file.Path;

/**
 * Entry point for the banbo Java client.
 *
 * <p>banbo is a standalone Go CLI security scanner. This client does not reimplement
 * scanning: it downloads the prebuilt banbo binary for the host platform (once, into a
 * per-user cache) and runs it, parsing its JSON output into typed Java objects.</p>
 *
 * <p>Typical usage:</p>
 * <pre>{@code
 * ScanResult result = Banbo.scan("example.com")
 *         .authorized()
 *         .ports(80, 443)
 *         .timeout("5s")
 *         .run();
 *
 * for (Finding f : result.getFindings()) {
 *     System.out.println(f.getSeverity() + " " + f.getTitle());
 * }
 *
 * ScanResult code = Banbo.code(Paths.get("src/main/java")).full().run();
 * }</pre>
 *
 * <p>Set the {@code BANBO_BINARY} environment variable to an existing banbo executable
 * to skip the download entirely (useful in CI or air-gapped environments).</p>
 */
public final class Banbo {

    private static final BinaryResolver RESOLVER = new BinaryResolver();

    private Banbo() {
    }

    /**
     * Starts a {@code banbo scan <target>} command.
     *
     * @param target host, IP, or URL to scan (must not be {@code null})
     * @return a fluent builder; terminate with {@link BanboCommand#run()} or
     *         {@link BanboCommand#runRaw()}
     */
    public static BanboCommand scan(String target) {
        if (target == null || target.trim().isEmpty()) {
            throw new IllegalArgumentException("scan target must not be null or empty");
        }
        return new BanboCommand(RESOLVER, "scan", target);
    }

    /**
     * Starts a {@code banbo code [path]} source-review command.
     *
     * @param path directory or file to review; {@code null} means the current directory
     * @return a fluent builder; terminate with {@link BanboCommand#run()} or
     *         {@link BanboCommand#runRaw()}
     */
    public static BanboCommand code(Path path) {
        return new BanboCommand(RESOLVER, "code", path == null ? null : path.toString());
    }

    /**
     * Runs {@code banbo} with an arbitrary argument vector, returning the raw result.
     *
     * <p>Use this for subcommands not covered by the fluent builder, such as
     * {@code Banbo.exec("version")}.</p>
     *
     * @param args raw arguments passed to the banbo binary
     * @return the exit code and captured streams
     * @throws BanboException on an execution error (exit code outside {0, 1, 2})
     */
    public static BanboResult exec(String... args) {
        return RESOLVER.exec(args);
    }

    /**
     * Returns banbo's reported version string (stdout of {@code banbo version}).
     *
     * @throws BanboException on an execution error
     */
    public static String version() {
        return exec("version").getStdout().trim();
    }

    /** @return the shared {@link BinaryResolver} used by the static entry points. */
    public static BinaryResolver resolver() {
        return RESOLVER;
    }
}
