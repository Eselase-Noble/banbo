package io.github.eselasenoble.banbo;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A fluent builder for a single banbo invocation ({@code scan} or {@code code}).
 *
 * <p>Create one via {@link Banbo#scan(String)} or {@link Banbo#code(java.nio.file.Path)},
 * chain option methods, then terminate with {@link #run()} (parsed {@link ScanResult})
 * or {@link #runRaw()} (exit code + raw streams).</p>
 *
 * <p>Instances are not thread-safe; build and run them on a single thread.</p>
 */
public final class BanboCommand {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private final BinaryResolver resolver;
    private final String subcommand; // "scan" or "code"
    private final String positional; // target (scan) or path (code), may be null for code

    private boolean authorized;
    private boolean full;
    private boolean noAi;
    private boolean active;
    private boolean noColor = true; // JSON consumers want machine output by default
    private String ports;
    private String timeout;
    private String output = "json";

    BanboCommand(BinaryResolver resolver, String subcommand, String positional) {
        this.resolver = resolver;
        this.subcommand = subcommand;
        this.positional = positional;
    }

    /** Pass {@code -y}/{@code --i-am-authorized} to confirm you are authorized to scan the target. */
    public BanboCommand authorized() {
        this.authorized = true;
        return this;
    }

    /** Pass {@code --full} (source-code review depth). Only meaningful for {@code code}. */
    public BanboCommand full() {
        this.full = true;
        return this;
    }

    /** Pass {@code --no-ai} to disable AI-assisted explanations/remediation. */
    public BanboCommand noAi() {
        this.noAi = true;
        return this;
    }

    /** Pass {@code --active} to enable active (more intrusive) checks. Only meaningful for {@code scan}. */
    public BanboCommand active() {
        this.active = true;
        return this;
    }

    /** Pass {@code --no-color} (default true; disable to let banbo emit ANSI colors). */
    public BanboCommand noColor(boolean value) {
        this.noColor = value;
        return this;
    }

    /** Pass {@code --ports p1,p2,...}. Only meaningful for {@code scan}. */
    public BanboCommand ports(String portsCsv) {
        this.ports = portsCsv;
        return this;
    }

    /** Pass {@code --ports 22,80,443}. Only meaningful for {@code scan}. */
    public BanboCommand ports(int... portNumbers) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < portNumbers.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(portNumbers[i]);
        }
        this.ports = sb.toString();
        return this;
    }

    /** Pass {@code --timeout <value>}, e.g. {@code "5s"}. Only meaningful for {@code scan}. */
    public BanboCommand timeout(String goDuration) {
        this.timeout = goDuration;
        return this;
    }

    /**
     * Override the output format passed to {@code -o}. Defaults to {@code json};
     * changing it means {@link #run()} can no longer parse the result, so use
     * {@link #runRaw()} instead.
     */
    public BanboCommand output(String format) {
        this.output = format;
        return this;
    }

    /** @return the exact argument vector that will be passed to the banbo binary. */
    public List<String> buildArgs() {
        List<String> args = new ArrayList<>();
        args.add(subcommand);
        if (positional != null) {
            args.add(positional);
        }
        if (output != null) {
            args.add("-o");
            args.add(output);
        }
        if (authorized) {
            args.add("-y");
        }
        if (ports != null && !ports.isEmpty()) {
            args.add("--ports");
            args.add(ports);
        }
        if (timeout != null && !timeout.isEmpty()) {
            args.add("--timeout");
            args.add(timeout);
        }
        if (active) {
            args.add("--active");
        }
        if (full) {
            args.add("--full");
        }
        if (noAi) {
            args.add("--no-ai");
        }
        if (noColor) {
            args.add("--no-color");
        }
        return args;
    }

    /**
     * Runs banbo and returns the raw exit code and captured streams, without parsing.
     *
     * @throws BanboException on an execution error (exit code outside {0, 1, 2})
     */
    public BanboResult runRaw() {
        return resolver.exec(buildArgs().toArray(new String[0]));
    }

    /**
     * Runs banbo and parses its JSON stdout into a {@link ScanResult}.
     *
     * @throws BanboException on an execution error or if the output is not valid JSON
     */
    public ScanResult run() {
        if (!"json".equals(output)) {
            throw new BanboException("run() requires JSON output but output format is '"
                    + output + "'. Call output(\"json\") or use runRaw().");
        }
        BanboResult raw = runRaw();
        String stdout = raw.getStdout();
        if (stdout == null || stdout.trim().isEmpty()) {
            throw new BanboException("banbo produced no JSON output. stderr: "
                    + (raw.getStderr() == null ? "" : raw.getStderr().trim()));
        }
        try {
            return MAPPER.readValue(stdout, ScanResult.class);
        } catch (Exception e) {
            throw new BanboException("Failed to parse banbo JSON output: " + e.getMessage()
                    + System.lineSeparator() + "Raw stdout: " + stdout, e);
        }
    }

    @Override
    public String toString() {
        return "BanboCommand" + Arrays.toString(buildArgs().toArray());
    }
}
