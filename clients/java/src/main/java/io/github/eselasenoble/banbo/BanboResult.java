package io.github.eselasenoble.banbo;

/**
 * The raw result of executing the banbo binary: its exit code and captured streams.
 *
 * @see BanboCommand#runRaw()
 */
public final class BanboResult {

    private final int exitCode;
    private final String stdout;
    private final String stderr;

    public BanboResult(int exitCode, String stdout, String stderr) {
        this.exitCode = exitCode;
        this.stdout = stdout;
        this.stderr = stderr;
    }

    /**
     * Process exit code. Per the banbo contract: {@code 0} = clean / info only,
     * {@code 1} = low/medium findings, {@code 2} = high/critical findings.
     */
    public int getExitCode() {
        return exitCode;
    }

    public String getStdout() {
        return stdout;
    }

    public String getStderr() {
        return stderr;
    }

    @Override
    public String toString() {
        return "BanboResult{exitCode=" + exitCode + ", stdoutLength="
                + (stdout == null ? 0 : stdout.length()) + "}";
    }
}
