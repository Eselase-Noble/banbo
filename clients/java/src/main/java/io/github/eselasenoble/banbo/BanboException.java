package io.github.eselasenoble.banbo;

/**
 * Thrown when the banbo binary cannot be resolved or executed, or when its output
 * cannot be parsed.
 *
 * <p>Note that findings-driven non-zero exit codes (1 and 2) are <em>not</em> errors:
 * they mean banbo ran successfully and found issues. Only exit codes other than
 * 0, 1, or 2 raise this exception.</p>
 */
public class BanboException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public BanboException(String message) {
        super(message);
    }

    public BanboException(String message, Throwable cause) {
        super(message, cause);
    }
}
