package io.github.eselasenoble.banbo;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Severity of a {@link Finding}, ordered from least to most serious.
 *
 * <p>Serialized to / deserialized from the lowercase JSON tokens emitted by banbo
 * (for example {@code "high"}).</p>
 */
public enum Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    /** Lowercase JSON representation, e.g. {@code CRITICAL -> "critical"}. */
    @JsonValue
    public String jsonValue() {
        return name().toLowerCase();
    }

    /**
     * Parses a severity from its JSON token, case-insensitively.
     *
     * @param value the JSON token (e.g. {@code "medium"})
     * @return the matching severity, or {@code null} if {@code value} is {@code null}
     * @throws IllegalArgumentException if {@code value} is not a known severity
     */
    @JsonCreator
    public static Severity fromJson(String value) {
        if (value == null) {
            return null;
        }
        return Severity.valueOf(value.trim().toUpperCase());
    }
}
