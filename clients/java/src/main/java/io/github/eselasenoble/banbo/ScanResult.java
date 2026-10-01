package io.github.eselasenoble.banbo;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Collections;
import java.util.List;

/**
 * The parsed result of a banbo {@code scan} or {@code code} run (the object printed
 * to stdout by {@code -o json}).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class ScanResult {

    private String target;
    private String host;

    @JsonProperty("started_at")
    private String startedAt;

    /** Scan duration. Despite the field name, banbo reports this in nanoseconds. */
    @JsonProperty("duration_ms")
    private long durationMs;

    private List<Finding> findings;
    private Counts summary;
    private List<ModuleError> errors;

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    /** Scan start time as an RFC 3339 string. */
    public String getStartedAt() {
        return startedAt;
    }

    public void setStartedAt(String startedAt) {
        this.startedAt = startedAt;
    }

    /** Raw duration value from banbo (nanoseconds). */
    public long getDurationMs() {
        return durationMs;
    }

    public void setDurationMs(long durationMs) {
        this.durationMs = durationMs;
    }

    /** Never {@code null}; empty when there are no findings. */
    public List<Finding> getFindings() {
        return findings == null ? Collections.emptyList() : findings;
    }

    public void setFindings(List<Finding> findings) {
        this.findings = findings;
    }

    public Counts getSummary() {
        return summary;
    }

    public void setSummary(Counts summary) {
        this.summary = summary;
    }

    /** Never {@code null}; empty when no module errors occurred. */
    public List<ModuleError> getErrors() {
        return errors == null ? Collections.emptyList() : errors;
    }

    public void setErrors(List<ModuleError> errors) {
        this.errors = errors;
    }

    @Override
    public String toString() {
        return "ScanResult{target='" + target + "', host='" + host + "', findings="
                + getFindings().size() + ", summary=" + summary + '}';
    }
}
