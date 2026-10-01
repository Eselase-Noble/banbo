package io.github.eselasenoble.banbo;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A non-fatal error reported by an individual banbo scan module.
 *
 * <p>Modules may fail independently; the overall scan can still succeed and
 * return findings while recording these errors.</p>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class ModuleError {

    private String module;
    private String error;

    public String getModule() {
        return module;
    }

    public void setModule(String module) {
        this.module = module;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    @Override
    public String toString() {
        return "ModuleError{module='" + module + "', error='" + error + "'}";
    }
}
