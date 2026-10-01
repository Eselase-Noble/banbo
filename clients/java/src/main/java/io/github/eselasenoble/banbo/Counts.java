package io.github.eselasenoble.banbo;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Per-severity counts summarizing a {@link ScanResult}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class Counts {

    private int critical;
    private int high;
    private int medium;
    private int low;
    private int info;
    private int total;

    public int getCritical() {
        return critical;
    }

    public void setCritical(int critical) {
        this.critical = critical;
    }

    public int getHigh() {
        return high;
    }

    public void setHigh(int high) {
        this.high = high;
    }

    public int getMedium() {
        return medium;
    }

    public void setMedium(int medium) {
        this.medium = medium;
    }

    public int getLow() {
        return low;
    }

    public void setLow(int low) {
        this.low = low;
    }

    public int getInfo() {
        return info;
    }

    public void setInfo(int info) {
        this.info = info;
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    @Override
    public String toString() {
        return "Counts{critical=" + critical + ", high=" + high + ", medium=" + medium
                + ", low=" + low + ", info=" + info + ", total=" + total + '}';
    }
}
