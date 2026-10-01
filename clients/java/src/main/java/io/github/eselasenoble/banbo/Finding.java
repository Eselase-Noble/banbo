package io.github.eselasenoble.banbo;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * A single security finding reported by banbo.
 *
 * <p>Fields marked optional in the banbo JSON contract may be {@code null}.</p>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public final class Finding {

    private String id;
    private String title;
    private String layer;
    private Severity severity;
    private String asset;
    private String evidence;
    private String description;
    private String remediation;
    private List<String> references;
    private Double cvss;
    private List<String> compliance;

    @JsonProperty("ai_explanation")
    private String aiExplanation;

    @JsonProperty("ai_remediation")
    private String aiRemediation;

    @JsonProperty("business_impact")
    private String businessImpact;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    /** The scan layer: one of {@code dns}, {@code network}, {@code transport}, {@code application}, {@code code}. */
    public String getLayer() {
        return layer;
    }

    public void setLayer(String layer) {
        this.layer = layer;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public String getAsset() {
        return asset;
    }

    public void setAsset(String asset) {
        this.asset = asset;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getRemediation() {
        return remediation;
    }

    public void setRemediation(String remediation) {
        this.remediation = remediation;
    }

    public List<String> getReferences() {
        return references;
    }

    public void setReferences(List<String> references) {
        this.references = references;
    }

    public Double getCvss() {
        return cvss;
    }

    public void setCvss(Double cvss) {
        this.cvss = cvss;
    }

    public List<String> getCompliance() {
        return compliance;
    }

    public void setCompliance(List<String> compliance) {
        this.compliance = compliance;
    }

    public String getAiExplanation() {
        return aiExplanation;
    }

    public void setAiExplanation(String aiExplanation) {
        this.aiExplanation = aiExplanation;
    }

    public String getAiRemediation() {
        return aiRemediation;
    }

    public void setAiRemediation(String aiRemediation) {
        this.aiRemediation = aiRemediation;
    }

    public String getBusinessImpact() {
        return businessImpact;
    }

    public void setBusinessImpact(String businessImpact) {
        this.businessImpact = businessImpact;
    }

    @Override
    public String toString() {
        return "Finding{id='" + id + "', title='" + title + "', layer='" + layer
                + "', severity=" + severity + ", asset='" + asset + "'}";
    }
}
