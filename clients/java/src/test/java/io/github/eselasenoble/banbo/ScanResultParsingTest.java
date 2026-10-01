package io.github.eselasenoble.banbo;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScanResultParsingTest {

    private final ObjectMapper mapper = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    @Test
    void parsesFullScanResult() throws Exception {
        String json = "{"
                + "\"target\":\"example.com\",\"host\":\"93.184.216.34\","
                + "\"started_at\":\"2026-10-01T12:00:00Z\",\"duration_ms\":1500000000,"
                + "\"findings\":[{"
                + "  \"id\":\"TLS-001\",\"title\":\"Weak TLS\",\"layer\":\"transport\","
                + "  \"severity\":\"high\",\"asset\":\"example.com:443\","
                + "  \"evidence\":\"TLS 1.0 enabled\",\"cvss\":7.4,"
                + "  \"references\":[\"https://example.com/ref\"],"
                + "  \"compliance\":[\"PCI-DSS\"],"
                + "  \"ai_explanation\":\"explained\",\"ai_remediation\":\"fix it\","
                + "  \"business_impact\":\"data exposure\","
                + "  \"unknown_future_field\":\"ignored\""
                + "}],"
                + "\"summary\":{\"critical\":0,\"high\":1,\"medium\":0,\"low\":0,\"info\":0,\"total\":1},"
                + "\"errors\":[{\"module\":\"dns\",\"error\":\"timeout\"}]"
                + "}";

        ScanResult result = mapper.readValue(json, ScanResult.class);

        assertEquals("example.com", result.getTarget());
        assertEquals("93.184.216.34", result.getHost());
        assertEquals("2026-10-01T12:00:00Z", result.getStartedAt());
        assertEquals(1500000000L, result.getDurationMs());

        assertEquals(1, result.getFindings().size());
        Finding f = result.getFindings().get(0);
        assertEquals("TLS-001", f.getId());
        assertEquals(Severity.HIGH, f.getSeverity());
        assertEquals("transport", f.getLayer());
        assertEquals(7.4, f.getCvss(), 0.0001);
        assertEquals("explained", f.getAiExplanation());
        assertEquals("fix it", f.getAiRemediation());
        assertEquals("data exposure", f.getBusinessImpact());
        assertTrue(f.getReferences().contains("https://example.com/ref"));
        assertTrue(f.getCompliance().contains("PCI-DSS"));

        assertEquals(1, result.getSummary().getHigh());
        assertEquals(1, result.getSummary().getTotal());
        assertEquals(1, result.getErrors().size());
        assertEquals("dns", result.getErrors().get(0).getModule());
    }

    @Test
    void parsesMinimalResultWithNoFindings() throws Exception {
        String json = "{\"target\":\"localhost\",\"host\":\"127.0.0.1\","
                + "\"started_at\":\"2026-10-01T12:00:00Z\",\"duration_ms\":10,"
                + "\"findings\":[],"
                + "\"summary\":{\"critical\":0,\"high\":0,\"medium\":0,\"low\":0,\"info\":0,\"total\":0}}";

        ScanResult result = mapper.readValue(json, ScanResult.class);
        assertNotNull(result.getFindings());
        assertTrue(result.getFindings().isEmpty());
        assertTrue(result.getErrors().isEmpty());
    }

    @Test
    void severityRoundTrips() throws Exception {
        for (Severity s : Severity.values()) {
            String json = mapper.writeValueAsString(s);
            assertEquals("\"" + s.name().toLowerCase() + "\"", json);
            assertEquals(s, mapper.readValue(json, Severity.class));
        }
    }

    @Test
    void scanBuildsExpectedArgs() {
        BanboCommand cmd = Banbo.scan("example.com")
                .authorized()
                .ports(80, 443)
                .timeout("5s")
                .active()
                .noAi();

        java.util.List<String> args = cmd.buildArgs();
        assertEquals("scan", args.get(0));
        assertEquals("example.com", args.get(1));
        assertTrue(args.contains("-o"));
        assertTrue(args.contains("json"));
        assertTrue(args.contains("-y"));
        assertTrue(args.contains("--ports"));
        assertTrue(args.contains("80,443"));
        assertTrue(args.contains("--timeout"));
        assertTrue(args.contains("5s"));
        assertTrue(args.contains("--active"));
        assertTrue(args.contains("--no-ai"));
        assertTrue(args.contains("--no-color"));
    }

    @Test
    void codeBuildsExpectedArgs() {
        BanboCommand cmd = Banbo.code(java.nio.file.Paths.get("src")).full().noAi();
        java.util.List<String> args = cmd.buildArgs();
        assertEquals("code", args.get(0));
        assertEquals("src", args.get(1));
        assertTrue(args.contains("--full"));
        assertFalse(args.contains("--active"));
    }

    @Test
    void okExitCodes() {
        assertTrue(BinaryResolver.isOkExitCode(0));
        assertTrue(BinaryResolver.isOkExitCode(1));
        assertTrue(BinaryResolver.isOkExitCode(2));
        assertFalse(BinaryResolver.isOkExitCode(3));
        assertFalse(BinaryResolver.isOkExitCode(127));
    }
}
