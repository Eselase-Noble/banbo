using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Banbo
{
    /// <summary>
    /// A single security finding reported by banbo.
    /// </summary>
    /// <remarks>
    /// Fields marked optional in the banbo JSON contract may be <c>null</c>.
    /// </remarks>
    public sealed class Finding
    {
        /// <summary>Stable identifier for the finding (e.g. a rule id).</summary>
        [JsonPropertyName("id")]
        public string? Id { get; set; }

        /// <summary>Short human-readable title.</summary>
        [JsonPropertyName("title")]
        public string? Title { get; set; }

        /// <summary>
        /// The scan layer: one of <c>dns</c>, <c>network</c>, <c>transport</c>,
        /// <c>application</c>, <c>code</c>.
        /// </summary>
        [JsonPropertyName("layer")]
        public string? Layer { get; set; }

        /// <summary>Severity classification.</summary>
        [JsonPropertyName("severity")]
        public Severity Severity { get; set; }

        /// <summary>The affected asset (host, port, file, etc.).</summary>
        [JsonPropertyName("asset")]
        public string? Asset { get; set; }

        /// <summary>Optional evidence captured while detecting the issue.</summary>
        [JsonPropertyName("evidence")]
        public string? Evidence { get; set; }

        /// <summary>Optional longer description.</summary>
        [JsonPropertyName("description")]
        public string? Description { get; set; }

        /// <summary>Optional remediation guidance.</summary>
        [JsonPropertyName("remediation")]
        public string? Remediation { get; set; }

        /// <summary>Optional external references (URLs, CVE ids, etc.).</summary>
        [JsonPropertyName("references")]
        public IReadOnlyList<string>? References { get; set; }

        /// <summary>Optional CVSS base score.</summary>
        [JsonPropertyName("cvss")]
        public double? Cvss { get; set; }

        /// <summary>Optional compliance mappings (e.g. PCI-DSS, SOC2 controls).</summary>
        [JsonPropertyName("compliance")]
        public IReadOnlyList<string>? Compliance { get; set; }

        /// <summary>Optional AI-generated explanation (present unless <c>--no-ai</c>).</summary>
        [JsonPropertyName("ai_explanation")]
        public string? AiExplanation { get; set; }

        /// <summary>Optional AI-generated remediation (present unless <c>--no-ai</c>).</summary>
        [JsonPropertyName("ai_remediation")]
        public string? AiRemediation { get; set; }

        /// <summary>Optional AI-generated business impact summary.</summary>
        [JsonPropertyName("business_impact")]
        public string? BusinessImpact { get; set; }

        public override string ToString()
            => $"Finding{{id='{Id}', title='{Title}', layer='{Layer}', severity={Severity}, asset='{Asset}'}}";
    }
}
