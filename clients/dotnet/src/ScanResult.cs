using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Banbo
{
    /// <summary>
    /// The parsed result of a banbo <c>scan</c> or <c>code</c> run (the object printed
    /// to stdout by <c>-o json</c>).
    /// </summary>
    public sealed class ScanResult
    {
        /// <summary>The scan target as supplied on the command line.</summary>
        [JsonPropertyName("target")]
        public string? Target { get; set; }

        /// <summary>The resolved host.</summary>
        [JsonPropertyName("host")]
        public string? Host { get; set; }

        /// <summary>Scan start time as an RFC 3339 string.</summary>
        [JsonPropertyName("started_at")]
        public string? StartedAt { get; set; }

        /// <summary>
        /// Raw duration value reported by banbo. Despite the field name, banbo may
        /// report this in nanoseconds; treat it as an opaque numeric from the CLI.
        /// </summary>
        [JsonPropertyName("duration_ms")]
        public long DurationMs { get; set; }

        /// <summary>All findings. Never <c>null</c>; empty when there are none.</summary>
        [JsonPropertyName("findings")]
        public IReadOnlyList<Finding> Findings { get; set; } = Array.Empty<Finding>();

        /// <summary>Per-severity summary counts.</summary>
        [JsonPropertyName("summary")]
        public Counts? Summary { get; set; }

        /// <summary>Per-module errors. Never <c>null</c>; empty when none occurred.</summary>
        [JsonPropertyName("errors")]
        public IReadOnlyList<ModuleError> Errors { get; set; } = Array.Empty<ModuleError>();

        /// <summary>Shared, case-insensitive serializer options used to parse banbo output.</summary>
        internal static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            NumberHandling = JsonNumberHandling.AllowReadingFromString,
        };

        /// <summary>
        /// Parses a <see cref="ScanResult"/> from the JSON printed by banbo on stdout.
        /// </summary>
        /// <param name="json">The raw stdout from a <c>-o json</c> run.</param>
        /// <returns>The parsed result (never <c>null</c>).</returns>
        /// <exception cref="BanboException">If the JSON cannot be parsed.</exception>
        public static ScanResult Parse(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                throw new BanboException("banbo produced no JSON output to parse.");
            }

            try
            {
                var result = JsonSerializer.Deserialize<ScanResult>(json, JsonOptions);
                if (result == null)
                {
                    throw new BanboException("banbo JSON output deserialized to null.");
                }

                result.Findings ??= Array.Empty<Finding>();
                result.Errors ??= Array.Empty<ModuleError>();
                return result;
            }
            catch (JsonException ex)
            {
                throw new BanboException("Failed to parse banbo JSON output: " + ex.Message, ex);
            }
        }

        public override string ToString()
            => $"ScanResult{{target='{Target}', host='{Host}', findings={Findings.Count}, summary={Summary}}}";
    }
}
