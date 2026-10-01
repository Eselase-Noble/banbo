using System.Text.Json.Serialization;

namespace Banbo
{
    /// <summary>
    /// Severity of a <see cref="Finding"/>, ordered from least to most serious.
    /// </summary>
    /// <remarks>
    /// Serialized to and from the lowercase JSON tokens emitted by banbo
    /// (for example <c>"high"</c>) via <see cref="JsonStringEnumConverter"/>.
    /// </remarks>
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum Severity
    {
        [JsonPropertyName("info")]
        Info,

        [JsonPropertyName("low")]
        Low,

        [JsonPropertyName("medium")]
        Medium,

        [JsonPropertyName("high")]
        High,

        [JsonPropertyName("critical")]
        Critical,
    }
}
