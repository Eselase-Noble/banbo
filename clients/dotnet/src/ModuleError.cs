using System.Text.Json.Serialization;

namespace Banbo
{
    /// <summary>
    /// A non-fatal error reported by an individual banbo scan module.
    /// </summary>
    /// <remarks>
    /// Modules may fail independently; the overall scan can still succeed and
    /// return findings while recording these errors.
    /// </remarks>
    public sealed class ModuleError
    {
        [JsonPropertyName("module")]
        public string? Module { get; set; }

        [JsonPropertyName("error")]
        public string? Error { get; set; }

        public override string ToString()
            => $"ModuleError{{module='{Module}', error='{Error}'}}";
    }
}
