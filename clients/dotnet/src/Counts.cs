using System.Text.Json.Serialization;

namespace Banbo
{
    /// <summary>
    /// Per-severity counts summarizing a <see cref="ScanResult"/>.
    /// </summary>
    public sealed class Counts
    {
        [JsonPropertyName("critical")]
        public int Critical { get; set; }

        [JsonPropertyName("high")]
        public int High { get; set; }

        [JsonPropertyName("medium")]
        public int Medium { get; set; }

        [JsonPropertyName("low")]
        public int Low { get; set; }

        [JsonPropertyName("info")]
        public int Info { get; set; }

        [JsonPropertyName("total")]
        public int Total { get; set; }

        public override string ToString()
            => $"Counts{{critical={Critical}, high={High}, medium={Medium}, low={Low}, info={Info}, total={Total}}}";
    }
}
