using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace RADAR.Core.Models
{
    public class ThreatActor
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("aliases")]
        public List<string> Aliases { get; set; } = new List<string>();

        [JsonPropertyName("country")]
        public string? Country { get; set; }

        [JsonPropertyName("motivation")]
        public List<string> Motivation { get; set; } = new List<string>();

        [JsonPropertyName("targets")]
        public List<string> Targets { get; set; } = new List<string>();

        [JsonPropertyName("ttps")]
        public List<string> TTPs { get; set; } = new List<string>();

        [JsonPropertyName("indicators")]
        public List<ThreatIndicator> Indicators { get; set; } = new List<ThreatIndicator>();

        [JsonPropertyName("first_seen")]
        public DateTime FirstSeen { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("last_activity")]
        public DateTime LastActivity { get; set; } = DateTime.UtcNow;

        public override string ToString()
        {
            var aliasesStr = Aliases.Count > 0 ? $" (aka: {string.Join(", ", Aliases)})" : "";
            return $"{Name}{aliasesStr} - {Country ?? "Unknown"} - {Indicators.Count} indicators";
        }
    }
}