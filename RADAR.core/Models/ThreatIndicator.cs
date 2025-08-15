using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace RADAR.Core.Models
{
    public class ThreatIndicator
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [JsonPropertyName("value")]
        [Required]
        public string Value { get; set; } = string.Empty;

        [JsonPropertyName("type")]
        [Required]
        public IndicatorType Type { get; set; }

        [JsonPropertyName("source")]
        public string Source { get; set; } = string.Empty;

        [JsonPropertyName("confidence")]
        [Range(0, 100)]
        public int Confidence { get; set; }

        [JsonPropertyName("created")]
        public DateTime Created { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("last_seen")]
        public DateTime LastSeen { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("tags")]
        public List<string> Tags { get; set; } = new List<string>();

        [JsonPropertyName("threat_actor")]
        public string? ThreatActor { get; set; }

        [JsonPropertyName("malware_family")]
        public string? MalwareFamily { get; set; }

        [JsonPropertyName("description")]
        public string? Description { get; set; }

        public override string ToString()
        {
            return $"{Type}: {Value} (Source: {Source}, Confidence: {Confidence}%)";
        }

        public override bool Equals(object? obj)
        {
            if (obj is ThreatIndicator other)
            {
                return Value.Equals(other.Value, StringComparison.OrdinalIgnoreCase) && 
                       Type == other.Type;
            }
            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(Value.ToLowerInvariant(), Type);
        }
    }

    public enum IndicatorType
    {
        IpAddress,
        Domain,
        Url,
        FileHash,
        Email,
        Mutex,
        Registry,
        Certificate
    }
}