using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace RADAR.Core.Models
{
    public class CorrelationResult
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [JsonPropertyName("related_indicators")]
        public List<ThreatIndicator> RelatedIndicators { get; set; } = new List<ThreatIndicator>();

        [JsonPropertyName("correlation_type")]
        public string CorrelationType { get; set; } = string.Empty;

        [JsonPropertyName("confidence_score")]
        public double ConfidenceScore { get; set; }

        [JsonPropertyName("discovered_at")]
        public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [JsonPropertyName("analysis_details")]
        public Dictionary<string, object> AnalysisDetails { get; set; } = new Dictionary<string, object>();

        public override string ToString()
        {
            return $"{CorrelationType}: {RelatedIndicators.Count} indicators (Confidence: {ConfidenceScore:P1})";
        }
    }

    public class InfrastructurePivot
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [JsonPropertyName("threat_actors")]
        public List<string> ThreatActors { get; set; } = new List<string>();

        [JsonPropertyName("shared_infrastructure")]
        public ThreatIndicator SharedInfrastructure { get; set; } = new ThreatIndicator();

        [JsonPropertyName("pivot_type")]
        public string PivotType { get; set; } = string.Empty;

        [JsonPropertyName("confidence_score")]
        public double ConfidenceScore { get; set; }

        [JsonPropertyName("discovered_at")]
        public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;

        [JsonPropertyName("evidence")]
        public List<string> Evidence { get; set; } = new List<string>();

        [JsonPropertyName("related_campaigns")]
        public List<string> RelatedCampaigns { get; set; } = new List<string>();

        public override string ToString()
        {
            return $"{PivotType}: {SharedInfrastructure.Value} shared by {ThreatActors.Count} actors (Confidence: {ConfidenceScore:P1})";
        }
    }
}