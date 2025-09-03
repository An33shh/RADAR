using Microsoft.Extensions.Logging;
using RADAR.Core.Configuration;
using RADAR.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace RADAR.Core.Collectors
{
    public class MitreAttckCollector : BaseThreatCollector
    {
        public override string SourceName => "MITRE_ATT&CK";

        public MitreAttckCollector(HttpClient httpClient, ThreatFeedConfig config, ILogger<MitreAttckCollector> logger)
            : base(httpClient, config, logger)
        {
            ValidateConfiguration();
        }

        public override async Task<bool> IsHealthyAsync()
        {
            try
            {
                // Test with a simple file that should always exist
                var testUrl = $"{_config.BaseUrl.TrimEnd('/')}/README.md";
                var response = await _httpClient.GetAsync(testUrl);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Health check failed for {SourceName}", SourceName);
                return false;
            }
        }

        public override async Task<List<ThreatIndicator>> CollectIndicatorsAsync()
        {
            var indicators = new List<ThreatIndicator>();

            try
            {
                _logger.LogInformation("Starting technique collection from MITRE ATT&CK");

                // Get ATT&CK techniques
                var techniques = await GetAttackTechniquesAsync();
                if (techniques?.Objects == null)
                {
                    _logger.LogWarning("No techniques received from MITRE ATT&CK");
                    return indicators;
                }

                // Convert techniques to indicators
                foreach (var technique in techniques.Objects.Where(t => t.Type == "attack-pattern").Take(500)) // Increased from 100 to 500
                {
                    var indicator = ConvertTechniqueToIndicator(technique);
                    if (indicator != null)
                    {
                        indicators.Add(indicator);
                    }
                }

                _logger.LogInformation("Collected {Count} technique indicators from MITRE ATT&CK", indicators.Count);
                return indicators;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error collecting indicators from MITRE ATT&CK");
                return indicators;
            }
        }

        public override async Task<List<ThreatActor>> CollectThreatActorsAsync()
        {
            var actors = new List<ThreatActor>();

            try
            {
                _logger.LogInformation("Collecting threat actors from MITRE ATT&CK");

                // Get intrusion sets (threat actors)
                var intrusionSets = await GetIntrusionSetsAsync();
                if (intrusionSets?.Objects == null)
                {
                    _logger.LogWarning("No intrusion sets received from MITRE ATT&CK");
                    return actors;
                }

                // Convert intrusion sets to threat actors
                foreach (var intrusionSet in intrusionSets.Objects.Where(i => i.Type == "intrusion-set").Take(20))
                {
                    var actor = ConvertToThreatActor(intrusionSet);
                    if (actor != null)
                    {
                        actors.Add(actor);
                    }
                }

                _logger.LogInformation("Collected {Count} threat actors from MITRE ATT&CK", actors.Count);
                return actors;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error collecting threat actors from MITRE ATT&CK");
                return actors;
            }
        }

        private async Task<MitreStixBundle?> GetAttackTechniquesAsync()
        {
            const string endpoint = "/enterprise-attack/enterprise-attack.json";
            var fullUrl = $"{_config.BaseUrl.TrimEnd('/')}{endpoint}";
            return await GetJsonAsync<MitreStixBundle>(fullUrl);
        }

        private async Task<MitreStixBundle?> GetIntrusionSetsAsync()
        {
            // Same file contains both techniques and intrusion sets
            return await GetAttackTechniquesAsync();
        }

        private ThreatIndicator? ConvertTechniqueToIndicator(MitreStixObject technique)
        {
            if (string.IsNullOrEmpty(technique.Name)) return null;

            return new ThreatIndicator
            {
                Value = technique.ExternalReferences?.FirstOrDefault()?.ExternalId ?? technique.Name,
                Type = IndicatorType.Registry, // Using Registry type for ATT&CK techniques
                Source = SourceName,
                Description = $"ATT&CK Technique: {technique.Name}",
                Tags = ExtractTechniqueTags(technique),
                Confidence = 95 // High confidence for MITRE data
            };
        }

        private ThreatActor? ConvertToThreatActor(MitreStixObject intrusionSet)
        {
            if (string.IsNullOrEmpty(intrusionSet.Name)) return null;

            var actor = new ThreatActor
            {
                Name = intrusionSet.Name,
                Country = "Unknown" // MITRE doesn't always specify country
            };

            // Extract aliases
            if (intrusionSet.Aliases != null)
            {
                actor.Aliases = intrusionSet.Aliases.ToList();
            }

            // Extract description as potential motivation
            if (!string.IsNullOrEmpty(intrusionSet.Description))
            {
                actor.Motivation.Add(ExtractMotivationFromDescription(intrusionSet.Description));
            }

            // Add MITRE ID as TTP
            var mitreId = intrusionSet.ExternalReferences?.FirstOrDefault()?.ExternalId;
            if (!string.IsNullOrEmpty(mitreId))
            {
                actor.TTPs.Add($"MITRE Group: {mitreId}");
            }

            return actor;
        }

        private List<string> ExtractTechniqueTags(MitreStixObject technique)
        {
            var tags = new List<string> { "mitre-attack" };

            // Add tactic tags from kill chain phases
            if (technique.KillChainPhases != null)
            {
                foreach (var phase in technique.KillChainPhases.Take(3))
                {
                    if (!string.IsNullOrEmpty(phase.PhaseName))
                    {
                        tags.Add($"tactic:{phase.PhaseName}");
                    }
                }
            }

            // Add platform tags
            if (technique.Platforms != null)
            {
                foreach (var platform in technique.Platforms.Take(2))
                {
                    tags.Add($"platform:{platform.ToLowerInvariant()}");
                }
            }

            return tags;
        }

        private string ExtractMotivationFromDescription(string description)
        {
            // Simple heuristic to extract motivation
            if (description.Contains("financial", StringComparison.OrdinalIgnoreCase))
                return "Financial";
            if (description.Contains("espionage", StringComparison.OrdinalIgnoreCase))
                return "Espionage";
            if (description.Contains("sabotage", StringComparison.OrdinalIgnoreCase))
                return "Sabotage";
            
            return "Unknown";
        }
    }

    // Data models for MITRE ATT&CK STIX format
    public class MitreStixBundle
    {
        [JsonPropertyName("objects")]
        public List<MitreStixObject>? Objects { get; set; }
    }

    public class MitreStixObject
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        [JsonPropertyName("name")]
        public string? Name { get; set; }

        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [JsonPropertyName("aliases")]
        public List<string>? Aliases { get; set; }

        [JsonPropertyName("external_references")]
        public List<MitreExternalReference>? ExternalReferences { get; set; }

        [JsonPropertyName("kill_chain_phases")]
        public List<MitreKillChainPhase>? KillChainPhases { get; set; }

        [JsonPropertyName("x_mitre_platforms")]
        public List<string>? Platforms { get; set; }
    }

    public class MitreExternalReference
    {
        [JsonPropertyName("external_id")]
        public string? ExternalId { get; set; }

        [JsonPropertyName("source_name")]
        public string? SourceName { get; set; }

        [JsonPropertyName("url")]
        public string? Url { get; set; }
    }

    public class MitreKillChainPhase
    {
        [JsonPropertyName("kill_chain_name")]
        public string? KillChainName { get; set; }

        [JsonPropertyName("phase_name")]
        public string? PhaseName { get; set; }
    }
}