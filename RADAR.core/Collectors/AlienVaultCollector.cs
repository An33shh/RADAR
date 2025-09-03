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
    public class AlienVaultCollector : BaseThreatCollector
    {
        public override string SourceName => "AlienVault_OTX";

        public AlienVaultCollector(HttpClient httpClient, ThreatFeedConfig config, ILogger<AlienVaultCollector> logger)
            : base(httpClient, config, logger)
        {
            ValidateConfiguration();
        }

        public override async Task<List<ThreatIndicator>> CollectIndicatorsAsync()
        {
            var indicators = new List<ThreatIndicator>();

            try
            {
                _logger.LogInformation("Starting IOC collection from AlienVault OTX");

                var pulses = await GetRecentPulsesAsync();
                if (pulses?.Results == null)
                {
                    _logger.LogWarning("No pulses received from AlienVault OTX");
                    return indicators;
                }

                foreach (var pulse in pulses.Results.Take(500)) 
                {
                    var pulseIndicators = await ExtractIndicatorsFromPulse(pulse);
                    indicators.AddRange(pulseIndicators);
                }

                _logger.LogInformation("Collected {Count} indicators from AlienVault OTX", indicators.Count);
                return indicators;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error collecting indicators from AlienVault OTX");
                return indicators;
            }
        }

        public override async Task<List<ThreatActor>> CollectThreatActorsAsync()
        {
            var actors = new List<ThreatActor>();

            try
            {
                _logger.LogInformation("Collecting threat actors from AlienVault OTX");

                var pulses = await GetRecentPulsesAsync();
                if (pulses?.Results == null) return actors;

                var actorGroups = pulses.Results
                    .Where(p => !string.IsNullOrEmpty(p.Name))
                    .GroupBy(p => ExtractActorName(p.Name))
                    .Where(g => !string.IsNullOrEmpty(g.Key));

                foreach (var group in actorGroups.Take(20)) 
                {
                    var actor = CreateThreatActorFromPulses(group.Key!, group.ToList());
                    actors.Add(actor);
                }

                _logger.LogInformation("Collected {Count} threat actors from AlienVault OTX", actors.Count);
                return actors;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error collecting threat actors from AlienVault OTX");
                return actors;
            }
        }

        private async Task<OtxPulsesResponse?> GetRecentPulsesAsync()
        {
            const string subscribedEndpoint = "/pulses/subscribed?limit=1000";
            const string publicEndpoint = "/pulses/public?limit=500"; 
            
            var subscribedUrl = $"{_config.BaseUrl.TrimEnd('/')}{subscribedEndpoint}";
            var publicUrl = $"{_config.BaseUrl.TrimEnd('/')}{publicEndpoint}";
            
            var subscribedResult = await GetJsonAsync<OtxPulsesResponse>(subscribedUrl);
            if (subscribedResult?.Results != null && subscribedResult.Results.Count > 0)
            {
                return subscribedResult;
            }

            _logger.LogInformation("Subscribed pulses unavailable, trying public pulses");
            return await GetJsonAsync<OtxPulsesResponse>(publicUrl);
        }

        private async Task<List<ThreatIndicator>> ExtractIndicatorsFromPulse(OtxPulse pulse)
        {
            var indicators = new List<ThreatIndicator>();

            try
            {
                var detailUrl = $"{_config.BaseUrl.TrimEnd('/')}/pulses/{pulse.Id}";
                var pulseDetail = await GetJsonAsync<OtxPulseDetail>(detailUrl);

                if (pulseDetail?.Indicators == null) return indicators;

                                    foreach (var indicator in pulseDetail.Indicators.Take(500)) 
                {
                    var threatIndicator = ConvertToThreatIndicator(indicator, pulse);
                    if (threatIndicator != null)
                    {
                        indicators.Add(threatIndicator);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error extracting indicators from pulse {PulseId}", pulse.Id);
            }

            return indicators;
        }

        private ThreatIndicator? ConvertToThreatIndicator(OtxIndicator otxIndicator, OtxPulse pulse)
        {
            var indicatorType = MapIndicatorType(otxIndicator.Type);
            if (indicatorType == null) return null;

            return new ThreatIndicator
            {
                Value = otxIndicator.Indicator,
                Type = indicatorType.Value,
                Source = SourceName,
                Description = otxIndicator.Description ?? pulse.Description,
                ThreatActor = ExtractActorName(pulse.Name),
                Tags = pulse.Tags?.ToList() ?? new List<string>(),
                Confidence = 80 
            };
        }

        private static IndicatorType? MapIndicatorType(string otxType)
        {
            return otxType?.ToLowerInvariant() switch
            {
                "ipv4" or "ipv6" => IndicatorType.IpAddress,
                "domain" => IndicatorType.Domain,
                "hostname" => IndicatorType.Domain,
                "url" => IndicatorType.Url,
                "filehash-md5" or "filehash-sha1" or "filehash-sha256" => IndicatorType.FileHash,
                "email" => IndicatorType.Email,
                _ => null
            };
        }

        private static string ExtractActorName(string pulseName)
        {
            var commonActors = new[] { "APT", "Lazarus", "Carbanak", "FIN", "Turla", "Sofacy" };
            
            foreach (var actor in commonActors)
            {
                if (pulseName.Contains(actor, StringComparison.OrdinalIgnoreCase))
                {
                    return actor;
                }
            }

            var words = pulseName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            return words.Length > 0 ? words[0] : "Unknown";
        }

        private ThreatActor CreateThreatActorFromPulses(string actorName, List<OtxPulse> pulses)
        {
            var actor = new ThreatActor
            {
                Name = actorName,
                Country = "Unknown" 
            };

            var allTags = pulses.SelectMany(p => p.Tags ?? new List<string>()).Distinct().ToList();
            actor.TTPs = allTags.Take(10).ToList();

            return actor;
        }
    }

    public class OtxPulsesResponse
    {
        [JsonPropertyName("results")]
        public List<OtxPulse>? Results { get; set; }
    }

    public class OtxPulse
    {
        [JsonPropertyName("id")]
        public string Id { get; set; } = string.Empty;

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string? Description { get; set; }

        [JsonPropertyName("tags")]
        public List<string>? Tags { get; set; }

        [JsonPropertyName("created")]
        public DateTime Created { get; set; }
    }

    public class OtxPulseDetail : OtxPulse
    {
        [JsonPropertyName("indicators")]
        public List<OtxIndicator>? Indicators { get; set; }
    }

    public class OtxIndicator
    {
        [JsonPropertyName("indicator")]
        public string Indicator { get; set; } = string.Empty;

        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        [JsonPropertyName("description")]
        public string? Description { get; set; }
    }
}